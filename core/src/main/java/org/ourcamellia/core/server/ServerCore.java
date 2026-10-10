package org.ourcamellia.core.server;

import org.ourcamellia.common.Errors;
import org.ourcamellia.common.Ids;
import org.ourcamellia.common.PasswordHash;
import org.ourcamellia.common.SelfSignedCerts;
import org.ourcamellia.common.Text;
import org.ourcamellia.common.config.ServerConfig;
import org.ourcamellia.common.domain.NotificationKind;
import org.ourcamellia.common.domain.NotificationState;
import org.ourcamellia.common.protocol.Envelope;
import org.ourcamellia.common.protocol.Wire;
import org.ourcamellia.common.protocol.WireMessages;
import org.ourcamellia.core.security.RateLimiter;
import org.ourcamellia.core.transport.Conn;
import org.ourcamellia.core.transport.ConnSession;
import org.ourcamellia.core.transport.SocketConn;
import org.ourcamellia.core.transport.TlsConnections;
import org.ourcamellia.core.verifier.ExternalVerifier;

import javax.net.ssl.SSLContext;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * The Ourcamellia server: one independent community (no federation). Owns accounts,
 * friendships, groups, notifications, registration policy, and the announcement
 * channel. Every protected operation is authorized server-side; client-side UI is
 * never the authorization boundary. Ordinary users never receive other users' IP
 * addresses — source addresses are used only for rate limiting and diagnostics.
 */
public final class ServerCore implements AutoCloseable {

    private static final Logger LOG = Logger.getLogger(ServerCore.class.getName());

    private final ServerConfig config;
    private final ServerStateStore store;
    private final ServerEvents events;
    private final ExternalVerifier verifier;
    private final RateLimiter loginLimiter;
    private final RateLimiter registerLimiter;
    private final RateLimiter friendLimiter;
    private final RateLimiter messageLimiter;
    private final RateLimiter groupLimiter;
    private final ExecutorService verifierExecutor = Executors.newVirtualThreadPerTaskExecutor();

    private SelfSignedCerts.GeneratedCert identity;
    private SSLContext serverContext;
    private javax.net.ssl.SSLServerSocket listener;
    private final AtomicBoolean closed = new AtomicBoolean(false);

    /** Authenticated clients by username. */
    private final ConcurrentHashMap<String, Client> clients = new ConcurrentHashMap<>();
    /** All live sessions for shutdown and IP bookkeeping. */
    private final ConcurrentHashMap<ConnSession, SessionRec> sessions = new ConcurrentHashMap<>();

    /** One authenticated connection (or in-process BOT session). */
    public static final class Client {
        public final String name;
        public final boolean bot;
        public final ConnSession session;   // null for BOT sessions
        public final String address;
        public final java.util.function.Consumer<Envelope> botSink; // null for network clients

        Client(String name, boolean bot, ConnSession session, String address,
               java.util.function.Consumer<Envelope> botSink) {
            this.name = name;
            this.bot = bot;
            this.session = session;
            this.address = address;
            this.botSink = botSink;
        }
    }

    /** Routes an envelope to a client over its socket or BOT inbox. */
    private void deliver(Client c, Envelope envelope) {
        if (c == null) {
            return;
        }
        if (c.session != null) {
            c.session.conn().send(envelope);
        } else if (c.botSink != null) {
            c.botSink.accept(envelope);
        }
    }

    private static final class SessionRec {
        final String address; // source IP:port — diagnostics only, never sent to users
        volatile Client client; // set after login

        SessionRec(String address) {
            this.address = address;
        }
    }

    public ServerCore(ServerConfig config, ServerStateStore store, ServerEvents events) {
        this.config = config;
        this.store = store;
        this.events = events;
        this.verifier = config.registrationPolicy().equals("external")
                ? new ExternalVerifier(config.verifier().url(), config.verifier().sharedSecret(),
                config.verifier().timeoutMs(), config.verifier().maxRetries(),
                config.verifier().allowPrivateTargets(), config.verifier().maxRedirects())
                : null;
        this.loginLimiter = new RateLimiter(config.rateLimits().loginPerMinute());
        this.registerLimiter = new RateLimiter(config.rateLimits().registerPerMinute());
        this.friendLimiter = new RateLimiter(config.rateLimits().friendRequestPerMinute());
        this.messageLimiter = new RateLimiter(config.rateLimits().messagePerMinute());
        this.groupLimiter = new RateLimiter(config.rateLimits().groupOpPerMinute());
    }

    public ServerStateStore store() {
        return store;
    }

    // ---------------- startup ----------------

    public void start() {
        store.load(config.serverName());
        purgeExpired();
        Path ks = config.dataDirPath().resolve(config.tlsKeystorePath());
        try {
            if (java.nio.file.Files.exists(ks)) {
                identity = SelfSignedCerts.loadKeystore(ks, tlsPassword());
            } else if (config.tlsAutoGenerate()) {
                identity = SelfSignedCerts.generate("ourcamellia-server", 3650);
                java.nio.file.Files.createDirectories(ks.toAbsolutePath().getParent());
                SelfSignedCerts.saveKeystore(ks, identity.cert(), identity.key(), tlsPassword());
                events.onInfo("generated self-signed TLS certificate (fingerprint "
                        + identity.fingerprint() + "); clients pin it on first connect");
            } else {
                throw new Errors.Persistence("TLS keystore missing: " + ks);
            }
            serverContext = SelfSignedCerts.serverContext(identityKeyStore(), tlsPassword().toCharArray());
            listener = TlsConnections.listen(config.bindHost(), config.port(), serverContext);
            events.onInfo("server '" + config.serverName() + "' listening on "
                    + config.bindHost() + ":" + config.port()
                    + " (registration: " + config.registrationPolicy() + ")");
            Thread.ofVirtual().name("server-accept").start(this::acceptLoop);
        } catch (Errors.OcException e) {
            throw e;
        } catch (java.io.IOException e) {
            throw new Errors.Persistence("server startup failed", e);
        }
    }

    private String tlsPassword() {
        Path pwFile = config.dataDirPath().resolve("tls/keystore.password");
        byte[] raw = org.ourcamellia.core.persist.AtomicFiles.readOrNull(pwFile);
        if (raw != null) {
            return new String(raw, java.nio.charset.StandardCharsets.US_ASCII).trim();
        }
        if (!config.tlsKeystorePassword().isBlank()) {
            return config.tlsKeystorePassword();
        }
        String pw = org.ourcamellia.common.CryptoUtil.randomHex(16);
        try {
            java.nio.file.Files.createDirectories(pwFile.toAbsolutePath().getParent());
            org.ourcamellia.core.persist.AtomicFiles.writeString(pwFile, pw + "\n");
            java.nio.file.Files.setPosixFilePermissions(pwFile,
                    java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
        } catch (Exception e) {
            throw new Errors.Persistence("cannot store TLS keystore password", e);
        }
        return pw;
    }

    private java.security.KeyStore identityKeyStore() {
        try {
            java.security.KeyStore ks = java.security.KeyStore.getInstance(SelfSignedCerts.KEYSTORE_TYPE);
            ks.load(null, null);
            ks.setKeyEntry(SelfSignedCerts.DEFAULT_ALIAS, identity.key(),
                    tlsPassword().toCharArray(),
                    new java.security.cert.Certificate[]{identity.cert()});
            return ks;
        } catch (Exception e) {
            throw new Errors.Internal("keystore assembly failed", e);
        }
    }

    private void acceptLoop() {
        while (!closed.get() && listener != null) {
            try {
                var ssl = TlsConnections.accept(listener, config.connectTimeoutMs());
                String address = ssl.getInetAddress().getHostAddress() + ":" + ssl.getPort();
                SocketConn conn = new SocketConn(ssl, address, null, config.maxFrameBytes());
                SessionRec rec = new SessionRec(address);
                ConnSession[] holder = new ConnSession[1];
                ConnSession session = new ConnSession(conn, new ConnSession.Handler() {
                    @Override
                    public void onEnvelope(Conn c, Envelope envelope) {
                        try {
                            handle(rec, holder[0], c, envelope);
                        } catch (Errors.OcException e) {
                            c.send(Wire.error(envelope.id(), e.category, e.getMessage()));
                        } catch (RuntimeException e) {
                            LOG.log(Level.WARNING, "unexpected handler error from " + address, e);
                            c.send(Wire.error(envelope.id(), Errors.Category.INTERNAL, "internal error"));
                        }
                    }

                    @Override
                    public void onClosed(Conn c, String reason) {
                        onDisconnected(rec, holder[0], reason);
                    }
                }, config.pingIntervalMs(), config.readTimeoutMs());
                holder[0] = session;
                sessions.put(session, rec);
            } catch (Errors.OcException e) {
                if (!closed.get()) {
                    LOG.log(Level.FINE, "accept failed: {0}", e.getMessage());
                }
            } catch (java.io.IOException e) {
                if (!closed.get()) {
                    LOG.log(Level.FINE, "accept io failure: {0}", e.getMessage());
                }
            }
        }
    }

    private void onDisconnected(SessionRec rec, ConnSession session, String reason) {
        sessions.remove(session);
        Client client = rec.client;
        if (client != null) {
            clients.remove(client.name, client);
            broadcastToFriends(client.name, Wire.peerState(client.name, "disconnected"));
            events.onInfo(client.name + " disconnected (" + reason + ")");
        }
    }

    // ---------------- inbound dispatch ----------------

    private void handle(SessionRec rec, ConnSession session, Conn conn, Envelope envelope) {
        Client client = rec.client;
        if (client == null) {
            handlePreAuth(rec, session, conn, envelope);
            return;
        }
        handleAuthed(client, conn, envelope);
    }

    private void handlePreAuth(SessionRec rec, ConnSession session, Conn conn, Envelope envelope) {
        switch (envelope.type()) {
            case Wire.T_HELLO -> {
                var hello = Wire.parseHello(envelope);
                if (!hello.version().equals(String.valueOf(Envelope.PROTOCOL_VERSION))) {
                    conn.send(Wire.error(envelope.id(), Errors.Category.MALFORMED,
                            "unsupported protocol version"));
                    conn.close();
                    return;
                }
                conn.send(Wire.welcome(config.serverName(), store.state().channelId, 0,
                        config.registrationPolicy(), groupPolicyNote()));
            }
            case Wire.T_LOGIN -> handleLogin(rec, session, conn, envelope);
            case Wire.T_REGISTER -> handleRegister(rec, session, conn, envelope);
            default -> conn.send(Wire.error(envelope.id(), Errors.Category.DENIED, "login required"));
        }
    }

    private String groupPolicyNote() {
        return config.encryptedGroupsAllowed()
                ? "encrypted groups are allowed; operators cannot read their content"
                : "encrypted groups are disabled by server policy";
    }

    private void handleLogin(SessionRec rec, ConnSession session, Conn conn, Envelope envelope) {
        var login = Wire.parseLogin(envelope);
        String ipKey = "ip:" + rec.address;
        if (!loginLimiter.tryAcquire(ipKey) || !loginLimiter.tryAcquire("user:" + login.username())) {
            throw new Errors.RateLimited("too many login attempts; wait a minute");
        }
        ServerStateStore.Account account = store.state().accounts.get(login.username());
        if (account == null) {
            // A pending registration with a matching password gets an honest,
            // non-enumerating answer: the caller already proved knowledge of the
            // password, so this leaks nothing an attacker didn't know.
            ServerStateStore.Registration pending = null;
            for (ServerStateStore.Registration r : store.state().registrations.values()) {
                if (r.username.equals(login.username())
                        && PasswordHash.verify(login.password(), r.passwordHash)) {
                    pending = r;
                    break;
                }
            }
            if (pending != null) {
                boolean expired = pending.expiresAt > 0 && System.currentTimeMillis() > pending.expiresAt;
                throw new Errors.Denied(expired
                        ? "account registration expired — please register again"
                        : "account registration is still pending approval");
            }
            throw new Errors.Auth("invalid username or password");
        }
        if (!PasswordHash.verify(login.password(), account.passwordHash)) {
            throw new Errors.Auth("invalid username or password");
        }
        if ("pending".equals(account.status)) {
            throw new Errors.Denied("account registration is still pending approval");
        }
        completeLogin(rec, session, conn, account);
    }

    private void completeLogin(SessionRec rec, ConnSession session, Conn conn, ServerStateStore.Account account) {
        // One session per account: replace an older connection.
        Client old = clients.get(account.name);
        if (old != null && old.session != null) {
            old.session.close();
        }
        Client client = new Client(account.name, account.bot, session, rec.address, null);
        rec.client = client;
        clients.put(account.name, client);
        loginLimiter.clear("user:" + account.name);

        int unread = countUnread(account.name);
        conn.send(Wire.authOk(account.name, account.bot, unread, config.serverName()));

        // Push offline (and online) notification backlog.
        List<ServerStateStore.Notif> backlog = activeNotifications(account.name);
        if (!backlog.isEmpty()) {
            conn.send(Wire.notifyList(toDtos(backlog)));
        }
        // Friends with live statuses.
        List<WireMessages.FriendEntry> friends = new ArrayList<>();
        for (String friend : account.friends) {
            friends.add(new WireMessages.FriendEntry(friend,
                    clients.containsKey(friend) ? "connected" : "disconnected",
                    isBot(friend)));
        }
        conn.send(Wire.friendsList(friends));
        // Groups the user belongs to.
        for (ServerStateStore.Group g : store.state().groups.values()) {
            if (g.owner.equals(account.name) || g.members.contains(account.name)) {
                conn.send(Wire.groupUpdate(toGroupDto(g)));
                // Encrypted groups: hand out this member's wrapped key blob.
                if ("encrypted".equals(g.privacy)) {
                    ServerStateStore.KeyWrap wrap = g.wrappedKeys.get(account.name);
                    if (wrap != null) {
                        conn.send(Wire.groupKeyWrap(g.id, account.name, wrap.box, wrap.generation,
                                g.owner, store.state().accounts.containsKey(g.owner)
                                        ? store.state().accounts.get(g.owner).x25519PublicKey : null));
                    }
                }
            }
        }
        // Announcements since last login are in the notification backlog already.
        broadcastToFriends(account.name, Wire.peerState(account.name, "connected"));
        events.onInfo(account.name + " connected");
    }

    private void handleRegister(SessionRec rec, ConnSession session, Conn conn, Envelope envelope) {
        var reg = Wire.parseRegister(envelope);
        String ipKey = "ip:" + rec.address;
        if (!registerLimiter.tryAcquire(ipKey)) {
            throw new Errors.RateLimited("too many registration attempts; wait a minute");
        }
        Text.requireServerName(reg.username());
        if (reg.password().length() < 8 || reg.password().length() > 256) {
            throw new Errors.Validation("password must be 8-256 characters");
        }
        synchronized (store) {
            if (store.state().accounts.containsKey(reg.username())) {
                throw new Errors.Conflict("username already taken");
            }
            for (ServerStateStore.Registration r : store.state().registrations.values()) {
                if (r.username.equals(reg.username())) {
                    throw new Errors.Conflict("username is pending registration");
                }
            }
            Map<String, String> fields = new LinkedHashMap<>(reg.fields());
            if (config.requireEmail()) {
                String email = fields.get("@Email");
                Text.requireEmail(email == null ? "" : email);
            }
            String x25519PublicKey = Wire.parseRegisterPublicKey(envelope);
            String passwordHash = PasswordHash.hash(reg.password(), config.passwordHashIterations());
            switch (config.registrationPolicy()) {
                case "auto" -> {
                    ServerStateStore.Account account = new ServerStateStore.Account();
                    account.name = reg.username();
                    account.passwordHash = passwordHash;
                    account.status = "active";
                    account.createdAt = System.currentTimeMillis();
                    account.fields = fields;
                    account.x25519PublicKey = x25519PublicKey;
                    if (config.adminUsernames().contains(reg.username())) {
                        if (!store.state().admins.contains(reg.username())) {
                            store.state().admins.add(reg.username());
                            events.onAudit("bootstrap: " + reg.username() + " became operator");
                        }
                    }
                    store.state().accounts.put(account.name, account);
                    store.save();
                    conn.send(Wire.registerResult("approved", reg.ticketId(),
                            "account created and approved"));
                    completeLogin(rec, session, conn, account);
                }
                case "manual", "external" -> {
                    ServerStateStore.Registration ticket = new ServerStateStore.Registration();
                    ticket.ticketId = reg.ticketId() == null ? Ids.newId() : Ids.requireId(reg.ticketId(), "ticket");
                    ticket.username = reg.username();
                    ticket.passwordHash = passwordHash;
                    ticket.fields = fields;
                    ticket.createdAt = System.currentTimeMillis();
                    ticket.expiresAt = ticket.createdAt + config.pendingTtlMinutes() * 60_000L;
                    ticket.policy = config.registrationPolicy();
                    ticket.x25519PublicKey = x25519PublicKey;
                    store.state().registrations.put(ticket.ticketId, ticket);
                    store.save();
                    conn.send(Wire.registerResult("pending", ticket.ticketId,
                            "registration pending " + config.registrationPolicy() + " approval"));
                    events.onInfo("registration pending: " + reg.username() + " (ticket " + ticket.ticketId + ")");
                    if (config.registrationPolicy().equals("external")) {
                        submitToVerifier(ticket);
                    }
                }
            }
        }
    }

    private void submitToVerifier(ServerStateStore.Registration ticket) {
        verifierExecutor.submit(() -> {
            try {
                ExternalVerifier.Result result =
                        verifier.submit(ticket.ticketId, ticket.username, ticket.fields);
                synchronized (store) {
                    ServerStateStore.Registration current =
                            store.state().registrations.get(ticket.ticketId);
                    if (current == null) {
                        return; // already acted on
                    }
                    switch (result.decision()) {
                        case APPROVED -> approveRegistrationLocked(ticket.ticketId,
                                "external verifier approved" + (result.message().isBlank() ? "" : ": " + result.message()));
                        case REJECTED -> rejectRegistrationLocked(ticket.ticketId,
                                "external verifier rejected" + (result.message().isBlank() ? "" : ": " + result.message()));
                        case PENDING -> current.verifierState = "sent";
                        case ERROR -> {
                            current.verifierState = "error";
                            events.onInfo("verifier error for " + ticket.username + ": " + result.message());
                        }
                    }
                    store.save();
                }
            } catch (RuntimeException e) {
                LOG.log(Level.WARNING, "verifier submission failed", e);
            }
        });
    }

    private void handleAuthed(Client client, Conn conn, Envelope envelope) {
        switch (envelope.type()) {
            case Wire.T_FRIEND_REQUEST -> handleFriendRequest(client, conn, envelope);
            case Wire.T_NOTIFY_ACTION -> handleNotifyAction(client, conn, envelope);
            case Wire.T_MESSAGE -> handlePrivateMessage(client, conn, envelope);
            case Wire.T_GROUP_CREATE -> handleGroupCreate(client, conn, envelope);
            case Wire.T_GROUP_INVITE -> handleGroupMemberOp(client, conn, envelope, true);
            case Wire.T_GROUP_REMOVE -> handleGroupMemberOp(client, conn, envelope, false);
            case Wire.T_GROUP_LEAVE -> handleGroupLeave(client, conn, envelope);
            case Wire.T_GROUP_TRANSFER -> handleGroupTransfer(client, conn, envelope);
            case Wire.T_GROUP_MEMBERS -> {
                var op = Wire.parseGroupOp(envelope);
                ServerStateStore.Group g = requireGroup(op.groupId());
                requireMember(g, client.name);
                conn.send(Wire.groupUpdate(toGroupDto(g)));
            }
            case Wire.T_GROUP_MESSAGE -> handleGroupMessage(client, conn, envelope);
            case Wire.T_GROUP_KEY_WRAP -> handleGroupKeyWrap(client, conn, envelope);
            default -> conn.send(Wire.error(envelope.id(), Errors.Category.USAGE, "unsupported frame type"));
        }
    }

    // ---------------- friendship ----------------

    private void handleFriendRequest(Client client, Conn conn, Envelope envelope) {
        var req = Wire.parseFriendRequest(envelope);
        if (!req.from().equals(client.name)) {
            throw new Errors.Denied("friend request must come from your own account");
        }
        if (!friendLimiter.tryAcquire(client.name)) {
            throw new Errors.RateLimited("too many friend requests; wait a minute");
        }
        if (req.from().equals(req.to())) {
            throw new Errors.Usage("you cannot friend yourself");
        }
        ServerStateStore.Account target = store.state().accounts.get(req.to());
        if (target == null || "pending".equals(target.status)) {
            throw new Errors.NotFound("no such user: " + req.to());
        }
        synchronized (store) {
            ServerStateStore.Account me = store.state().accounts.get(client.name);
            if (me.friends.contains(req.to())) {
                throw new Errors.Conflict("you are already friends with " + req.to());
            }
            for (ServerStateStore.FriendRequest existing : store.state().friendRequests.values()) {
                if (existing.from.equals(req.from()) && existing.to.equals(req.to())) {
                    conn.send(Wire.ack(envelope.id(), "already-pending"));
                    return; // idempotent
                }
            }
            ServerStateStore.FriendRequest fr = new ServerStateStore.FriendRequest();
            fr.id = req.requestId();
            fr.from = req.from();
            fr.to = req.to();
            fr.ts = System.currentTimeMillis();
            store.state().friendRequests.put(fr.id, fr);
            addNotification(req.to(), new ServerStateStore.Notif(), n -> {
                n.id = Ids.newId();
                n.kind = "friend-request";
                n.state = "unread";
                n.from = req.from();
                n.text = req.from() + " sent you a friend request";
                n.createdAt = System.currentTimeMillis();
                n.expiresAt = n.createdAt + config.notificationRetentionDays() * 24L * 3600_000L;
                n.refId = req.requestId();
            });
            store.save();
            pushNotification(req.to(), lastNotification(req.to()));
        }
        conn.send(Wire.ack(envelope.id(), "pending"));
    }

    private void handleNotifyAction(Client client, Conn conn, Envelope envelope) {
        var action = Wire.parseNotifyAction(envelope);
        synchronized (store) {
            ServerStateStore.Notif n = findNotification(client.name, action.notifId());
            if (n == null) {
                throw new Errors.NotFound("notification not found");
            }
            if (n.state.equals("acted") || n.state.equals("dismissed") || n.state.equals("expired")) {
                throw new Errors.Conflict("notification was already handled");
            }
            switch (action.action()) {
                case "over" -> {
                    n.state = "dismissed";
                    conn.send(Wire.notifyState(n.id, "dismissed"));
                }
                case "pass" -> {
                    if (!n.kind.equals("friend-request")) {
                        n.state = "dismissed";
                        conn.send(Wire.notifyState(n.id, "dismissed"));
                        break;
                    }
                    ServerStateStore.FriendRequest fr = store.state().friendRequests.get(n.refId);
                    if (fr == null) {
                        n.state = "expired";
                        conn.send(Wire.notifyState(n.id, "expired"));
                        throw new Errors.Conflict("friend request expired");
                    }
                    ServerStateStore.Account me = store.state().accounts.get(client.name);
                    ServerStateStore.Account other = store.state().accounts.get(fr.from);
                    if (me != null && other != null) {
                        me.friends.add(fr.from);
                        other.friends.add(fr.to);
                    }
                    store.state().friendRequests.remove(fr.id);
                    n.state = "acted";
                    conn.send(Wire.notifyState(n.id, "acted"));
                    // Both sides learn the new friendship immediately.
                    conn.send(Wire.friendState(fr.id, fr.from, fr.to, "accepted"));
                    deliver(clients.get(fr.from), Wire.friendState(fr.id, fr.to, fr.from, "accepted"));
                    addNotification(fr.from, new ServerStateStore.Notif(), nn -> {
                        nn.id = Ids.newId();
                        nn.kind = "info";
                        nn.state = "unread";
                        nn.from = fr.to;
                        nn.text = fr.to + " accepted your friend request";
                        nn.createdAt = System.currentTimeMillis();
                        nn.expiresAt = 0;
                        nn.refId = fr.id;
                    });
                    pushNotification(fr.from, lastNotification(fr.from));
                    events.onInfo(fr.to + " accepted friendship with " + fr.from);
                }
                case "reject" -> {
                    ServerStateStore.FriendRequest fr =
                            n.kind.equals("friend-request") ? store.state().friendRequests.get(n.refId) : null;
                    if (fr != null) {
                        store.state().friendRequests.remove(fr.id);
                        deliver(clients.get(fr.from), Wire.friendState(fr.id, fr.to, fr.from, "rejected"));
                        addNotification(fr.from, new ServerStateStore.Notif(), nn -> {
                            nn.id = Ids.newId();
                            nn.kind = "info";
                            nn.state = "unread";
                            nn.from = fr.to;
                            nn.text = fr.to + " rejected your friend request";
                            nn.createdAt = System.currentTimeMillis();
                            nn.expiresAt = 0;
                            nn.refId = fr.id;
                        });
                        pushNotification(fr.from, lastNotification(fr.from));
                    }
                    n.state = "acted";
                    conn.send(Wire.notifyState(n.id, "acted"));
                }
            }
            store.save();
        }
    }

    // ---------------- private messaging ----------------

    private void handlePrivateMessage(Client client, Conn conn, Envelope envelope) {
        var msg = Wire.parseMessage(envelope);
        if (!msg.sender().equals(client.name)) {
            throw new Errors.Denied("message must come from your own account");
        }
        if (!messageLimiter.tryAcquire(client.name)) {
            throw new Errors.RateLimited("message rate limit exceeded; wait a minute");
        }
        if (msg.sender().equals(msg.to())) {
            throw new Errors.Usage("you cannot message yourself");
        }
        ServerStateStore.Account me = store.state().accounts.get(client.name);
        if (me == null || !me.friends.contains(msg.to())) {
            throw new Errors.Denied("you are not friends with " + msg.to());
        }
        Client target = clients.get(msg.to());
        if (target == null) {
            // Honest delivery semantics: the server does not queue private messages.
            conn.send(Wire.delivery(msg.msgId(), msg.to(), "failed"));
            conn.send(Wire.error(envelope.id(), Errors.Category.NETWORK,
                    msg.to() + " is not connected; the message was not delivered"));
            return;
        }
        try {
            deliver(target, Wire.message(msg.msgId(), msg.sender(), msg.to(), msg.text(), msg.ts()));
        } catch (Errors.OcException relayFailed) {
            // The recipient's connection just dropped: report the honest failure.
            conn.send(Wire.delivery(msg.msgId(), msg.to(), "failed"));
            return;
        }
        conn.send(Wire.delivery(msg.msgId(), msg.to(), "delivered"));
    }

    // ---------------- groups ----------------

    private void handleGroupCreate(Client client, Conn conn, Envelope envelope) {
        var create = Wire.parseGroupCreate(envelope);
        if (!groupLimiter.tryAcquire(client.name)) {
            throw new Errors.RateLimited("group operation rate limit exceeded");
        }
        boolean encrypted = create.privacy().equals("encrypted");
        if (encrypted && !config.encryptedGroupsAllowed()) {
            throw new Errors.Denied("encrypted groups are disabled by server policy");
        }
        synchronized (store) {
            if (store.state().groups.containsKey(create.groupId())) {
                throw new Errors.Conflict("group id already exists");
            }
            for (String member : create.members()) {
                if (member.equals(client.name)) {
                    throw new Errors.Usage("you are already the owner; do not list yourself");
                }
                ServerStateStore.Account a = store.state().accounts.get(member);
                if (a == null || "pending".equals(a.status)) {
                    throw new Errors.NotFound("no active user named " + member);
                }
            }
            ServerStateStore.Group g = new ServerStateStore.Group();
            g.id = create.groupId();
            g.name = create.name();
            g.privacy = create.privacy();
            g.owner = client.name;
            g.members.addAll(create.members());
            g.createdAt = System.currentTimeMillis();
            store.state().groups.put(g.id, g);
            store.save();
            conn.send(Wire.ack(envelope.id(), "created"));
            broadcastGroupUpdate(g);
            for (String member : g.members) {
                addNotification(member, new ServerStateStore.Notif(), n -> {
                    n.id = Ids.newId();
                    n.kind = "info";
                    n.state = "unread";
                    n.from = g.owner;
                    n.text = g.owner + " added you to " + describeGroup(g);
                    n.createdAt = System.currentTimeMillis();
                    n.expiresAt = n.createdAt + config.notificationRetentionDays() * 24L * 3600_000L;
                    n.refId = g.id;
                });
                pushNotification(member, lastNotification(member));
            }
            store.save();
        }
    }

    private void handleGroupMemberOp(Client client, Conn conn, Envelope envelope, boolean invite) {
        var op = Wire.parseGroupMemberOp(envelope);
        synchronized (store) {
            ServerStateStore.Group g = requireGroup(op.groupId());
            if (!g.owner.equals(client.name) && !store.state().admins.contains(client.name)) {
                throw new Errors.Denied("only the group owner (or an operator) can "
                        + (invite ? "invite" : "remove") + " members");
            }
            if (invite) {
                ServerStateStore.Account target = store.state().accounts.get(op.member());
                if (target == null || "pending".equals(target.status)) {
                    throw new Errors.NotFound("no active user named " + op.member());
                }
                if (g.members.contains(op.member()) || g.owner.equals(op.member())) {
                    throw new Errors.Conflict(op.member() + " is already a member");
                }
                g.members.add(op.member());
                addNotification(op.member(), new ServerStateStore.Notif(), n -> {
                    n.id = Ids.newId();
                    n.kind = "info";
                    n.state = "unread";
                    n.from = g.owner;
                    n.text = g.owner + " added you to " + describeGroup(g);
                    n.createdAt = System.currentTimeMillis();
                    n.expiresAt = n.createdAt + config.notificationRetentionDays() * 24L * 3600_000L;
                    n.refId = g.id;
                });
                pushNotification(op.member(), lastNotification(op.member()));
            } else {
                if (!g.members.remove(op.member())) {
                    throw new Errors.NotFound(op.member() + " is not a member");
                }
                g.wrappedKeys.remove(op.member());
                if (g.privacy.equals("encrypted") && !g.members.isEmpty()) {
                    // Owner must rotate the group key; content sent before rotation
                    // remains readable by the removed member (honest, documented).
                    g.generation += 1;
                    g.wrappedKeys.clear();
                }
            }
            store.save();
            conn.send(Wire.ack(envelope.id(), "ok"));
            Envelope update = Wire.groupUpdate(toGroupDto(g));
            broadcastGroupUpdate(g);
            if (!invite) {
                // The removed member must learn they were removed.
                deliver(clients.get(op.member()), update);
            }
        }
    }

    private void handleGroupLeave(Client client, Conn conn, Envelope envelope) {
        var op = Wire.parseGroupOp(envelope);
        synchronized (store) {
            ServerStateStore.Group g = requireGroup(op.groupId());
            if (g.owner.equals(client.name)) {
                throw new Errors.Conflict("the owner cannot leave; transfer ownership first");
            }
            if (!g.members.remove(client.name)) {
                throw new Errors.Conflict("you are not a member of this group");
            }
            g.wrappedKeys.remove(client.name);
            if (g.privacy.equals("encrypted") && !g.members.isEmpty()) {
                g.generation += 1;
                g.wrappedKeys.clear();
            }
            store.save();
            conn.send(Wire.ack(envelope.id(), "left"));
            broadcastGroupUpdate(g);
            deliver(client, Wire.groupUpdate(toGroupDto(g)));
        }
    }

    private void handleGroupTransfer(Client client, Conn conn, Envelope envelope) {
        var op = Wire.parseGroupMemberOp(envelope);
        synchronized (store) {
            ServerStateStore.Group g = requireGroup(op.groupId());
            if (!g.owner.equals(client.name)) {
                throw new Errors.Denied("only the group owner can transfer ownership");
            }
            if (!g.members.remove(op.member())) {
                throw new Errors.NotFound(op.member() + " is not a member");
            }
            String oldOwner = g.owner;
            g.owner = op.member();
            g.members.add(oldOwner);
            store.save();
            conn.send(Wire.ack(envelope.id(), "transferred"));
            broadcastGroupUpdate(g);
        }
    }

    private void handleGroupMessage(Client client, Conn conn, Envelope envelope) {
        var msg = Wire.parseGroupMessage(envelope);
        if (!msg.sender().equals(client.name)) {
            throw new Errors.Denied("group message must come from your own account");
        }
        if (!messageLimiter.tryAcquire(client.name)) {
            throw new Errors.RateLimited("message rate limit exceeded; wait a minute");
        }
        ServerStateStore.Group g = requireGroup(msg.groupId());
        if (!g.owner.equals(client.name) && !g.members.contains(client.name)) {
            throw new Errors.Denied("you are not a member of this group");
        }
        boolean encrypted = g.privacy.equals("encrypted");
        if (encrypted && msg.text() != null) {
            throw new Errors.Denied("encrypted group requires ciphertext only");
        }
        if (!encrypted && msg.box() != null) {
            throw new Errors.Malformed("operator-visible group does not accept ciphertext");
        }
        // Relay to online members.
        Envelope relay = Wire.groupMessage(msg.msgId(), msg.groupId(), msg.sender(), msg.text(), msg.box());
        Client owner = clients.get(g.owner);
        if (owner != null && !g.owner.equals(msg.sender())) {
            deliver(owner, relay);
        }
        for (String member : g.members) {
            Client c = clients.get(member);
            if (c != null && !member.equals(msg.sender())) {
                deliver(c, relay);
            }
        }
        conn.send(Wire.ack(envelope.id(), "relayed"));
        if (!encrypted) {
            // Operator review log for operator-visible groups only.
            store.appendReview(new ServerStateStore.ReviewEntry(g.id, g.name, msg.msgId(),
                    msg.sender(), msg.text(), System.currentTimeMillis()), config.reviewLogRetention());
        }
    }

    private void handleGroupKeyWrap(Client client, Conn conn, Envelope envelope) {
        var wrap = Wire.parseGroupKeyWrap(envelope);
        synchronized (store) {
            ServerStateStore.Group g = requireGroup(wrap.groupId());
            if (!g.privacy.equals("encrypted")) {
                throw new Errors.Denied("this group does not use key wraps");
            }
            if (!g.owner.equals(client.name)) {
                throw new Errors.Denied("only the group owner distributes group keys");
            }
            if (!g.members.contains(wrap.forUser()) && !g.owner.equals(wrap.forUser())) {
                throw new Errors.Denied("key wrap addressed to a non-member");
            }
            // The sender identity must match the group owner's registered public key
            // (key-confusion defense: the server relays, it must not be able to
            // substitute a different sender key without the owner's registered key).
            ServerStateStore.Account ownerAcc = store.state().accounts.get(client.name);
            if (wrap.from() != null && ownerAcc != null && ownerAcc.x25519PublicKey != null
                    && !ownerAcc.x25519PublicKey.equals(wrap.fromPub())) {
                throw new Errors.Denied("key wrap sender key does not match the owner's registered key");
            }
            ServerStateStore.KeyWrap kw = new ServerStateStore.KeyWrap();
            kw.box = wrap.box();
            kw.generation = wrap.generation();
            g.wrappedKeys.put(wrap.forUser(), kw);
            if (wrap.generation() > g.generation) {
                g.generation = wrap.generation();
            }
            store.save();
            conn.send(Wire.ack(envelope.id(), "stored"));
            deliver(clients.get(wrap.forUser()), Wire.groupKeyWrap(wrap.groupId(), wrap.forUser(),
                    wrap.box(), wrap.generation(), wrap.from(), wrap.fromPub()));
        }
    }

    // ---------------- announcements / channel ----------------

    /** Operator-only: posts to the announcement channel and notifies every account. */
    public void announce(String text) {
        Text.requireCleanText(text, "announcement", Text.MAX_MESSAGE);
        String msgId = Ids.newId();
        long ts = System.currentTimeMillis();
        synchronized (store) {
            for (ServerStateStore.Account account : store.state().accounts.values()) {
                addNotification(account.name, new ServerStateStore.Notif(), n -> {
                    n.id = Ids.newId();
                    n.kind = "announcement";
                    n.state = "unread";
                    n.from = config.serverName();
                    n.text = text;
                    n.createdAt = ts;
                    n.expiresAt = ts + config.notificationRetentionDays() * 24L * 3600_000L;
                    n.refId = msgId;
                });
            }
            store.save();
        }
        for (Client c : clients.values()) {
            deliver(c, Wire.channelMessage(msgId, store.state().channelId, text));
            pushNotification(c.name, lastNotification(c.name));
        }
        events.onAudit("announcement posted (msgId=" + msgId + ")");
        events.onInfo("announcement posted to " + store.state().accounts.size() + " accounts");
    }

    // ---------------- operator operations ----------------

    public boolean isAdmin(String name) {
        return store.state().admins.contains(name);
    }

    public void promote(String name) {
        Text.requireServerName(name);
        synchronized (store) {
            if (!store.state().accounts.containsKey(name)) {
                throw new Errors.NotFound("no such account: " + name);
            }
            if (store.state().admins.contains(name)) {
                throw new Errors.Conflict(name + " is already an operator");
            }
            store.state().admins.add(name);
            store.save();
        }
        events.onAudit("promoted " + name + " to operator");
    }

    public void demote(String name) {
        synchronized (store) {
            if (!store.state().admins.remove(name)) {
                throw new Errors.Conflict(name + " is not an operator");
            }
            store.save();
        }
        events.onAudit("demoted " + name + " from operator");
    }

    public void approveRegistration(String ticketId) {
        synchronized (store) {
            approveRegistrationLocked(ticketId, "operator approved");
            store.save();
        }
        events.onAudit("registration " + ticketId + " approved");
    }

    public void rejectRegistration(String ticketId) {
        synchronized (store) {
            rejectRegistrationLocked(ticketId, "operator rejected");
            store.save();
        }
        events.onAudit("registration " + ticketId + " rejected");
    }

    private void approveRegistrationLocked(String ticketId, String reason) {
        ServerStateStore.Registration ticket = store.state().registrations.get(ticketId);
        if (ticket == null) {
            throw new Errors.NotFound("no such registration ticket");
        }
        ServerStateStore.Account account = new ServerStateStore.Account();
        account.name = ticket.username;
        account.passwordHash = ticket.passwordHash;
        account.status = "active";
        account.createdAt = System.currentTimeMillis();
        account.fields = ticket.fields;
        account.x25519PublicKey = ticket.x25519PublicKey;
        store.state().accounts.put(account.name, account);
        store.state().registrations.remove(ticketId);
        // Bootstrap operator promotion applies at approval time as well.
        if (config.adminUsernames().contains(account.name)
                && !store.state().admins.contains(account.name)) {
            store.state().admins.add(account.name);
            events.onAudit("bootstrap: " + account.name + " became operator");
        }
        addNotification(account.name, new ServerStateStore.Notif(), n -> {
            n.id = Ids.newId();
            n.kind = "info";
            n.state = "unread";
            n.from = config.serverName();
            n.text = "your registration was approved — you can log in now";
            n.createdAt = System.currentTimeMillis();
            n.expiresAt = 0;
            n.refId = ticketId;
        });
        events.onInfo("approved registration for " + ticket.username + " (" + reason + ")");
    }

    private void rejectRegistrationLocked(String ticketId, String reason) {
        ServerStateStore.Registration ticket = store.state().registrations.get(ticketId);
        if (ticket == null) {
            throw new Errors.NotFound("no such registration ticket");
        }
        store.state().registrations.remove(ticketId);
        events.onInfo("rejected registration for " + ticket.username + " (" + reason + ")");
    }

    // ---------------- BOT API ----------------

    /** Credential issued once at BOT creation: the token plus the X25519 private key. */
    public record BotCredential(String token, String x25519PrivateKeyBase64) {}

    /**
     * Creates a BOT account (marked BOT) and issues its credential. The token is
     * stored only as a SHA-256 digest; the credential is shown exactly once. The BOT
     * account cannot log in with a password and has no administrative rights.
     */
    public BotCredential createBot(String operatorName, String botName) {
        Text.requireServerName(botName);
        synchronized (store) {
            if (store.state().accounts.containsKey(botName)) {
                throw new Errors.Conflict("account already exists: " + botName);
            }
            java.security.KeyPair kp;
            try {
                kp = java.security.KeyPairGenerator.getInstance("X25519").generateKeyPair();
            } catch (java.security.GeneralSecurityException e) {
                throw new Errors.Internal("X25519 unavailable", e);
            }
            ServerStateStore.Account bot = new ServerStateStore.Account();
            bot.name = botName;
            bot.passwordHash = ""; // password login is impossible for BOT accounts
            bot.status = "active";
            bot.bot = true;
            bot.createdAt = System.currentTimeMillis();
            bot.x25519PublicKey = java.util.Base64.getEncoder().encodeToString(
                    org.ourcamellia.core.crypto.GroupCrypto.publicKeyBytes(kp));
            store.state().accounts.put(bot.name, bot);

            String token = org.ourcamellia.common.CryptoUtil.randomToken();
            ServerStateStore.BotToken bt = new ServerStateStore.BotToken();
            bt.tokenHash = org.ourcamellia.common.CryptoUtil.sha256Hex(token);
            bt.owner = operatorName;
            bt.botName = botName;
            bt.createdAt = System.currentTimeMillis();
            bt.rateLimitPerMinute = config.botApi().rateLimitPerMinute();
            store.state().botTokens.put(bt.tokenHash, bt);
            store.save();
            events.onAudit("bot " + botName + " created by " + operatorName);
            return new BotCredential(token, java.util.Base64.getEncoder().encodeToString(
                    kp.getPrivate().getEncoded()));
        }
    }

    /** Revokes every token of a BOT account (owner or operator only) and closes its sessions. */
    public void revokeBotTokens(String requester, String botName) {
        synchronized (store) {
            boolean allowed = store.state().admins.contains(requester)
                    || store.state().botTokens.values().stream()
                    .anyMatch(t -> t.botName.equals(botName) && t.owner.equals(requester));
            if (!allowed) {
                throw new Errors.Denied("only the BOT's owner or an operator can revoke its tokens");
            }
            store.state().botTokens.values().removeIf(t -> t.botName.equals(botName));
            store.save();
        }
        closeBotSession(botName);
        events.onAudit("bot tokens revoked for " + botName + " by " + requester);
    }

    /** Opens an in-process BOT session authenticated by token + X25519 private key. */
    public org.ourcamellia.core.botapi.BotSession openBotSession(String token, String x25519PrivateKeyBase64) {
        String hash = org.ourcamellia.common.CryptoUtil.sha256Hex(token);
        ServerStateStore.BotToken bt = store.state().botTokens.get(hash);
        if (bt == null) {
            throw new Errors.Auth("invalid bot token");
        }
        ServerStateStore.Account account = store.state().accounts.get(bt.botName);
        if (account == null || !account.bot) {
            throw new Errors.Auth("bot account missing");
        }
        PrivateKey xKey = null;
        if (x25519PrivateKeyBase64 != null && !x25519PrivateKeyBase64.isBlank()) {
            try {
                xKey = org.ourcamellia.core.crypto.GroupCrypto.privateKeyFrom(
                        java.util.Base64.getDecoder().decode(x25519PrivateKeyBase64));
            } catch (RuntimeException e) {
                throw new Errors.Auth("invalid bot private key");
            }
        }
        // One live session per bot account: replace the previous one.
        Client old = clients.get(bt.botName);
        if (old != null) {
            old.session.close();
        }
        org.ourcamellia.core.botapi.BotSession session = new org.ourcamellia.core.botapi.BotSession(
                this, bt.botName, hash, bt.rateLimitPerMinute, xKey);
        Client client = new Client(bt.botName, true, null, "bot-api", session::send);
        clients.put(bt.botName, client);
        // Bring the bot up to date on the groups it belongs to (and its key wraps).
        for (ServerStateStore.Group g : store.state().groups.values()) {
            if (g.owner.equals(bt.botName) || g.members.contains(bt.botName)) {
                session.send(Wire.groupUpdate(toGroupDto(g)));
                if ("encrypted".equals(g.privacy)) {
                    ServerStateStore.KeyWrap wrap = g.wrappedKeys.get(bt.botName);
                    if (wrap != null) {
                        session.send(Wire.groupKeyWrap(g.id, bt.botName, wrap.box, wrap.generation,
                                g.owner, store.state().accounts.containsKey(g.owner)
                                        ? store.state().accounts.get(g.owner).x25519PublicKey : null));
                    }
                }
            }
        }
        broadcastToFriends(bt.botName, Wire.peerState(bt.botName, "connected"));
        events.onInfo("bot session opened for " + bt.botName);
        return session;
    }

    /** Called by BotSession.close(). */
    public void closeBotSession(String botName) {
        Client c = clients.get(botName);
        if (c != null && c.bot) {
            clients.remove(botName, c);
            broadcastToFriends(botName, Wire.peerState(botName, "disconnected"));
            events.onInfo("bot session closed for " + botName);
        }
    }

    /** Routes a BOT API operation through the same authorization checks as network clients. */
    public void botDispatch(org.ourcamellia.core.botapi.BotSession session, Envelope envelope) {
        Client client = clients.get(session.botName());
        if (client == null || !client.bot) {
            throw new Errors.Auth("bot session is not active");
        }
        try {
            handleAuthed(client, session, envelope);
        } catch (Errors.OcException e) {
            session.send(Wire.error(envelope.id(), e.category, e.getMessage()));
        }
    }

    /** Operator moderation: removes one operator-visible group message everywhere. */
    public void modDelete(String groupId, String msgId) {
        ServerStateStore.Group g = requireGroup(groupId);
        if (g.privacy.equals("encrypted")) {
            throw new Errors.Denied("encrypted group content cannot be moderated");
        }
        store.removeReview(groupId, msgId);
        Envelope notice = Wire.modDelete(groupId, msgId, "operator");
        deliver(clients.get(g.owner), notice);
        for (String member : g.members) {
            deliver(clients.get(member), notice);
        }
        events.onAudit("moderated group " + groupId + " message " + msgId);
    }

    public List<ServerStateStore.ReviewEntry> review(String groupId, int limit) {
        requireGroup(groupId);
        return store.review(groupId, limit);
    }

    public String policySummary() {
        return "server: " + config.serverName() + "\n"
                + "registration: " + config.registrationPolicy()
                + (config.requireEmail() ? " (email required)" : "") + "\n"
                + "encrypted groups: " + (config.encryptedGroupsAllowed() ? "allowed" : "disabled") + "\n"
                + "notification retention: " + config.notificationRetentionDays() + " days\n"
                + "admin bootstrap names: " + String.join(", ", config.adminUsernames()) + "\n"
                + "accounts: " + store.state().accounts.size()
                + ", groups: " + store.state().groups.size();
    }

    public String stats() {
        return "connections: " + sessions.size() + ", online accounts: " + clients.size();
    }

    // ---------------- notification helpers ----------------

    private interface NotifFiller {
        void fill(ServerStateStore.Notif n);
    }

    private void addNotification(String user, ServerStateStore.Notif template, NotifFiller filler) {
        ServerStateStore.Notif n = new ServerStateStore.Notif();
        filler.fill(n);
        List<ServerStateStore.Notif> list = store.state().notifications
                .computeIfAbsent(user, k -> new ArrayList<>());
        // dedup by stable id
        if (list.stream().noneMatch(e -> e.id.equals(n.id))) {
            list.add(0, n);
        }
    }

    private ServerStateStore.Notif lastNotification(String user) {
        List<ServerStateStore.Notif> list = store.state().notifications.get(user);
        return list == null || list.isEmpty() ? null : list.get(0);
    }

    private void pushNotification(String user, ServerStateStore.Notif n) {
        if (n == null) {
            return;
        }
        deliver(clients.get(user), Wire.notifyPush(toDto(n)));
    }

    private ServerStateStore.Notif findNotification(String user, String id) {
        List<ServerStateStore.Notif> list = store.state().notifications.get(user);
        if (list == null) {
            return null;
        }
        return list.stream().filter(n -> n.id.equals(id)).findFirst().orElse(null);
    }

    private List<ServerStateStore.Notif> activeNotifications(String user) {
        List<ServerStateStore.Notif> list = store.state().notifications.get(user);
        if (list == null) {
            return List.of();
        }
        long now = System.currentTimeMillis();
        return list.stream()
                .filter(n -> !isExpired(n, now))
                .filter(n -> n.state.equals("unread") || n.state.equals("read"))
                .toList();
    }

    private int countUnread(String user) {
        return (int) activeNotifications(user).stream().filter(n -> n.state.equals("unread")).count();
    }

    private boolean isExpired(ServerStateStore.Notif n, long now) {
        return n.expiresAt > 0 && now > n.expiresAt;
    }

    private void purgeExpired() {
        synchronized (store) {
            long now = System.currentTimeMillis();
            boolean changed = false;
            for (List<ServerStateStore.Notif> list : store.state().notifications.values()) {
                for (ServerStateStore.Notif n : list) {
                    if (isExpired(n, now)) {
                        n.state = "expired";
                        changed = true;
                    }
                }
            }
            // Expired friend requests and registration tickets.
            List<String> staleRequests = new ArrayList<>();
            for (var e : store.state().friendRequests.entrySet()) {
                if (now - e.getValue().ts > config.notificationRetentionDays() * 24L * 3600_000L) {
                    staleRequests.add(e.getKey());
                }
            }
            staleRequests.forEach(store.state().friendRequests::remove);
            List<String> staleTickets = new ArrayList<>();
            for (var e : store.state().registrations.entrySet()) {
                if (e.getValue().expiresAt > 0 && now > e.getValue().expiresAt) {
                    staleTickets.add(e.getKey());
                }
            }
            staleTickets.forEach(store.state().registrations::remove);
            if (changed || !staleRequests.isEmpty() || !staleTickets.isEmpty()) {
                store.save();
            }
        }
    }

    // ---------------- wire helpers ----------------

    private WireMessages.NotificationDto toDto(ServerStateStore.Notif n) {
        return new WireMessages.NotificationDto(n.id, n.kind, n.state, n.from, n.text,
                n.createdAt, n.expiresAt, n.refId);
    }

    private List<WireMessages.NotificationDto> toDtos(List<ServerStateStore.Notif> list) {
        return list.stream().map(this::toDto).toList();
    }

    private WireMessages.GroupInfo toGroupDto(ServerStateStore.Group g) {
        Map<String, String> pubKeys = new LinkedHashMap<>();
        for (String name : g.members) {
            ServerStateStore.Account a = store.state().accounts.get(name);
            if (a != null && a.x25519PublicKey != null) {
                pubKeys.put(name, a.x25519PublicKey);
            }
        }
        ServerStateStore.Account ownerAcc = store.state().accounts.get(g.owner);
        if (ownerAcc != null && ownerAcc.x25519PublicKey != null) {
            pubKeys.put(g.owner, ownerAcc.x25519PublicKey);
        }
        return new WireMessages.GroupInfo(g.id, g.name, g.privacy, g.owner,
                List.copyOf(g.members), pubKeys, g.createdAt);
    }

    private String describeGroup(ServerStateStore.Group g) {
        String privacy = g.privacy.equals("encrypted")
                ? "encrypted group (operators cannot read content)" : "group";
        return privacy + " '" + g.name + "'";
    }

    private ServerStateStore.Group requireGroup(String groupId) {
        ServerStateStore.Group g = store.state().groups.get(groupId);
        if (g == null) {
            throw new Errors.NotFound("no such group");
        }
        return g;
    }

    private void requireMember(ServerStateStore.Group g, String user) {
        if (!g.owner.equals(user) && !g.members.contains(user)) {
            throw new Errors.Denied("you are not a member of this group");
        }
    }

    private boolean isBot(String name) {
        ServerStateStore.Account a = store.state().accounts.get(name);
        return a != null && a.bot;
    }

    private void broadcastToFriends(String name, Envelope envelope) {
        ServerStateStore.Account account = store.state().accounts.get(name);
        if (account == null) {
            return;
        }
        for (String friend : account.friends) {
            deliver(clients.get(friend), envelope);
        }
    }

    private void broadcastGroupUpdate(ServerStateStore.Group g) {
        Envelope update = Wire.groupUpdate(toGroupDto(g));
        deliver(clients.get(g.owner), update);
        for (String member : g.members) {
            deliver(clients.get(member), update);
        }
    }

    @Override
    public void close() {
        if (closed.getAndSet(true)) {
            return;
        }
        if (listener != null) {
            try {
                listener.close();
            } catch (java.io.IOException ignored) {
            }
        }
        for (ConnSession session : sessions.keySet()) {
            session.close();
        }
        sessions.clear();
        clients.clear();
        verifierExecutor.shutdown();
        store.close();
    }
}
