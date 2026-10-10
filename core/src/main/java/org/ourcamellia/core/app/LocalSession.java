package org.ourcamellia.core.app;

import org.ourcamellia.common.Errors;
import org.ourcamellia.common.Ids;
import org.ourcamellia.common.SelfSignedCerts;
import org.ourcamellia.common.Text;
import org.ourcamellia.common.config.ClientConfig;
import org.ourcamellia.common.domain.ConversationRef;
import org.ourcamellia.common.domain.FriendState;
import org.ourcamellia.common.domain.Message;
import org.ourcamellia.common.domain.NotificationKind;
import org.ourcamellia.common.domain.NotificationState;
import org.ourcamellia.common.domain.PeerStatus;
import org.ourcamellia.common.protocol.Envelope;
import org.ourcamellia.common.protocol.Wire;
import org.ourcamellia.core.discovery.DiscoveryService;
import org.ourcamellia.core.persist.AtomicFiles;
import org.ourcamellia.core.persist.ClientStateStore;
import org.ourcamellia.core.persist.LocalHistoryStore;
import org.ourcamellia.core.transport.Conn;
import org.ourcamellia.core.transport.ConnSession;
import org.ourcamellia.core.transport.SocketConn;
import org.ourcamellia.core.transport.TlsConnections;

import javax.net.ssl.SSLContext;
import java.net.InetAddress;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Local mode: direct peer communication with an independent local identity.
 *
 * - Discoverability and connectability are independent settings.
 * - Friendship gates chat: strangers may only use the friend-request path; ordinary
 *   messages from non-friends are refused (first-contact restriction).
 * - Observer-relative status: CONNECTED when a live connection exists, DISCOVERED
 *   after a recent discovery reply, UNREACHABLE after a failed attempt, UNCONFIRMED
 *   otherwise (honest "unknown" instead of a false "offline").
 * - Identity = local name + pinned certificate fingerprint (TOFU); a fingerprint
 *   change at a known friend's address is refused (impersonation defense).
 */
public final class LocalSession implements AutoCloseable {

    private static final Logger LOG = Logger.getLogger(LocalSession.class.getName());
    private static final String PROTOCOL_VERSION_STR = String.valueOf(Envelope.PROTOCOL_VERSION);

    private final ClientConfig config;
    private final ClientStateStore store;
    private final LocalHistoryStore history;
    private final AppEvents events;
    private final Path dataDir;

    private String myName;
    private SelfSignedCerts.GeneratedCert identity;
    private SSLContext serverContext;
    private SSLContext clientContext;
    private javax.net.ssl.SSLServerSocket listener;
    private DiscoveryService discovery;
    private final AtomicBoolean closed = new AtomicBoolean(false);

    // Runtime-togglable settings (initialized from config; REQUIREMENTS 3.2).
    private volatile boolean discoverable;
    private volatile boolean connectable;

    private final Object lock = new Object();
    private final Map<String, Peer> peers = new LinkedHashMap<>();
    private final Map<String, DiscoveredPeer> discovered = new ConcurrentHashMap<>();

    /** A known/discovered peer entry. */
    public record DiscoveredPeer(String name, String host, int port, String fingerprint, long expiresAt) {}

    static final class Peer {
        String name;
        ConnSession session;
        PeerStatus status = PeerStatus.UNCONFIRMED;
        String address;       // host:port of the live connection
        String fingerprint;

        boolean sessionIsOpen() {
            return session != null && session.isOpen();
        }
    }

    public LocalSession(ClientConfig config, ClientStateStore store, LocalHistoryStore history,
                        AppEvents events, Path dataDir) {
        this.config = config;
        this.store = store;
        this.history = history;
        this.events = events;
        this.dataDir = dataDir;
        this.discoverable = config.discoverable();
        this.connectable = config.connectable();
    }

    public boolean isActive() {
        return myName != null;
    }

    public String myName() {
        return myName;
    }

    public String myFingerprint() {
        return identity == null ? null : identity.fingerprint();
    }

    /** Enters Local mode with the given username; loads/generates the local identity. */
    public void start(String name) {
        synchronized (lock) {
            if (myName != null) {
                throw new Errors.Conflict("Local mode already active");
            }
            Text.requireLocalName(name);
            this.myName = name;

            Path ks = dataDir.resolve("local-identity.p12");
            try {
                if (java.nio.file.Files.exists(ks)) {
                    identity = SelfSignedCerts.loadKeystore(ks, keystorePassword());
                } else {
                    identity = SelfSignedCerts.generate("ourcamellia-local-" + name, 3650);
                    SelfSignedCerts.saveKeystore(ks, identity.cert(), identity.key(), keystorePassword());
                }
            } catch (Errors.OcException e) {
                throw new Errors.Persistence("local identity unavailable: " + e.getMessage(), e);
            }
            store.setLocalIdentity(name, identity.fingerprint());
            serverContext = SelfSignedCerts.serverContextWithTrustAll(identityKeyStore(), keystorePassword().toCharArray());
            // Peer identity is established by fingerprint pinning AFTER the handshake,
            // so the TLS layer trusts any cert here (see SelfSignedCerts.trustAllContext).
            clientContext = SelfSignedCerts.trustAllContext(identityKeyStore(), keystorePassword().toCharArray());

            if (connectable) {
                try {
                    listener = TlsConnections.listen(config.listenHost(), config.listenPort(),
                            serverContext, true);
                    Thread.ofVirtual().name("local-listener").start(this::acceptLoop);
                } catch (Errors.OcException e) {
                    LOG.log(Level.WARNING, "inbound listener unavailable ({0}); outbound still works", e.getMessage());
                    events.onInfo("warning: inbound listener unavailable: " + e.getMessage());
                }
            }
            discovery = new DiscoveryService(config.discoveryPort(),
                    () -> discoverable, () -> connectable && listener != null,
                    () -> myName, () -> config.listenPort(), () -> identity.fingerprint(),
                    config.discoveryTtlSeconds() * 1000L, null);
            discovery.setReplySink((reply, source) -> onDiscoveryReply(reply, source));
            discovery.start();
        }
    }

    public boolean discoverable() {
        return discoverable;
    }

    public boolean connectable() {
        return connectable;
    }

    /** Toggles discovery visibility (independent of connectability). */
    public void setDiscoverable(boolean on) {
        synchronized (lock) {
            requireActive();
            this.discoverable = on;
        }
    }

    /** Toggles inbound connection acceptance; binds/unbinds the listener as needed. */
    public void setConnectable(boolean on) {
        synchronized (lock) {
            requireActive();
            if (on == this.connectable) {
                return;
            }
            this.connectable = on;
            if (on) {
                try {
                    listener = TlsConnections.listen(config.listenHost(), config.listenPort(),
                            serverContext, true);
                    Thread.ofVirtual().name("local-listener").start(this::acceptLoop);
                } catch (Errors.OcException e) {
                    this.connectable = false;
                    throw new Errors.Network("cannot enable inbound connections: " + e.getMessage());
                }
            } else if (listener != null) {
                try {
                    listener.close();
                } catch (java.io.IOException ignored) {
                }
                listener = null;
            }
        }
    }

    private String keystorePassword() {
        // Random per-installation password stored next to the keystore (0600). Protects
        // the private key at rest against casual exposure; the file system is the trust
        // boundary (documented in THREAT_MODEL.md).
        Path pwFile = dataDir.resolve("local-identity.password");
        byte[] raw = AtomicFiles.readOrNull(pwFile);
        if (raw != null) {
            return new String(raw, java.nio.charset.StandardCharsets.US_ASCII).trim();
        }
        String pw = org.ourcamellia.common.CryptoUtil.randomHex(16);
        AtomicFiles.writeString(pwFile, pw + "\n");
        try {
            java.nio.file.Files.setPosixFilePermissions(pwFile,
                    java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
        } catch (Exception ignored) {
        }
        return pw;
    }

    private KeyStore identityKeyStore() {
        try {
            KeyStore ks = KeyStore.getInstance(SelfSignedCerts.KEYSTORE_TYPE);
            ks.load(null, null);
            ks.setKeyEntry(SelfSignedCerts.DEFAULT_ALIAS, identity.key(),
                    keystorePassword().toCharArray(),
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
                String fp = SelfSignedCerts.fingerprint(
                        (java.security.cert.X509Certificate) ssl.getSession().getPeerCertificates()[0]);
                String desc = ssl.getInetAddress().getHostAddress() + ":" + ssl.getPort();
                SocketConn conn = new SocketConn(ssl, desc, fp, config.maxFrameBytes());
                InboundHolder holder = new InboundHolder();
                ConnSession session = new ConnSession(conn, inboundHandler(holder),
                        config.pingIntervalMs(), config.readTimeoutMs());
                holder.session = session;
                holder.conn = conn;
            } catch (Errors.OcException e) {
                System.err.println("DEBUG-ACCEPT: OcException " + e + " " + e.getMessage());
                if (!closed.get()) {
                    LOG.log(Level.FINE, "inbound accept failed: {0}", e.getMessage());
                }
            } catch (java.io.IOException e) {
                System.err.println("DEBUG-ACCEPT: IOException " + e + " " + e.getMessage());
                if (!closed.get()) {
                    LOG.log(Level.FINE, "inbound accept io failure: {0}", e.getMessage());
                }
            } catch (Throwable t) {
                System.err.println("DEBUG-ACCEPT: Throwable " + t);
            }
        }
    }

    private static final class InboundHolder {
        volatile ConnSession session;
        volatile Conn conn;
    }

    private ConnSession.Handler inboundHandler(InboundHolder holder) {
        return new ConnSession.Handler() {
            private volatile String peerName;

            @Override
            public void onEnvelope(Conn conn, Envelope envelope) {
                if (peerName == null) {
                    if (!envelope.type().equals(Wire.T_HELLO)) {
                        conn.send(Wire.error(envelope.id(), Errors.Category.MALFORMED, "hello required first"));
                        conn.close();
                        return;
                    }
                    var hello = Wire.parseHello(envelope);
                    if (!hello.version().equals(PROTOCOL_VERSION_STR)) {
                        conn.send(Wire.error(envelope.id(), Errors.Category.MALFORMED,
                                "unsupported protocol version " + hello.version()));
                        conn.close();
                        return;
                    }
                    String name = Text.requireLocalName(hello.client());
                    peerName = name;
                    // Both sides identify themselves: answer with our own HELLO.
                    conn.send(Wire.hello(myName, PROTOCOL_VERSION_STR));
                    onPeerHello(name, holder, conn.remoteFingerprint());
                    return;
                }
                dispatch(peerName, conn, envelope);
            }

            @Override
            public void onClosed(Conn conn, String reason) {
                if (peerName != null) {
                    onPeerDisconnected(peerName);
                }
            }
        };
    }

    private void onPeerHello(String name, InboundHolder holder, String remoteFp) {
        synchronized (lock) {
            // Impersonation defense: a known friend's name on a connection whose
            // certificate fingerprint differs from the pinned one is rejected.
            ClientStateStore.FriendRec friend = store.friend(name);
            if (friend != null && friend.fingerprint() != null
                    && !friend.fingerprint().equalsIgnoreCase(remoteFp)) {
                holder.conn.send(Wire.error(null, Errors.Category.DENIED,
                        "certificate for '" + name + "' does not match the pinned identity"));
                holder.conn.close();
                return;
            }
            Peer old = peers.get(name);
            if (old != null) {
                old.session.close();
            }
            Peer peer = new Peer();
            peer.name = name;
            peer.fingerprint = remoteFp;
            peer.address = holder.conn.remoteDescription();
            peer.session = holder.session;
            peers.put(name, peer);
            setStatus(name, PeerStatus.CONNECTED, peer.address);
        }
    }

    /** Outbound: connects to host:port with TOFU pinning, sends HELLO. */
    public void connect(String host, int port) {
        synchronized (lock) {
            requireActive();
            if (port < 1 || port > 65535) {
                throw new Errors.Validation("invalid port");
            }
            String address = host + ":" + port;
            // Reuse an existing live connection to this address.
            for (Peer p : peers.values()) {
                if (address.equals(p.address) && p.sessionIsOpen()) {
                    return;
                }
            }
            // If this address is a known friend, pin their fingerprint; else TOFU.
            String expected = PinGuard.expectedFingerprint(store, address);
            var result = TlsConnections.connect(host, port, expected, clientContext, config.connectTimeoutMs());
            PinGuard.check(store, result.fingerprint(), address);
            String desc = result.socket().getInetAddress().getHostAddress() + ":" + port;
            SocketConn conn;
            try {
                conn = new SocketConn(result.socket(), desc, result.fingerprint(), config.maxFrameBytes());
            } catch (java.io.IOException e) {
                throw new Errors.Network("connection setup failed", e);
            }
            Peer peer = new Peer();
            peer.address = address;
            peer.fingerprint = result.fingerprint();
            peer.session = new ConnSession(conn, outboundHandler(peer), config.pingIntervalMs(),
                    config.readTimeoutMs());
            peer.session.conn().send(Wire.hello(myName, PROTOCOL_VERSION_STR));
        }
    }

    private ConnSession.Handler outboundHandler(Peer peer) {
        return new ConnSession.Handler() {
            private volatile boolean gotHello = false;

            @Override
            public void onEnvelope(Conn conn, Envelope envelope) {
                if (!gotHello) {
                    if (!envelope.type().equals(Wire.T_HELLO)) {
                        conn.send(Wire.error(envelope.id(), Errors.Category.MALFORMED, "hello required first"));
                        conn.close();
                        return;
                    }
                    var hello = Wire.parseHello(envelope);
                    if (!hello.version().equals(PROTOCOL_VERSION_STR)) {
                        conn.send(Wire.error(envelope.id(), Errors.Category.MALFORMED,
                                "unsupported protocol version " + hello.version()));
                        conn.close();
                        return;
                    }
                    String name = Text.requireLocalName(hello.client());
                    gotHello = true;
                    synchronized (lock) {
                        peer.name = name;
                        Peer old = peers.get(name);
                        if (old != null && old != peer) {
                            old.session.close();
                        }
                        peers.put(name, peer);
                        setStatus(name, PeerStatus.CONNECTED, peer.address);
                    }
                    return;
                }
                dispatch(peer.name, conn, envelope);
            }

            @Override
            public void onClosed(Conn conn, String reason) {
                synchronized (lock) {
                    if (peer.name != null && peers.get(peer.name) == peer) {
                        peers.remove(peer.name);
                    }
                }
                if (peer.name != null) {
                    events.onPeerStatus(peer.name, PeerStatus.UNCONFIRMED);
                    events.onStatusChanged();
                }
            }
        };
    }

    // ---------------- protocol dispatch ----------------

    private void dispatch(String peerName, Conn conn, Envelope envelope) {
        String type = envelope.type();
        try {
            switch (type) {
                case Wire.T_MESSAGE -> onMessageFrame(peerName, conn, envelope);
                case Wire.T_DELIVERY -> onDeliveryFrame(peerName, envelope);
                case Wire.T_FRIEND_REQUEST -> onFriendRequestFrame(peerName, conn, envelope);
                case Wire.T_FRIEND_REPLY -> onFriendReplyFrame(peerName, envelope);
                case Wire.T_ERROR -> events.onInfo("peer " + peerName + " reported: "
                        + envelope.body().path("message").asText("error"));
                default -> conn.send(Wire.error(envelope.id(), Errors.Category.USAGE, "unsupported frame type"));
            }
        } catch (Errors.OcException e) {
            conn.send(Wire.error(envelope.id(), e.category, e.getMessage()));
        }
    }

    private void onMessageFrame(String peerName, Conn conn, Envelope envelope) {
        var m = Wire.parseMessage(envelope);
        if (!m.sender().equals(peerName)) {
            throw new Errors.Malformed("sender does not match connection peer");
        }
        if (!m.to().equals(myName)) {
            throw new Errors.Malformed("message addressed to someone else");
        }
        if (friendState(peerName) != FriendState.ACCEPTED) {
            // First-contact restriction: chat requires accepted friendship.
            conn.send(Wire.error(envelope.id(), Errors.Category.DENIED,
                    "you are not friends with " + myName + "; send a friend request first"));
            return;
        }
        recordInbound(peerName, m.msgId(), m.sender(), m.text(), m.ts());
        conn.send(Wire.delivery(m.msgId(), peerName, "delivered"));
    }

    private void onDeliveryFrame(String peerName, Envelope envelope) {
        var d = Wire.parseDelivery(envelope);
        events.onInfo("delivered to " + d.to());
        events.onStatusChanged();
    }

    private void onFriendRequestFrame(String peerName, Conn conn, Envelope envelope) {
        var req = Wire.parseFriendRequest(envelope);
        if (!req.from().equals(peerName) || !req.to().equals(myName)) {
            throw new Errors.Malformed("friend request fields mismatch");
        }
        FriendState current = friendState(peerName);
        if (current == FriendState.ACCEPTED) {
            conn.send(Wire.friendReply(req.requestId(), myName, peerName, true));
            return;
        }
        if (current == FriendState.PENDING_IN) {
            return; // already pending; idempotent
        }
        store.putFriend(new ClientStateStore.FriendRec(peerName, FriendState.PENDING_IN.name(),
                conn.remoteDescription(), conn.remoteFingerprint(), System.currentTimeMillis()));
        store.addNotification(new ClientStateStore.NotifRec(
                Ids.newId(), NotificationKind.FRIEND_REQUEST.name(), NotificationState.UNREAD.name(),
                peerName, peerName + " sent you a friend request", System.currentTimeMillis(),
                System.currentTimeMillis() + 7L * 24 * 3600 * 1000, req.requestId()));
        events.onNotificationsChanged();
        events.onStatusChanged();
    }

    private void onFriendReplyFrame(String peerName, Envelope envelope) {
        var reply = Wire.parseFriendReply(envelope);
        if (!reply.from().equals(peerName) || !reply.to().equals(myName)) {
            throw new Errors.Malformed("friend reply fields mismatch");
        }
        if (reply.accept()) {
            store.putFriend(new ClientStateStore.FriendRec(peerName, FriendState.ACCEPTED.name(),
                    peerAddress(peerName), peerFingerprint(peerName), System.currentTimeMillis()));
            store.addNotification(new ClientStateStore.NotifRec(
                    Ids.newId(), NotificationKind.INFO.name(), NotificationState.UNREAD.name(),
                    peerName, peerName + " accepted your friend request", System.currentTimeMillis(),
                    0, reply.requestId()));
        } else {
            store.putFriend(new ClientStateStore.FriendRec(peerName, FriendState.REJECTED.name(),
                    null, null, System.currentTimeMillis()));
        }
        events.onNotificationsChanged();
        events.onStatusChanged();
    }

    // ---------------- friendship operations ----------------

    /** Sends a friend request. Returns false when the peer is unreachable (UNDELIVERABLE). */
    public boolean sendFriendRequest(String peerName) {
        synchronized (lock) {
            requireActive();
            Text.requireLocalName(peerName);
            if (peerName.equals(myName)) {
                throw new Errors.Usage("you cannot friend yourself");
            }
            FriendState current = friendState(peerName);
            if (current == FriendState.ACCEPTED) {
                throw new Errors.Conflict("you are already friends with " + peerName);
            }
            if (current == FriendState.PENDING_IN) {
                throw new Errors.Conflict("a friend request from " + peerName
                        + " is pending — accept or reject it");
            }
            if (current == FriendState.PENDING_OUT) {
                throw new Errors.Conflict("a friend request to " + peerName + " is already pending");
            }
            Peer peer = peers.get(peerName);
            if (peer == null || !peer.sessionIsOpen()) {
                DiscoveredPeer d = discovered.get(peerName);
                if (d != null && d.expiresAt() > System.currentTimeMillis()) {
                    connect(d.host(), d.port());
                    peer = peers.get(peerName);
                }
            }
            if (peer == null || !peer.sessionIsOpen()) {
                store.putFriend(new ClientStateStore.FriendRec(peerName, FriendState.UNDELIVERABLE.name(),
                        null, null, System.currentTimeMillis()));
                events.onStatusChanged();
                return false;
            }
            String requestId = Ids.newId();
            peer.session.conn().send(Wire.friendRequest(requestId, myName, peerName));
            store.putFriend(new ClientStateStore.FriendRec(peerName, FriendState.PENDING_OUT.name(),
                    peer.address, peer.fingerprint, System.currentTimeMillis()));
            events.onStatusChanged();
            return true;
        }
    }

    /** Accepts a pending incoming friend request (requestId from the notification refId). */
    public void acceptFriendRequest(String peerName, String requestId) {
        synchronized (lock) {
            requireActive();
            Text.requireLocalName(peerName);
            Peer peer = peers.get(peerName);
            if (peer == null || !peer.sessionIsOpen()) {
                throw new Errors.Network("no connection to " + peerName
                        + " — acceptance can only be sent while the peer is reachable");
            }
            peer.session.conn().send(Wire.friendReply(requestId, myName, peerName, true));
            store.putFriend(new ClientStateStore.FriendRec(peerName, FriendState.ACCEPTED.name(),
                    peer.address, peer.fingerprint, System.currentTimeMillis()));
            events.onStatusChanged();
        }
    }

    public void rejectFriendRequest(String peerName, String requestId) {
        synchronized (lock) {
            requireActive();
            Text.requireLocalName(peerName);
            Peer peer = peers.get(peerName);
            if (peer != null && peer.sessionIsOpen()) {
                peer.session.conn().send(Wire.friendReply(requestId, myName, peerName, false));
            }
            store.putFriend(new ClientStateStore.FriendRec(peerName, FriendState.REJECTED.name(),
                    null, null, System.currentTimeMillis()));
            events.onStatusChanged();
        }
    }

    // ---------------- messaging ----------------

    /** Sends ordinary text to a friend. Requires accepted friendship and a live connection. */
    public void sendMessage(String peerName, String text) {
        synchronized (lock) {
            requireActive();
            Text.requireCleanText(text, "message", Text.MAX_MESSAGE);
            if (friendState(peerName) != FriendState.ACCEPTED) {
                throw new Errors.Denied("you are not friends with " + peerName);
            }
            Peer peer = peers.get(peerName);
            if (peer == null || !peer.sessionIsOpen()) {
                throw new Errors.Network("no connection to " + peerName + " — the message was not sent");
            }
            String msgId = Ids.newId();
            long ts = System.currentTimeMillis();
            peer.session.conn().send(Wire.message(msgId, myName, peerName, text));
            recordOutbound(peerName, msgId, text, ts);
        }
    }

    /** Test-only hook: sends a raw frame to a connected peer, bypassing local checks. */
    void rawSend(String peerName, Envelope envelope) {
        synchronized (lock) {
            Peer peer = peers.get(peerName);
            if (peer == null || !peer.sessionIsOpen()) {
                throw new Errors.Network("no connection to " + peerName);
            }
            peer.session.conn().send(envelope);
        }
    }

    private void recordInbound(String peerName, String msgId, String sender, String text, long ts) {
        String key = convKey(peerName);
        history.onMessage(key, peerName, new LocalHistoryStore.Entry(msgId, sender, text, ts, "in"));
        events.onMessage(ConversationRef.privateChat(peerName, false),
                new Message(msgId, key, sender, text, ts));
    }

    private void recordOutbound(String peerName, String msgId, String text, long ts) {
        String key = convKey(peerName);
        history.onMessage(key, peerName, new LocalHistoryStore.Entry(msgId, myName, text, ts, "out"));
        events.onMessage(ConversationRef.privateChat(peerName, false),
                new Message(msgId, key, myName, text, ts));
    }

    public String convKey(String peerName) {
        return "local:" + peerName;
    }

    // ---------------- status / queries ----------------

    public FriendState friendState(String peerName) {
        ClientStateStore.FriendRec f = store.friend(peerName);
        return f == null ? FriendState.NONE : FriendState.valueOf(f.state());
    }

    public PeerStatus peerStatus(String peerName) {
        Peer peer;
        synchronized (lock) {
            peer = peers.get(peerName);
        }
        if (peer != null && peer.sessionIsOpen()) {
            return PeerStatus.CONNECTED;
        }
        DiscoveredPeer d = discovered.get(peerName);
        if (d != null && d.expiresAt() > System.currentTimeMillis()) {
            return PeerStatus.DISCOVERED;
        }
        return PeerStatus.UNCONFIRMED;
    }

    public List<String> friends() {
        List<String> out = new ArrayList<>();
        for (var e : store.state().friends.entrySet()) {
            if (FriendState.valueOf(e.getValue().state()) == FriendState.ACCEPTED) {
                out.add(e.getKey());
            }
        }
        out.sort(Comparator.naturalOrder());
        return out;
    }

    public List<DiscoveredPeer> discoveredPeers() {
        long now = System.currentTimeMillis();
        return discovered.values().stream()
                .filter(d -> d.expiresAt() > now)
                .sorted(Comparator.comparing(DiscoveredPeer::name))
                .toList();
    }

    public void runDiscovery() {
        if (discovery != null) {
            discovery.query();
        }
    }

    public boolean discoveryAvailable() {
        return discovery != null && discovery.available();
    }

    private void onDiscoveryReply(org.ourcamellia.common.protocol.WireMessages.DiscoverReply reply, InetAddress source) {
        if (myName == null || reply.username().equals(myName)) {
            return; // our own echo
        }
        discovered.put(reply.username(), new DiscoveredPeer(reply.username(),
                source.getHostAddress(), reply.tcpPort(), reply.fp(), reply.expiresAt()));
        synchronized (lock) {
            if (peers.get(reply.username()) == null) {
                events.onPeerStatus(reply.username(), PeerStatus.DISCOVERED);
            }
        }
        events.onStatusChanged();
    }

    private void setStatus(String name, PeerStatus status, String address) {
        Peer peer = peers.get(name);
        if (peer != null) {
            peer.status = status;
            if (address != null) {
                peer.address = address;
            }
        }
        events.onPeerStatus(name, status);
        events.onStatusChanged();
    }

    private void onPeerDisconnected(String name) {
        synchronized (lock) {
            peers.remove(name);
        }
        // Honest state: we cannot distinguish offline from unknown.
        events.onPeerStatus(name, PeerStatus.UNCONFIRMED);
        events.onStatusChanged();
    }

    private String peerFingerprint(String name) {
        Peer p = peers.get(name);
        return p != null ? p.fingerprint : null;
    }

    private String peerAddress(String name) {
        Peer p = peers.get(name);
        return p != null ? p.address : null;
    }

    private void requireActive() {
        if (myName == null) {
            throw new Errors.Usage("Local mode is not active");
        }
    }

    @Override
    public void close() {
        if (closed.getAndSet(true)) {
            return;
        }
        if (discovery != null) {
            discovery.close();
        }
        if (listener != null) {
            try {
                listener.close();
            } catch (java.io.IOException ignored) {
            }
        }
        synchronized (lock) {
            for (Peer p : new ArrayList<>(peers.values())) {
                if (p.session != null) {
                    p.session.close();
                }
            }
            peers.clear();
        }
        events.onShutdown();
    }
}
