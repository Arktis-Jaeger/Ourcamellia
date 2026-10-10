package org.ourcamellia.core.app;

import org.ourcamellia.common.Errors;
import org.ourcamellia.common.Ids;
import org.ourcamellia.common.Text;
import org.ourcamellia.common.config.ClientConfig;
import org.ourcamellia.common.domain.ConversationRef;
import org.ourcamellia.common.domain.FriendState;
import org.ourcamellia.common.domain.Message;
import org.ourcamellia.common.domain.Notification;
import org.ourcamellia.common.domain.NotificationKind;
import org.ourcamellia.common.domain.NotificationState;
import org.ourcamellia.common.domain.PeerStatus;
import org.ourcamellia.common.protocol.Envelope;
import org.ourcamellia.common.protocol.Wire;
import org.ourcamellia.common.protocol.WireMessages;
import org.ourcamellia.core.crypto.GroupCrypto;
import org.ourcamellia.core.persist.ClientStateStore;
import org.ourcamellia.core.persist.LocalHistoryStore;
import org.ourcamellia.core.transport.ConnSession;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Server-mode client session: one connection to one independent server. Handles
 * login/registration, friendships, private messaging, groups (both privacy modes),
 * notifications, and the announcement channel. Group encryption is performed
 * client-side with {@link GroupCrypto}; the server never sees group keys.
 */
public final class ServerSession implements AutoCloseable {

    private final ClientConfig config;
    private final ClientStateStore store;
    private final LocalHistoryStore history;
    private final AppEvents events;
    private final ClientApp app;

    // connection state
    private volatile ConnSession session;
    private volatile String serverAddress;
    private volatile String serverName;
    private volatile String channelId;
    private volatile String loggedInUser;
    private volatile boolean bot = false;

    // friends + presence
    private final Map<String, FriendEntry> friends = new ConcurrentHashMap<>();
    private final Set<String> pendingOut = ConcurrentHashMap.newKeySet();
    private final List<WireMessages.NotificationDto> notifications = new CopyOnWriteArrayList<>();

    // groups
    private final Map<String, ClientGroup> groups = new ConcurrentHashMap<>();

    /** One group from this client's perspective (public for UI and tests). */
    public static final class ClientGroup {
        public volatile String id;
        public volatile String name;
        public volatile String privacy;
        public volatile String owner;
        public volatile List<String> members = List.of();
        public volatile byte[] groupKey;           // null until unwrapped
        public volatile long generation = 1;
        public volatile boolean rotationPending = false;
        public final Map<String, String> pubKeys = new ConcurrentHashMap<>();
    }

    record FriendEntry(String name, boolean online, boolean bot) {}

    public ServerSession(ClientConfig config, ClientStateStore store, LocalHistoryStore history,
                         AppEvents events, ClientApp app) {
        this.config = config;
        this.store = store;
        this.history = history;
        this.events = events;
        this.app = app;
    }

    // ---- wiring used by ServerConnection ----
    public ClientConfig config() { return config; }
    public ClientStateStore store() { return store; }
    public LocalHistoryStore history() { return history; }
    public AppEvents events() { return events; }
    public ClientApp app() { return app; }

    public boolean isConnected() {
        return session != null && session.isOpen();
    }

    public String serverAddress() { return serverAddress; }
    public String serverName() { return serverName; }
    public String loggedInUser() { return loggedInUser; }
    public String channelId() { return channelId; }
    public boolean isBot() { return bot; }
    public ConnSession session() { return session; }

    // ---- lifecycle ----

    public void connect(String address) {
        Text.requireCleanText(address, "server address", 255);
        int colon = address.lastIndexOf(':');
        if (colon <= 0 || colon == address.length() - 1) {
            throw new Errors.Validation("server address must be host:port");
        }
        String host = address.substring(0, colon);
        int port;
        try {
            port = Integer.parseInt(address.substring(colon + 1));
        } catch (NumberFormatException e) {
            throw new Errors.Validation("server address must be host:port");
        }
        ServerConnection.connect(this, host, port, address);
        this.serverAddress = address;
        events.onStatusChanged();
    }

    void setSession(ConnSession s) {
        this.session = s;
    }

    void setWelcome(String serverName, String channelId, int unread, String policy, String note) {
        this.serverName = serverName;
        this.channelId = channelId;
        events.onInfo("connected to server '" + serverName + "' — registration policy: " + policy
                + " — " + note);
        events.onStatusChanged();
    }

    void setLoggedIn(String username, boolean bot, int unread) {
        this.loggedInUser = username;
        this.bot = bot;
        events.onInfo("logged in as " + username + (bot ? " [BOT]" : ""));
        events.onStatusChanged();
    }

    void onClosed(String reason) {
        loggedInUser = null;
        friends.clear();
        notifications.clear();
        events.onInfo("disconnected from server: " + reason);
        events.onStatusChanged();
    }

    // ---- operations ----

    public void register(String username, String password, Map<String, String> fields) {
        ensureConnected();
        Text.requireServerName(username);
        byte[] pub = GroupCrypto.publicKeyBytes(store.x25519KeyPair());
        session.conn().send(Wire.register(username, password, Ids.newId(), fields,
                Base64.getEncoder().encodeToString(pub)));
    }

    public void login(String username, String password) {
        ensureConnected();
        Text.requireServerName(username);
        session.conn().send(Wire.login(username, password));
    }

    /** Reconnects automatically when the transport session was closed (e.g. after logout). */
    private void ensureConnected() {
        if (session == null || !session.isOpen()) {
            if (serverAddress == null) {
                throw new Errors.Network("not connected to a server");
            }
            connect(serverAddress);
        }
    }

    public void logout() {
        if (session != null) {
            session.close();
        }
    }

    void onRegisterResult(String status, String ticketId, String message) {
        events.onInfo("registration: " + status + (message.isBlank() ? "" : " — " + message));
    }

    // ---- notifications ----

    public List<Notification> notificationList() {
        long now = System.currentTimeMillis();
        List<Notification> out = new ArrayList<>();
        for (WireMessages.NotificationDto n : notifications) {
            if (n.expiresAt() > 0 && now > n.expiresAt()) {
                continue;
            }
            String state = n.state();
            if (state.equals("unread") || state.equals("read")) {
                out.add(new Notification(n.id(), NotificationKind.valueOf(
                        kindName(n.kind())), NotificationState.valueOf(state.toUpperCase()),
                        n.from(), n.text(), n.createdAt(), n.expiresAt(), n.refId()));
            }
        }
        return out;
    }

    private static String kindName(String wireKind) {
        return switch (wireKind) {
            case "friend-request" -> "FRIEND_REQUEST";
            case "announcement" -> "ANNOUNCEMENT";
            default -> "INFO";
        };
    }

    void onNotifications(List<WireMessages.NotificationDto> items) {
        for (WireMessages.NotificationDto n : items) {
            upsertNotification(n);
        }
        events.onNotificationsChanged();
    }

    void onNotification(WireMessages.NotificationDto n) {
        upsertNotification(n);
        events.onNotificationsChanged();
        events.onInfo("new notification: " + n.text());
    }

    private void upsertNotification(WireMessages.NotificationDto n) {
        for (int i = 0; i < notifications.size(); i++) {
            if (notifications.get(i).id().equals(n.id())) {
                notifications.set(i, n); // dedup by stable id
                return;
            }
        }
        notifications.add(0, n);
    }

    void onNotificationState(String notifId, String state) {
        for (int i = 0; i < notifications.size(); i++) {
            WireMessages.NotificationDto n = notifications.get(i);
            if (n.id().equals(notifId)) {
                notifications.set(i, new WireMessages.NotificationDto(n.id(), n.kind(), state,
                        n.from(), n.text(), n.createdAt(), n.expiresAt(), n.refId()));
                break;
            }
        }
        events.onNotificationsChanged();
    }

    /** Sends a notification action to the server; state updates arrive asynchronously. */
    public String notifyAction(Notification n, String action) {
        requireConnected();
        session.conn().send(Wire.notifyAction(n.id(), action));
        return "action sent";
    }

    // ---- friends ----

    void onFriendsList(List<WireMessages.FriendEntry> list) {
        friends.clear();
        for (WireMessages.FriendEntry f : list) {
            friends.put(f.name(), new FriendEntry(f.name(), f.status().equals("connected"), f.bot()));
        }
        events.onStatusChanged();
    }

    void onPeerState(String user, String status) {
        FriendEntry e = friends.get(user);
        if (e != null) {
            friends.put(user, new FriendEntry(user, status.equals("connected"), e.bot()));
            events.onPeerStatus(user, status.equals("connected")
                    ? PeerStatus.CONNECTED : PeerStatus.UNCONFIRMED);
            events.onStatusChanged();
        }
    }

    void onFriendState(WireMessages.FriendState fs) {
        if (fs.to().equals(loggedInUser) && fs.state().equals("accepted")) {
            friends.put(fs.from(), new FriendEntry(fs.from(), true, false));
            pendingOut.remove(fs.from());
            events.onStatusChanged();
        }
    }

    public List<String> friends() {
        List<String> out = new ArrayList<>(friends.keySet());
        out.sort(Comparator.naturalOrder());
        return out;
    }

    public FriendState friendState(String name) {
        if (friends.containsKey(name)) {
            return FriendState.ACCEPTED;
        }
        if (pendingOut.contains(name)) {
            return FriendState.PENDING_OUT;
        }
        for (Notification n : notificationList()) {
            if (n.kind() == NotificationKind.FRIEND_REQUEST && name.equals(n.from())) {
                return FriendState.PENDING_IN;
            }
        }
        return FriendState.NONE;
    }

    public PeerStatus peerStatus(String name) {
        FriendEntry e = friends.get(name);
        return e != null && e.online() ? PeerStatus.CONNECTED : PeerStatus.UNCONFIRMED;
    }

    public boolean sendFriendRequest(String name) {
        requireConnected();
        Text.requireServerName(name);
        if (name.equals(loggedInUser)) {
            throw new Errors.Usage("you cannot friend yourself");
        }
        if (friends.containsKey(name)) {
            throw new Errors.Conflict("you are already friends with " + name);
        }
        if (pendingOut.contains(name)) {
            throw new Errors.Conflict("a friend request to " + name + " is already pending");
        }
        pendingOut.add(name);
        session.conn().send(Wire.friendRequest(Ids.newId(), loggedInUser, name));
        events.onStatusChanged();
        return true;
    }

    public void acceptFriendRequest(String from, String requestId) {
        // Server-mediated: find the notification and pass it.
        for (Notification n : notificationList()) {
            if (n.kind() == NotificationKind.FRIEND_REQUEST && from.equals(n.from())
                    && requestId.equals(n.refId())) {
                notifyAction(n, "pass");
                return;
            }
        }
        throw new Errors.NotFound("friend request not found");
    }

    public void rejectFriendRequest(String from, String requestId) {
        for (Notification n : notificationList()) {
            if (n.kind() == NotificationKind.FRIEND_REQUEST && from.equals(n.from())
                    && requestId.equals(n.refId())) {
                notifyAction(n, "reject");
                return;
            }
        }
        throw new Errors.NotFound("friend request not found");
    }

    // ---- private messaging ----

    void onPrivateMessage(WireMessages.Message m) {
        if (!m.to().equals(loggedInUser)) {
            return;
        }
        String key = convKey(ConversationRef.privateChat(m.sender(), true));
        history.onMessage(key, m.sender(), new LocalHistoryStore.Entry(
                m.msgId(), m.sender(), m.text(), m.ts(), "in"));
        events.onMessage(ConversationRef.privateChat(m.sender(), true),
                new Message(m.msgId(), key, m.sender(), m.text(), m.ts()));
    }

    public void sendPrivate(String to, String text) {
        requireLoggedIn();
        Text.requireCleanText(text, "message", Text.MAX_MESSAGE);
        if (!friends.containsKey(to)) {
            throw new Errors.Denied("you are not friends with " + to);
        }
        String msgId = Ids.newId();
        long ts = System.currentTimeMillis();
        session.conn().send(Wire.message(msgId, loggedInUser, to, text));
        String key = convKey(ConversationRef.privateChat(to, true));
        history.onMessage(key, to, new LocalHistoryStore.Entry(
                msgId, loggedInUser, text, ts, "out"));
        events.onMessage(ConversationRef.privateChat(to, true),
                new Message(msgId, key, loggedInUser, text, ts));
    }

    // ---- channel ----

    void onChannelMessage(WireMessages.ChannelMessage m) {
        if (!m.channelId().equals(channelId)) {
            return;
        }
        String key = convKey(ConversationRef.channel(channelId, serverName == null ? "server" : serverName));
        history.onMessage(key, serverName == null ? "server" : serverName,
                new LocalHistoryStore.Entry(m.msgId(), serverName == null ? "server" : serverName,
                        m.text(), m.ts(), "in"));
        events.onMessage(ConversationRef.channel(channelId, serverName == null ? "server" : serverName),
                new Message(m.msgId(), key, serverName == null ? "server" : serverName, m.text(), m.ts()));
    }

    // ---- groups ----

    public List<ConversationRef> conversations() {
        List<ConversationRef> out = new ArrayList<>();
        if (channelId != null) {
            out.add(ConversationRef.channel(channelId, serverName == null ? "server" : serverName));
        }
        for (String friend : friends()) {
            out.add(ConversationRef.privateChat(friend, true));
        }
        for (ClientGroup g : groups.values()) {
            out.add(ConversationRef.group(g.id, g.name,
                    g.privacy.equals("encrypted")
                            ? org.ourcamellia.common.domain.GroupPrivacy.ENCRYPTED
                            : org.ourcamellia.common.domain.GroupPrivacy.OPERATOR_VISIBLE));
        }
        out.sort(Comparator.comparing((ConversationRef r) -> r.pinned() ? 0 : 1)
                .thenComparing(ConversationRef::title, SortUtil.SPEC_ORDER));
        return out;
    }

    public List<ClientGroup> groups() {
        return new ArrayList<>(groups.values());
    }

    void onGroupUpdate(WireMessages.GroupInfo info) {
        ClientGroup g = groups.computeIfAbsent(info.id(), id -> new ClientGroup());
        g.id = info.id();
        g.name = info.name();
        g.privacy = info.privacy();
        g.owner = info.owner();
        g.members = info.members();
        g.pubKeys.putAll(info.pubKeys());
        if (!info.members().contains(loggedInUser) && !info.owner().equals(loggedInUser)) {
            groups.remove(info.id()); // we were removed
        }
        events.onStatusChanged();
    }

    void onGroupMessage(WireMessages.GroupMessage m) {
        ClientGroup g = groups.get(m.groupId());
        if (g == null) {
            return;
        }
        String text;
        if (g.privacy.equals("encrypted")) {
            if (g.groupKey == null || m.box() == null) {
                events.onInfo("cannot decrypt group message (group key missing — ask the owner to re-send the key)");
                return;
            }
            String decrypted = GroupCrypto.decryptMessage(g.groupKey, g.id, m.box());
            if (decrypted == null) {
                events.onInfo("group message failed to decrypt (key rotation in progress?)");
                return;
            }
            text = decrypted;
        } else {
            text = m.text();
        }
        ConversationRef ref = ConversationRef.group(g.id, g.name, g.privacy.equals("encrypted")
                ? org.ourcamellia.common.domain.GroupPrivacy.ENCRYPTED
                : org.ourcamellia.common.domain.GroupPrivacy.OPERATOR_VISIBLE);
        String key = convKey(ref);
        history.onMessage(key, g.name, new LocalHistoryStore.Entry(
                m.msgId(), m.sender(), text, m.ts(), "in"));
        events.onMessage(ref, new Message(m.msgId(), key, m.sender(), text, m.ts()));
    }

    void onGroupKeyWrap(WireMessages.GroupKeyWrap w) {
        ClientGroup g = groups.get(w.groupId());
        if (g == null || !w.forUser().equals(loggedInUser)) {
            return;
        }
        byte[] senderPub = w.fromPub() == null ? null : Base64.getDecoder().decode(w.fromPub());
        if (senderPub == null || senderPub.length != 32) {
            events.onInfo("group key wrap has an invalid sender key (ignored)");
            return;
        }
        byte[] key = GroupCrypto.unwrapGroupKey(store.x25519KeyPair().getPrivate(),
                senderPub, w.groupId(), w.generation(), w.box());
        if (key == null) {
            events.onInfo("group key wrap could not be decrypted (ignored)");
            return;
        }
        g.groupKey = key;
        g.generation = w.generation();
        g.rotationPending = false;
        events.onInfo("received group key for '" + g.name + "'");
    }

    /** Creates a group. For encrypted groups the owner generates and distributes the key. */
    public String createGroup(String name, List<String> members, boolean encrypted) {
        requireLoggedIn();
        Text.requireGroupName(name);
        if (members.size() > 64) {
            throw new Errors.Validation("too many members (max 64)");
        }
        String groupId = Ids.newId();
        String privacy = encrypted ? "encrypted" : "operator-visible";
        session.conn().send(Wire.groupCreate(groupId, name, privacy, members));
        if (encrypted) {
            // Owner generates the group key now and wraps it per member (and keeps it).
            byte[] groupKey = GroupCrypto.randomGroupKey();
            ClientGroup g = groups.computeIfAbsent(groupId, id -> new ClientGroup());
            g.id = groupId;
            g.name = name;
            g.privacy = privacy;
            g.owner = loggedInUser;
            g.members = members;
            g.groupKey = groupKey;
            // We need member public keys; the server sends them via GROUP_UPDATE after
            // creation (it includes pubKeys). Distribute wraps once the update arrives.
            g.rotationPending = true; // wraps pending
            distributeKeysWhenReady(g);
        }
        return groupId;
    }

    /** Distributes key wraps when member public keys are known. */
    private void distributeKeysWhenReady(ClientGroup g) {
        Thread.ofVirtual().start(() -> {
            long deadline = System.currentTimeMillis() + 15_000;
            while (System.currentTimeMillis() < deadline) {
                boolean allKnown = true;
                for (String member : g.members) {
                    if (!g.pubKeys.containsKey(member)) {
                        allKnown = false;
                        break;
                    }
                }
                if (allKnown) {
                    sendWraps(g);
                    return;
                }
                try {
                    Thread.sleep(100);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                }
            }
            events.onInfo("warning: could not obtain public keys for all members of '"
                    + g.name + "' — send key wraps manually (${group-send-keys})");
        });
    }

    private void sendWraps(ClientGroup g) {
        var myKeys = store.x25519KeyPair();
        byte[] myPub = GroupCrypto.publicKeyBytes(myKeys);
        for (String member : g.members) {
            String pubB64 = g.pubKeys.get(member);
            if (pubB64 == null) {
                continue;
            }
            byte[] memberPub = Base64.getDecoder().decode(pubB64);
            String box = GroupCrypto.wrapGroupKey(myKeys.getPrivate(), memberPub, g.id,
                    g.generation, g.groupKey);
            session.conn().send(Wire.groupKeyWrap(g.id, member, box, g.generation,
                    loggedInUser, Base64.getEncoder().encodeToString(myPub)));
        }
        g.rotationPending = false;
    }

    /** Owner: re-wrap keys for remaining members after a removal (rotation). */
    public void rotateGroupKeys(String groupId) {
        requireLoggedIn();
        ClientGroup g = groups.get(groupId);
        if (g == null || !g.owner.equals(loggedInUser)) {
            throw new Errors.Denied("only the group owner rotates keys");
        }
        byte[] newKey = GroupCrypto.randomGroupKey();
        g.groupKey = newKey;
        g.generation += 1;
        sendWraps(g);
    }

    public void inviteMember(String groupId, String member) {
        requireLoggedIn();
        ClientGroup g = groups.get(groupId);
        if (g == null) {
            throw new Errors.NotFound("no such group");
        }
        session.conn().send(Wire.groupMemberOp(Wire.T_GROUP_INVITE, groupId, member));
        // For encrypted groups the new member's public key arrives via GROUP_UPDATE;
        // the owner distributes a wrap when it is known.
        if (g.privacy.equals("encrypted") && g.groupKey != null) {
            g.rotationPending = true;
            distributeKeysWhenReady(g);
        }
    }

    public void removeMember(String groupId, String member) {
        requireLoggedIn();
        session.conn().send(Wire.groupMemberOp(Wire.T_GROUP_REMOVE, groupId, member));
    }

    public void leaveGroup(String groupId) {
        requireLoggedIn();
        session.conn().send(Wire.groupOp(Wire.T_GROUP_LEAVE, groupId));
        groups.remove(groupId);
    }

    public void transferGroup(String groupId, String newOwner) {
        requireLoggedIn();
        session.conn().send(Wire.groupMemberOp(Wire.T_GROUP_TRANSFER, groupId, newOwner));
    }

    public List<String> groupMembers(String groupId) {
        ClientGroup g = groups.get(groupId);
        if (g == null) {
            throw new Errors.NotFound("no such group");
        }
        List<String> out = new ArrayList<>(g.members);
        out.add(0, g.owner);
        return out;
    }

    public ClientGroup group(String groupId) {
        return groups.get(groupId);
    }

    /** Sends text in a group; encrypted groups are encrypted client-side. */
    public void sendGroupMessage(String groupId, String text) {
        requireLoggedIn();
        Text.requireCleanText(text, "message", Text.MAX_MESSAGE);
        ClientGroup g = groups.get(groupId);
        if (g == null) {
            throw new Errors.NotFound("no such group");
        }
        if (!g.owner.equals(loggedInUser) && !g.members.contains(loggedInUser)) {
            throw new Errors.Denied("you are not a member of this group");
        }
        String msgId = Ids.newId();
        long ts = System.currentTimeMillis();
        if (g.privacy.equals("encrypted")) {
            if (g.groupKey == null) {
                throw new Errors.Denied("group key not available — ask the owner to re-send it");
            }
            String box = GroupCrypto.encryptMessage(g.groupKey, g.id,
                    text.getBytes(StandardCharsets.UTF_8));
            session.conn().send(Wire.groupMessage(msgId, groupId, loggedInUser, null, box));
            recordGroupOut(g, msgId, text, ts);
        } else {
            session.conn().send(Wire.groupMessage(msgId, groupId, loggedInUser, text, null));
            recordGroupOut(g, msgId, text, ts);
        }
    }

    private void recordGroupOut(ClientGroup g, String msgId, String text, long ts) {
        ConversationRef ref = ConversationRef.group(g.id, g.name, g.privacy.equals("encrypted")
                ? org.ourcamellia.common.domain.GroupPrivacy.ENCRYPTED
                : org.ourcamellia.common.domain.GroupPrivacy.OPERATOR_VISIBLE);
        String key = convKey(ref);
        history.onMessage(key, g.name, new LocalHistoryStore.Entry(
                msgId, loggedInUser, text, ts, "out"));
        events.onMessage(ref, new Message(msgId, key, loggedInUser, text, ts));
    }

    // ---- conversations / say routing ----

    public void sayIn(ConversationRef conversation, String text) {
        requireLoggedIn();
        if (conversation == null) {
            throw new Errors.Usage("no conversation selected");
        }
        switch (conversation.kind()) {
            case PRIVATE -> sendPrivate(conversation.id(), text);
            case GROUP -> sendGroupMessage(conversation.id(), text);
            case CHANNEL -> throw new Errors.Denied(
                    "the server channel is read-only: only operators post announcements");
        }
    }

    public String convKey(ConversationRef ref) {
        String prefix = convKeyPrefix();
        return switch (ref.kind()) {
            case PRIVATE -> prefix + "priv:" + ref.id();
            case GROUP -> prefix + "grp:" + ref.id();
            case CHANNEL -> prefix + "channel";
        };
    }

    public String convKeyPrefix() {
        return "server:" + sanitizeAddr(serverAddress) + ":";
    }

    static String sanitizeAddr(String address) {
        return address == null ? "?" : address.replaceAll("[^A-Za-z0-9.:-]", "_");
    }

    private void requireConnected() {
        if (session == null || !session.isOpen()) {
            throw new Errors.Network("not connected to a server");
        }
    }

    private void requireLoggedIn() {
        requireConnected();
        if (loggedInUser == null) {
            throw new Errors.Denied("not logged in — use ${login(...)}");
        }
    }

    @Override
    public void close() {
        if (session != null) {
            session.close(); // the session handler calls onClosed
        } else {
            onClosed("closed locally");
        }
    }
}
