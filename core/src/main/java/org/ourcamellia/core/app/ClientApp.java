package org.ourcamellia.core.app;

import org.ourcamellia.common.Errors;
import org.ourcamellia.common.Ids;
import org.ourcamellia.common.config.ClientConfig;
import org.ourcamellia.common.domain.ConversationRef;
import org.ourcamellia.common.domain.FriendState;
import org.ourcamellia.common.domain.Message;
import org.ourcamellia.common.domain.Notification;
import org.ourcamellia.common.domain.NotificationKind;
import org.ourcamellia.common.domain.NotificationState;
import org.ourcamellia.common.domain.PeerStatus;
import org.ourcamellia.common.domain.SessionMode;
import org.ourcamellia.core.persist.ClientStateStore;
import org.ourcamellia.core.persist.LocalHistoryStore;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * The client application facade — the single entry point used by the CLI modes, the
 * command set, and (future) GUIs. All business rules live here or below; the
 * presentation layers only render.
 */
public final class ClientApp implements AutoCloseable {

    private final ClientConfig config;
    private final ClientStateStore store;
    private final LocalHistoryStore history;
    private final Path dataDir;

    private LocalSession local;
    private ServerSession server;
    private SessionMode mode = SessionMode.NONE;
    private ConversationRef currentConversation;
    private final AtomicBoolean closed = new AtomicBoolean(false);
    private volatile boolean exitRequested = false;
    private volatile AppEvents events = null;

    /** Attaches the presentation event sink (once, before the run loop). */
    public void attachEvents(AppEvents events) {
        this.events = events;
    }

    public AppEvents events() {
        return events == null ? NOOP : events;
    }

    private static final AppEvents NOOP = new AppEvents() {
        @Override
        public void onMessage(ConversationRef conversation, Message message) {
        }

        @Override
        public void onStatusChanged() {
        }

        @Override
        public void onNotificationsChanged() {
        }

        @Override
        public void onInfo(String text) {
        }

        @Override
        public void onPeerStatus(String peerName, PeerStatus status) {
        }

        @Override
        public void onShutdown() {
        }
    };

    public ClientApp(ClientConfig config, ClientStateStore store, LocalHistoryStore history,
                     AppEvents events, Path dataDir) {
        this.config = config;
        this.store = store;
        this.history = history;
        this.events = events; // replaced by attachEvents() before the run loop
        this.dataDir = dataDir;
    }

    // ---------------- lifecycle ----------------

    public SessionMode mode() {
        return mode;
    }

    public boolean exitRequested() {
        return exitRequested;
    }

    public void requestExit() {
        this.exitRequested = true;
        events().onShutdown();
    }

    public ClientStateStore store() {
        return store;
    }

    public LocalHistoryStore history() {
        return history;
    }

    public LocalSession local() {
        return local;
    }

    public ServerSession server() {
        return server;
    }

    public Path dataDir() {
        return dataDir;
    }

    // ---------------- mode entry ----------------

    public void enterLocal(String name) {
        ensureMode(SessionMode.NONE, "already in " + modeLabel());
        local = new LocalSession(config, store, history, events(), dataDir);
        local.start(name);
        mode = SessionMode.LOCAL;
        events().onInfo("Local mode: you are '" + name + "' (identity fingerprint " + local.myFingerprint() + ")");
        events().onStatusChanged();
    }

    public void connectServer(String address) {
        ensureMode(SessionMode.NONE, "already in " + modeLabel());
        server = new ServerSession(config, store, history, events(), this);
        server.connect(address);
        mode = SessionMode.SERVER;
    }

    public void leaveMode() {
        if (mode == SessionMode.LOCAL && local != null) {
            local.close();
            local = null;
        }
        if (mode == SessionMode.SERVER && server != null) {
            server.close();
            server = null;
        }
        mode = SessionMode.NONE;
        currentConversation = null;
        events().onStatusChanged();
    }

    private void ensureMode(SessionMode expected, String message) {
        if (mode != expected) {
            throw new Errors.Usage(message);
        }
    }

    private String modeLabel() {
        return mode == SessionMode.LOCAL ? "Local mode" : mode == SessionMode.SERVER ? "Server mode" : "the mode menu";
    }

    // ---------------- conversation list (L2) ----------------

    /** Sorted conversation list for the current mode. */
    public List<ConversationRef> conversations() {
        List<ConversationRef> out = new ArrayList<>();
        if (mode == SessionMode.LOCAL && local != null) {
            for (String friend : local.friends()) {
                out.add(ConversationRef.privateChat(friend, false));
            }
            out.sort(Comparator.comparing(ConversationRef::title, SortUtil.SPEC_ORDER));
        } else if (mode == SessionMode.SERVER && server != null) {
            out.addAll(server.conversations());
        }
        return out;
    }

    public List<String> friends() {
        return mode == SessionMode.LOCAL && local != null
                ? local.friends()
                : mode == SessionMode.SERVER && server != null ? server.friends() : List.of();
    }

    public ConversationRef currentConversation() {
        return currentConversation;
    }

    /** Opens a conversation (from the list). */
    public void openConversation(ConversationRef ref) {
        if (mode == SessionMode.NONE) {
            throw new Errors.Usage("no mode active");
        }
        currentConversation = ref;
        events().onStatusChanged();
    }

    public void closeConversation() {
        currentConversation = null;
        events().onStatusChanged();
    }

    // ---------------- messaging ----------------

    /** Default `say`: sends text in the current conversation. */
    public void say(String text) {
        if (mode == SessionMode.LOCAL && local != null) {
            if (currentConversation == null) {
                throw new Errors.Usage("no conversation selected — open one from the list");
            }
            if (currentConversation.kind() != ConversationRef.Kind.PRIVATE) {
                throw new Errors.Usage("local groups: use ${group-send(...)}");
            }
            local.sendMessage(currentConversation.id(), text);
        } else if (mode == SessionMode.SERVER && server != null) {
            server.sayIn(currentConversation, text);
        } else {
            throw new Errors.Usage("no mode active");
        }
    }

    // ---------------- friendship ----------------

    public boolean sendFriendRequest(String name) {
        if (mode == SessionMode.LOCAL && local != null) {
            return local.sendFriendRequest(name);
        }
        if (mode == SessionMode.SERVER && server != null) {
            return server.sendFriendRequest(name);
        }
        throw new Errors.Usage("no mode active");
    }

    public FriendState friendState(String name) {
        if (mode == SessionMode.LOCAL && local != null) {
            return local.friendState(name);
        }
        if (mode == SessionMode.SERVER && server != null) {
            return server.friendState(name);
        }
        return FriendState.NONE;
    }

    public PeerStatus peerStatus(String name) {
        if (mode == SessionMode.LOCAL && local != null) {
            return local.peerStatus(name);
        }
        if (mode == SessionMode.SERVER && server != null) {
            return server.peerStatus(name);
        }
        return PeerStatus.UNCONFIRMED;
    }

    // ---------------- notifications ----------------

    /** Active notifications (UNREAD/READ, not expired), newest first. */
    public List<Notification> notifications() {
        if (mode == SessionMode.SERVER && server != null) {
            return server.notificationList();
        }
        long now = System.currentTimeMillis();
        List<Notification> out = new ArrayList<>();
        for (ClientStateStore.NotifRec n : store.notificationSnapshot()) {
            if (n.expiresAt() > 0 && now > n.expiresAt()) {
                continue;
            }
            NotificationState state = NotificationState.valueOf(n.state());
            if (state == NotificationState.UNREAD || state == NotificationState.READ) {
                out.add(new Notification(n.id(), NotificationKind.valueOf(n.kind()), state, n.from(),
                        n.text(), n.createdAt(), n.expiresAt(), n.refId()));
            }
        }
        return out;
    }

    /** Applies a notification action. Returns a user-visible outcome line. */
    public String notifyAction(int index, String action) {
        List<Notification> list = notifications();
        if (index < 1 || index > list.size()) {
            throw new Errors.Validation("notification " + index + " does not exist");
        }
        Notification n = list.get(index - 1);
        return switch (action) {
            case "over" -> {
                if (mode == SessionMode.SERVER && server != null) {
                    server.notifyAction(n, "over");
                } else {
                    store.updateNotification(n.id(), NotificationState.DISMISSED.name());
                }
                events().onNotificationsChanged();
                yield "notification marked reviewed and removed from the active list";
            }
            case "pass", "reject" -> actOnNotification(n, action);
            default -> throw new Errors.Usage("unknown notification action: " + action);
        };
    }

    private String actOnNotification(Notification n, String action) {
        if (n.kind() != NotificationKind.FRIEND_REQUEST) {
            if (mode == SessionMode.SERVER && server != null) {
                server.notifyAction(n, "over");
            } else {
                store.updateNotification(n.id(), NotificationState.DISMISSED.name());
            }
            events().onNotificationsChanged();
            return "notification dismissed (no action applies)";
        }
        String from = n.from();
        try {
            if (action.equals("pass")) {
                if (mode == SessionMode.LOCAL && local != null) {
                    local.acceptFriendRequest(from, n.refId());
                } else if (mode == SessionMode.SERVER && server != null) {
                    server.acceptFriendRequest(from, n.refId());
                } else {
                    throw new Errors.Usage("no mode active — friend request cannot be acted on");
                }
            } else {
                if (mode == SessionMode.LOCAL && local != null) {
                    local.rejectFriendRequest(from, n.refId());
                } else if (mode == SessionMode.SERVER && server != null) {
                    server.rejectFriendRequest(from, n.refId());
                } else {
                    throw new Errors.Usage("no mode active");
                }
            }
            if (mode != SessionMode.SERVER) {
                store.updateNotification(n.id(), NotificationState.ACTED.name());
            }
            events().onNotificationsChanged();
            return "friend request " + (action.equals("pass") ? "accepted" : "rejected");
        } catch (Errors.OcException e) {
            return "could not " + (action.equals("pass") ? "accept" : "reject") + ": " + e.getMessage();
        }
    }

    // ---------------- recording / history ----------------

    public boolean recording(String convKey) {
        return history.recording(convKey);
    }

    public void setRecording(String convKey, String title, boolean on) {
        history.setRecording(convKey, title, on);
        events().onStatusChanged();
    }

    public boolean hasBuffered(String convKey) {
        return history.hasBuffered(convKey);
    }

    public int persist(String convKey) {
        int n = history.persist(convKey);
        events().onStatusChanged();
        return n;
    }

    /** History deletion with the approved three scopes (P2). */
    public int deleteHistory(String scope, String arg) {
        return switch (scope) {
            case "current" -> {
                if (currentConversation == null) {
                    throw new Errors.Usage("no conversation selected");
                }
                String key = currentKey();
                history.deleteConversation(key);
                yield 1;
            }
            case "peer" -> {
                if (arg == null) {
                    throw new Errors.Usage("history-delete(peer, name) requires a peer name");
                }
                org.ourcamellia.common.Text.requireCleanText(arg, "peer name", 65);
                yield history.deleteMatching(peerScopePredicate(arg));
            }
            case "all" -> history.deleteAll();
            default -> throw new Errors.Usage("unknown deletion scope: " + scope + " (current|peer|all)");
        };
    }

    private String currentKey() {
        if (currentConversation == null) {
            throw new Errors.Usage("no conversation selected");
        }
        if (mode == SessionMode.LOCAL) {
            return "local:" + currentConversation.id();
        }
        return server == null ? null : server.convKey(currentConversation);
    }

    private java.util.function.Predicate<String> peerScopePredicate(String peerName) {
        if (mode == SessionMode.LOCAL) {
            return key -> key.equals("local:" + peerName);
        }
        String serverPrefix = server == null ? "server:" : server.convKeyPrefix();
        return key -> key.startsWith(serverPrefix + "priv:")
                && key.endsWith(":" + peerName);
    }

    // ---------------- local settings ----------------

    public void setDiscoverable(boolean on) {
        if (local == null) {
            throw new Errors.Usage("Local mode is not active");
        }
        local.setDiscoverable(on);
        events().onStatusChanged();
    }

    public void setConnectable(boolean on) {
        if (local == null) {
            throw new Errors.Usage("Local mode is not active");
        }
        local.setConnectable(on);
        events().onStatusChanged();
    }

    public boolean discoverable() {
        return local != null && local.discoverable();
    }

    public boolean connectable() {
        return local != null && local.connectable();
    }

    // ---------------- shutdown ----------------

    @Override
    public void close() {
        if (closed.getAndSet(true)) {
            return;
        }
        if (local != null) {
            local.close();
        }
        if (server != null) {
            server.close();
        }
        store.save();
    }
}
