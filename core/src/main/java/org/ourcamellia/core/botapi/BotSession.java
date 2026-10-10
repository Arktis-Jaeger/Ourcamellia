package org.ourcamellia.core.botapi;

import org.ourcamellia.common.Errors;
import org.ourcamellia.common.Ids;
import org.ourcamellia.common.Text;
import org.ourcamellia.common.protocol.Envelope;
import org.ourcamellia.common.protocol.Wire;
import org.ourcamellia.core.crypto.GroupCrypto;
import org.ourcamellia.core.security.RateLimiter;
import org.ourcamellia.core.server.ServerCore;
import org.ourcamellia.core.transport.Conn;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * In-process programmatic API for BOT participants (REQUIREMENTS §5.4,
 * ARCHITECTURE.md §3). A BOT authenticates with a token (issued by the server
 * operator, stored only as a SHA-256 digest) plus the X25519 private key issued with
 * it (needed to decrypt encrypted-group content). The BOT acts as its own marked
 * account — it is a participant type, not a privilege level: no administrative
 * operations exist in this API at all.
 *
 * This is the primary stable API for external programs; the optional localhost HTTP
 * adapter (BotHttpServer) is a thin wrapper over the same operations.
 */
public final class BotSession implements AutoCloseable, Conn {

    public static final long EVENT_POLL_TIMEOUT_MS = 60_000;

    private final ServerCore server;
    private final String botName;
    private final String tokenHash;
    private final RateLimiter rateLimiter;
    private final AtomicBoolean open = new AtomicBoolean(true);
    private final ConcurrentLinkedQueue<Envelope> inbox = new ConcurrentLinkedQueue<>();
    private final Object sendLock = new Object();
    private final java.security.PrivateKey x25519PrivateKey;
    private final ConcurrentHashMap<String, GroupState> groups = new ConcurrentHashMap<>();

    /** Encrypted-group key state for this bot. */
    public static final class GroupState {
        public volatile String id;
        public volatile String name;
        public volatile String privacy;
        public volatile byte[] groupKey;
        public volatile long generation = 1;
    }

    public BotSession(ServerCore server, String botName, String tokenHash, int rateLimitPerMinute,
                      PrivateKey x25519PrivateKey) {
        this.server = server;
        this.botName = botName;
        this.tokenHash = tokenHash;
        this.rateLimiter = new RateLimiter(rateLimitPerMinute);
        this.x25519PrivateKey = x25519PrivateKey;
    }

    public String botName() {
        return botName;
    }

    // ---------------- operations (user-level only; never administrative) ----------------

    /** Sends a private message; friendship and membership are checked server-side. */
    public void sendPrivate(String to, String text) {
        requireOpen();
        rateLimit();
        Text.requireCleanText(text, "message", Text.MAX_MESSAGE);
        server.botDispatch(this, Wire.message(Ids.newId(), botName, to, text));
    }

    /** Sends a group message; encrypted groups are encrypted with the group key. */
    public void sendGroup(String groupId, String text) {
        requireOpen();
        rateLimit();
        Text.requireCleanText(text, "message", Text.MAX_MESSAGE);
        GroupState g = groups.get(groupId);
        String box = null;
        if (g != null && "encrypted".equals(g.privacy)) {
            if (g.groupKey == null) {
                throw new Errors.Denied("group key not available for encrypted group");
            }
            box = GroupCrypto.encryptMessage(g.groupKey, groupId,
                    text.getBytes(StandardCharsets.UTF_8));
            text = null;
        }
        server.botDispatch(this, Wire.groupMessage(Ids.newId(), groupId, botName, text, box));
    }

    /** Sends a friend request (the BOT account's friendship is managed like any user's). */
    public void sendFriendRequest(String to) {
        requireOpen();
        rateLimit();
        server.botDispatch(this, Wire.friendRequest(Ids.newId(), botName, to));
    }

    /** Polls for the next user-visible event envelope (message, notification...). */
    public Envelope nextEvent(long timeoutMs) {
        requireOpen();
        long deadline = System.currentTimeMillis() + timeoutMs;
        while (System.currentTimeMillis() < deadline) {
            Envelope e = inbox.poll();
            if (e == null) {
                try {
                    Thread.sleep(20);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    return null;
                }
                continue;
            }
            if (absorbInternal(e)) {
                continue;
            }
            return e;
        }
        return null;
    }

    /** Drains all currently queued user-visible events. */
    public List<Envelope> drainEvents() {
        List<Envelope> out = new java.util.ArrayList<>();
        for (Envelope e : inbox) {
            if (!absorbInternal(e)) {
                out.add(e);
            }
        }
        return out;
    }

    /** Internal bookkeeping frames (group metadata, key wraps) update state and are hidden. */
    private boolean absorbInternal(Envelope e) {
        try {
            switch (e.type()) {
                case Wire.T_GROUP_UPDATE -> {
                    var u = Wire.parseGroupUpdate(e);
                    onGroupUpdate(u.group().id(), u.group().name(), u.group().privacy(),
                            u.group().members());
                    return true;
                }
                case Wire.T_GROUP_KEY_WRAP -> {
                    var w = Wire.parseGroupKeyWrap(e);
                    if (botName.equals(w.forUser())) {
                        onGroupKeyWrap(w.groupId(), w.generation(), w.box(), w.fromPub());
                    }
                    return true;
                }
                case Wire.T_ACK, Wire.T_NOTIFY_STATE -> {
                    // Operational confirmations are implicit in the API surface.
                    return true;
                }
                default -> {
                    return false;
                }
            }
        } catch (Errors.OcException malformed) {
            return true; // hostile frame to a bot is dropped, never exposed
        }
    }

    // ---------------- Conn implementation (outbound frames route to the inbox) ----------------

    @Override
    public void send(Envelope envelope) {
        // Called by the server to deliver replies/acks/errors to this bot.
        if (open.get()) {
            inbox.add(envelope);
        }
    }

    @Override
    public boolean isOpen() {
        return open.get();
    }

    @Override
    public String remoteDescription() {
        return "bot:" + botName;
    }

    @Override
    public String remoteFingerprint() {
        return null;
    }

    @Override
    public void close() {
        if (open.getAndSet(false)) {
            server.closeBotSession(botName);
        }
    }

    // ---------------- server-driven updates ----------------

    void onGroupUpdate(String id, String name, String privacy, List<String> members) {
        boolean isMember = members.contains(botName);
        GroupState g = groups.computeIfAbsent(id, k -> new GroupState());
        g.id = id;
        g.name = name;
        g.privacy = privacy;
        if (!isMember) {
            groups.remove(id);
        }
    }

    void onGroupKeyWrap(String groupId, long generation, String box, String fromPub) {
        GroupState g = groups.get(groupId);
        if (g == null || x25519PrivateKey == null) {
            return;
        }
        try {
            byte[] senderPub = Base64.getDecoder().decode(fromPub);
            byte[] key = GroupCrypto.unwrapGroupKey(x25519PrivateKey, senderPub, groupId,
                    generation, box);
            if (key != null) {
                g.groupKey = key;
                g.generation = generation;
            }
        } catch (IllegalArgumentException ignored) {
        }
    }

    private void rateLimit() {
        if (!rateLimiter.tryAcquire(tokenHash)) {
            throw new Errors.RateLimited("bot rate limit exceeded; wait a minute");
        }
    }

    private void requireOpen() {
        if (!open.get()) {
            throw new Errors.Network("bot session closed");
        }
    }
}
