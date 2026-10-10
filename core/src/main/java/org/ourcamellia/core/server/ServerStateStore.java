package org.ourcamellia.core.server;

import com.fasterxml.jackson.databind.JsonNode;
import org.ourcamellia.common.Errors;
import org.ourcamellia.common.Ids;
import org.ourcamellia.common.Json;
import org.ourcamellia.core.persist.AtomicFiles;

import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Server-side persistence (ARCHITECTURE.md §6): one structural JSON snapshot written
 * atomically (temp + fsync + rename) — accounts, friendships, groups, notifications,
 * registrations, bot tokens, admin set — plus a bounded operator review log for
 * operator-visible group content. A file lock prevents two server processes from
 * sharing one data directory. Corruption of the structural snapshot quarantines the
 * file and refuses to start (never silently discards recoverable data); the review
 * log is independently recoverable.
 */
public final class ServerStateStore {

    public static final String STATE_FILE = "server-state.json";
    public static final String REVIEW_FILE = "group-review.json";
    public static final int SCHEMA = 1;

    /** Server-side account record. Passwords stored only as PBKDF2 hashes. */
    public static final class Account {
        public String name;
        public String passwordHash;
        public String status = "active";        // active | pending
        public boolean bot = false;
        public long createdAt;
        public Map<String, String> fields = new LinkedHashMap<>(); // email + custom
        public List<String> friends = new ArrayList<>();
        public String x25519PublicKey;          // base64 raw 32 bytes (encrypted groups)
    }

    /** A pending friend request (server-side). */
    public static final class FriendRequest {
        public String id;
        public String from;
        public String to;
        public long ts;
    }

    /** Group record; wrappedKeys only for encrypted groups. */
    public static final class Group {
        public String id;
        public String name;
        public String privacy;                  // operator-visible | encrypted
        public String owner;
        public List<String> members = new ArrayList<>();
        public long createdAt;
        public Map<String, KeyWrap> wrappedKeys = new LinkedHashMap<>();
        public long generation = 1;
    }

    public static final class KeyWrap {
        public String box;
        public long generation;
    }

    /** Server-side notification (per user). */
    public static final class Notif {
        public String id;
        public String kind;                     // friend-request | announcement | info
        public String state = "unread";         // unread | read | acted | dismissed | expired
        public String from;
        public String text;
        public long createdAt;
        public long expiresAt;                  // 0 = never
        public String refId;
    }

    /** Pending registration ticket. */
    public static final class Registration {
        public String ticketId;
        public String username;
        public String passwordHash;
        public Map<String, String> fields = new LinkedHashMap<>();
        public long createdAt;
        public long expiresAt;
        public String policy;                   // manual | external
        public String verifierState = "none";   // none | sent | approved | rejected
        public String x25519PublicKey;
    }

    /** BOT API token (stored as SHA-256 digest only). */
    public static final class BotToken {
        public String tokenHash;
        public String owner;                    // @name of controlling account
        public String botName;                  // @name of the bot account
        public long createdAt;
        public int rateLimitPerMinute = 120;
    }

    public record ReviewEntry(String groupId, String groupName, String msgId, String sender,
                              String text, long ts) {}

    public static final class State {
        public int v = SCHEMA;
        public String serverName;
        public String channelId = Ids.newId();
        public LinkedHashMap<String, Account> accounts = new LinkedHashMap<>();
        public LinkedHashMap<String, FriendRequest> friendRequests = new LinkedHashMap<>();
        public LinkedHashMap<String, Group> groups = new LinkedHashMap<>();
        public LinkedHashMap<String, List<Notif>> notifications = new LinkedHashMap<>();
        public LinkedHashMap<String, Registration> registrations = new LinkedHashMap<>();
        public LinkedHashMap<String, BotToken> botTokens = new LinkedHashMap<>();
        public List<String> admins = new ArrayList<>();
    }

    private final Path dir;
    private final Path stateFile;
    private final Path reviewFile;
    private final FileChannel lockChannel;
    private final FileLock lock;
    private State state = new State();
    private final List<ReviewEntry> review = new ArrayList<>();

    public ServerStateStore(Path dataDir) {
        this.dir = dataDir;
        this.stateFile = dataDir.resolve(STATE_FILE);
        this.reviewFile = dataDir.resolve(REVIEW_FILE);
        try {
            java.nio.file.Files.createDirectories(dataDir);
            this.lockChannel = FileChannel.open(dataDir.resolve("data.lock"),
                    StandardOpenOption.CREATE, StandardOpenOption.WRITE);
            this.lock = lockChannel.tryLock();
            if (lock == null) {
                throw new Errors.Conflict("data directory is locked by another server process: " + dataDir);
            }
        } catch (java.io.IOException e) {
            throw new Errors.Persistence("cannot lock data directory " + dataDir, e);
        }
    }

    public synchronized void load(String defaultServerName) {
        byte[] raw = AtomicFiles.readOrNull(stateFile);
        if (raw != null) {
            try {
                JsonNode root = Json.parse(raw);
                long v = Json.reqLong(root, "v");
                if (v != SCHEMA) {
                    throw new Errors.Persistence("unsupported server state schema version " + v);
                }
                State s = Json.convert(root, State.class);
                if (s.accounts == null) s.accounts = new LinkedHashMap<>();
                if (s.friendRequests == null) s.friendRequests = new LinkedHashMap<>();
                if (s.groups == null) s.groups = new LinkedHashMap<>();
                if (s.notifications == null) s.notifications = new LinkedHashMap<>();
                if (s.registrations == null) s.registrations = new LinkedHashMap<>();
                if (s.botTokens == null) s.botTokens = new LinkedHashMap<>();
                if (s.admins == null) s.admins = new ArrayList<>();
                this.state = s;
            } catch (RuntimeException e) {
                AtomicFiles.quarantine(stateFile, "corrupt server state");
                throw new Errors.Persistence(
                        "server state file is corrupt and was quarantined; refusing to start "
                                + "rather than discard account data", e);
            }
        }
        if (state.serverName == null) {
            state.serverName = defaultServerName;
        }
        if (state.channelId == null) {
            state.channelId = Ids.newId();
        }
        byte[] reviewRaw = AtomicFiles.readOrNull(reviewFile);
        if (reviewRaw != null) {
            try {
                JsonNode root = Json.parse(reviewRaw);
                if ((int) Json.reqLong(root, "v") != SCHEMA) {
                    throw new Errors.Persistence("unsupported review log schema");
                }
                JsonNode entries = root.get("entries");
                if (entries != null && entries.isArray()) {
                    for (JsonNode e : entries) {
                        review.add(Json.convert(e, ReviewEntry.class));
                    }
                }
            } catch (RuntimeException e) {
                AtomicFiles.quarantine(reviewFile, "corrupt review log");
                review.clear(); // review log loss is acceptable and logged
            }
        }
    }

    public synchronized void save() {
        AtomicFiles.writeString(stateFile, Json.write(state));
    }

    public synchronized void appendReview(ReviewEntry entry, int retention) {
        review.add(entry);
        while (review.size() > retention) {
            review.remove(0);
        }
        var root = Json.object();
        root.put("v", SCHEMA);
        var arr = root.putArray("entries");
        for (ReviewEntry e : review) {
            arr.addPOJO(e);
        }
        AtomicFiles.writeString(reviewFile, Json.write(root));
    }

    public synchronized List<ReviewEntry> review(String groupId, int limit) {
        return review.stream()
                .filter(e -> e.groupId().equals(groupId))
                .skip(Math.max(0, review.stream().filter(e -> e.groupId().equals(groupId)).count() - limit))
                .toList();
    }

    public synchronized void removeReview(String groupId, String msgId) {
        review.removeIf(e -> e.groupId().equals(groupId) && e.msgId().equals(msgId));
        var root = Json.object();
        root.put("v", SCHEMA);
        var arr = root.putArray("entries");
        for (ReviewEntry e : review) {
            arr.addPOJO(e);
        }
        AtomicFiles.writeString(reviewFile, Json.write(root));
    }

    public synchronized State state() {
        return state;
    }

    public synchronized void close() {
        try {
            if (lock != null && lock.isValid()) {
                lock.release();
            }
            lockChannel.close();
        } catch (java.io.IOException ignored) {
        }
    }
}
