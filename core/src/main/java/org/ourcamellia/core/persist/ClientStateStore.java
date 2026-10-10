package org.ourcamellia.core.persist;

import com.fasterxml.jackson.databind.JsonNode;
import org.ourcamellia.common.Errors;
import org.ourcamellia.common.Json;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;

/**
 * Client-side durable state (config-independent generated state): local identity,
 * friendships, TOFU certificate pins, local notifications, local groups, server
 * aliases. Persisted as one JSON file with atomic replacement and schema versioning;
 * on corruption the file is quarantined and the client starts with empty state
 * (documented recovery behavior — never silently truncating a healthy file).
 */
public final class ClientStateStore {

    public static final String FILE_NAME = "state.json";
    public static final int SCHEMA_VERSION = 1;

    /** Friendship record from the local observer's perspective. */
    public record FriendRec(String name, String state, String address, String fingerprint, long ts) {}

    /** Trust-on-first-use pin: cert fingerprint → names and addresses seen with it. */
    public record PinRec(String fingerprint, String name, List<String> addresses) {}

    public record NotifRec(String id, String kind, String state, String from, String text,
                           long createdAt, long expiresAt, String refId) {}

    public record GroupRec(String id, String name, String privacy, String owner,
                           List<String> members, long createdAt) {}

    private final Path file;
    private State state = new State();

    public static final class State {
        public int v = SCHEMA_VERSION;
        public String localName;
        public String localFingerprint;
        public String x25519PrivateKey; // base64 PKCS#8; used for encrypted-group key exchange
        public String x25519PublicKey;  // base64 raw 32 bytes
        public LinkedHashMap<String, FriendRec> friends = new LinkedHashMap<>();
        public LinkedHashMap<String, PinRec> pins = new LinkedHashMap<>();
        public List<NotifRec> notifications = new ArrayList<>();
        public List<GroupRec> groups = new ArrayList<>();
        public LinkedHashMap<String, String> aliases = new LinkedHashMap<>();
    }

    public ClientStateStore(Path dataDir) {
        this.file = dataDir.resolve(FILE_NAME);
        load();
    }

    public synchronized void load() {
        byte[] raw = AtomicFiles.readOrNull(file);
        if (raw == null) {
            return;
        }
        try {
            JsonNode root = Json.parse(raw);
            long v = Json.reqLong(root, "v");
            if (v != SCHEMA_VERSION) {
                throw new Errors.Persistence("unsupported state schema version " + v);
            }
            State s = Json.convert(root, State.class);
            if (s.friends == null) s.friends = new LinkedHashMap<>();
            if (s.pins == null) s.pins = new LinkedHashMap<>();
            if (s.notifications == null) s.notifications = new ArrayList<>();
            if (s.groups == null) s.groups = new ArrayList<>();
            if (s.aliases == null) s.aliases = new LinkedHashMap<>();
            this.state = s;
        } catch (RuntimeException e) {
            AtomicFiles.quarantine(file, "corrupt state");
            this.state = new State();
        }
    }

    public synchronized void save() {
        AtomicFiles.writeString(file, Json.write(state));
    }

    public synchronized State state() {
        return state;
    }

    // ---------- helpers ----------

    public synchronized FriendRec friend(String name) {
        return state.friends.get(name);
    }

    public synchronized void putFriend(FriendRec rec) {
        state.friends.put(rec.name(), rec);
        save();
    }

    public synchronized void removeFriend(String name) {
        if (state.friends.remove(name) != null) {
            save();
        }
    }

    public synchronized PinRec pin(String fingerprint) {
        return state.pins.get(fingerprint);
    }

    public synchronized void putPin(String fingerprint, String name, String address) {
        PinRec existing = state.pins.get(fingerprint);
        if (existing == null) {
            List<String> addrs = new ArrayList<>();
            if (address != null) addrs.add(address);
            state.pins.put(fingerprint, new PinRec(fingerprint, name, addrs));
        } else {
            List<String> addrs = new ArrayList<>(existing.addresses());
            if (address != null && !addrs.contains(address)) {
                addrs.add(address);
            }
            state.pins.put(fingerprint, new PinRec(fingerprint,
                    existing.name() != null ? existing.name() : name, addrs));
        }
        save();
    }

    public synchronized void addNotification(NotifRec n) {
        // dedup by stable id
        for (NotifRec e : state.notifications) {
            if (e.id().equals(n.id())) {
                return;
            }
        }
        state.notifications.add(0, n);
        save();
    }

    public synchronized boolean updateNotification(String id, String newState) {
        for (int i = 0; i < state.notifications.size(); i++) {
            NotifRec n = state.notifications.get(i);
            if (n.id().equals(id)) {
                state.notifications.set(i, new NotifRec(n.id(), n.kind(), newState, n.from(),
                        n.text(), n.createdAt(), n.expiresAt(), n.refId()));
                save();
                return true;
            }
        }
        return false;
    }

    public synchronized void purgeExpiredNotifications(long now) {
        boolean changed = state.notifications.removeIf(n -> n.expiresAt() > 0 && now > n.expiresAt());
        if (changed) {
            save();
        }
    }

    /** Thread-safe snapshot for readers outside this class. */
    public synchronized List<NotifRec> notificationSnapshot() {
        return List.copyOf(state.notifications);
    }

    public synchronized GroupRec group(String id) {
        return state.groups.stream().filter(g -> g.id().equals(id)).findFirst().orElse(null);
    }

    public synchronized void putGroup(GroupRec rec) {
        state.groups.removeIf(g -> g.id().equals(rec.id()));
        state.groups.add(rec);
        save();
    }

    public synchronized void removeGroup(String id) {
        if (state.groups.removeIf(g -> g.id().equals(id))) {
            save();
        }
    }

    public synchronized String alias(String serverAddr) {
        return state.aliases.get(serverAddr);
    }

    public synchronized void putAlias(String serverAddr, String alias) {
        if (alias == null || alias.isBlank()) {
            state.aliases.remove(serverAddr);
        } else {
            state.aliases.put(serverAddr, alias);
        }
        save();
    }

    public synchronized void setLocalIdentity(String name, String fingerprint) {
        state.localName = name;
        state.localFingerprint = fingerprint;
        save();
    }

    /** Returns the client's X25519 keypair, creating and persisting it on first use. */
    public synchronized java.security.KeyPair x25519KeyPair() {
        try {
            if (state.x25519PrivateKey != null && state.x25519PublicKey != null) {
                byte[] pkcs8 = java.util.Base64.getDecoder().decode(state.x25519PrivateKey);
                byte[] rawPub = java.util.Base64.getDecoder().decode(state.x25519PublicKey);
                var priv = java.security.KeyFactory.getInstance("X25519").generatePrivate(
                        new java.security.spec.PKCS8EncodedKeySpec(pkcs8));
                var pub = org.ourcamellia.core.crypto.GroupCrypto.publicKeyFrom(rawPub);
                return new java.security.KeyPair(pub, priv);
            }
            var kpg = java.security.KeyPairGenerator.getInstance("X25519");
            java.security.KeyPair kp = kpg.generateKeyPair();
            state.x25519PrivateKey = java.util.Base64.getEncoder()
                    .encodeToString(kp.getPrivate().getEncoded());
            state.x25519PublicKey = java.util.Base64.getEncoder()
                    .encodeToString(org.ourcamellia.core.crypto.GroupCrypto.publicKeyBytes(kp));
            save();
            return kp;
        } catch (java.security.GeneralSecurityException e) {
            throw new Errors.Internal("X25519 unavailable", e);
        }
    }
}
