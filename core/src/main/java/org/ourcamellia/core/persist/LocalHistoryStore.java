package org.ourcamellia.core.persist;

import com.fasterxml.jackson.databind.JsonNode;
import org.ourcamellia.common.AeadBox;
import org.ourcamellia.common.Errors;
import org.ourcamellia.common.Ids;
import org.ourcamellia.common.Json;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Local JSON conversation history (REQUIREMENTS §8).
 *
 * - One JSON file per conversation; atomic writes; schema-versioned.
 * - Recording per conversation (persisted with the file): ON → new messages are
 *   persisted immediately; OFF → new messages stay in process memory (buffered) and
 *   are NOT written to disk until an explicit {@link #persist} (or the exit prompt).
 * - Toggling recording never deletes saved history.
 * - Stable message IDs deduplicate across retries/restarts.
 * - Optional secondary-password protection (P4): the whole file is an AES-256-GCM
 *   sealed box derived via PBKDF2 from the secondary password; loss of the password
 *   makes the file unrecoverable (documented, no silent fallback).
 * - Corrupted files are quarantined (never silently discarded without a copy).
 */
public final class LocalHistoryStore {

    public static final int SCHEMA = 1;

    public record Entry(String id, String sender, String text, long ts, String direction) {}

    public static final class Conversation {
        public String key;
        public String title;
        public boolean recording;
        public List<Entry> persisted = new ArrayList<>();
        public final List<Entry> buffered = new ArrayList<>();
    }

    private final Path historyDir;
    private final boolean defaultRecording;
    private final String secondaryPassword;   // null = no protection
    private final int iterations;
    private final Map<String, Conversation> open = new LinkedHashMap<>();

    public LocalHistoryStore(Path historyDir, boolean defaultRecording,
                             String secondaryPassword, int iterations) {
        this.historyDir = historyDir;
        this.defaultRecording = defaultRecording;
        this.secondaryPassword = secondaryPassword;
        this.iterations = iterations;
        try {
            java.nio.file.Files.createDirectories(historyDir);
        } catch (java.io.IOException e) {
            throw new Errors.Persistence("cannot create history directory", e);
        }
    }

    /** Stable file name for a conversation key (base64url, no path traversal possible). */
    static String fileName(String key) {
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(key.getBytes(StandardCharsets.UTF_8)) + ".json";
    }

    public synchronized Conversation open(String key, String title) {
        Conversation existing = open.get(key);
        if (existing != null) {
            return existing;
        }
        Conversation c = new Conversation();
        c.key = key;
        c.title = title;
        c.recording = defaultRecording;
        loadInto(c);
        open.put(key, c);
        return c;
    }

    public synchronized Conversation conversation(String key) {
        return open.get(key);
    }

    public synchronized boolean isOpen(String key) {
        return open.containsKey(key);
    }

    /** Records a new message: auto-persists when recording, else buffers in memory. */
    public synchronized void onMessage(String key, String title, Entry entry) {
        Conversation c = open(key, title);
        if (contains(c, entry.id())) {
            return; // duplicate delivery
        }
        if (c.recording) {
            c.persisted.add(entry);
            save(c);
        } else {
            c.buffered.add(entry);
        }
    }

    private static boolean contains(Conversation c, String id) {
        return c.persisted.stream().anyMatch(e -> e.id().equals(id))
                || c.buffered.stream().anyMatch(e -> e.id().equals(id));
    }

    public synchronized List<Entry> messages(String key) {
        Conversation c = open.get(key);
        if (c == null) {
            c = open(key, key); // loads (and quarantines) the persisted file on demand
        }
        return List.copyOf(c.persisted);
    }

    public synchronized boolean recording(String key) {
        Conversation c = open.get(key);
        if (c == null) {
            c = open(key, key);
        }
        return c.recording;
    }

    /** Toggles automatic recording for one conversation. Never deletes history. */
    public synchronized void setRecording(String key, String title, boolean on) {
        Conversation c = open(key, title);
        if (c.recording != on) {
            c.recording = on;
            save(c);
        }
    }

    public synchronized boolean hasBuffered(String key) {
        Conversation c = open.get(key);
        if (c == null) {
            c = open(key, key);
        }
        return !c.buffered.isEmpty();
    }

    /** Explicit manual persistence: moves buffered entries into the file. */
    public synchronized int persist(String key) {
        Conversation c = open.get(key);
        if (c == null || c.buffered.isEmpty()) {
            return 0;
        }
        int n = c.buffered.size();
        c.persisted.addAll(c.buffered);
        c.buffered.clear();
        save(c);
        return n;
    }

    /** Deletes the saved history of one conversation (file + in-memory view). */
    public synchronized void deleteConversation(String key) {
        open.remove(key);
        try {
            java.nio.file.Files.deleteIfExists(historyDir.resolve(fileName(key)));
        } catch (java.io.IOException e) {
            throw new Errors.Persistence("cannot delete history file", e);
        }
    }

    /** Deletes every history file whose conversation key matches the given predicate. */
    public synchronized int deleteMatching(java.util.function.Predicate<String> matches) {
        int removed = 0;
        for (String key : new ArrayList<>(open.keySet())) {
            if (matches.test(key)) {
                open.remove(key);
                try {
                    if (java.nio.file.Files.deleteIfExists(historyDir.resolve(fileName(key)))) {
                        removed++;
                    }
                } catch (java.io.IOException e) {
                    throw new Errors.Persistence("cannot delete history file", e);
                }
            }
        }
        // For files not currently open, decode the file name and match by key.
        try (var stream = java.nio.file.Files.list(historyDir)) {
            for (Path f : stream.filter(p -> p.getFileName().toString().endsWith(".json")).toList()) {
                String base = f.getFileName().toString();
                String key = decodeKey(base.substring(0, base.length() - 5));
                if (key != null && matches.test(key)) {
                    try {
                        if (java.nio.file.Files.deleteIfExists(f)) {
                            removed++;
                        }
                    } catch (java.io.IOException e) {
                        throw new Errors.Persistence("cannot delete history file", e);
                    }
                }
            }
        } catch (java.io.IOException e) {
            throw new Errors.Persistence("cannot list history directory", e);
        }
        return removed;
    }

    public synchronized int deleteAll() {
        int removed = 0;
        open.clear();
        try (var stream = java.nio.file.Files.list(historyDir)) {
            for (Path f : stream.filter(p -> p.getFileName().toString().endsWith(".json")).toList()) {
                try {
                    if (java.nio.file.Files.deleteIfExists(f)) {
                        removed++;
                    }
                } catch (java.io.IOException e) {
                    throw new Errors.Persistence("cannot delete history file", e);
                }
            }
        } catch (java.io.IOException e) {
            throw new Errors.Persistence("cannot list history directory", e);
        }
        return removed;
    }

    // ---------- file format ----------

    private void loadInto(Conversation c) {
        Path file = historyDir.resolve(fileName(c.key));
        byte[] raw = AtomicFiles.readOrNull(file);
        if (raw == null) {
            return;
        }
        boolean decryptFailed = false;
        try {
            JsonNode root = Json.parse(raw);
            JsonNode messages;
            if (root.has("protected") && root.get("protected").asBoolean()) {
                if (secondaryPassword == null) {
                    decryptFailed = true;
                    throw new Errors.Persistence(
                            "history file is protected by a secondary password but none was provided");
                }
                byte[] salt = Base64.getDecoder().decode(Json.reqStr(root, "salt", 256));
                int iter = (int) Json.reqLong(root, "iterations");
                byte[] box = Base64.getDecoder().decode(Json.reqStr(root, "box", 64 * 1024 * 1024));
                byte[] key = AeadBox.deriveKey(secondaryPassword, salt, iter);
                byte[] inner = AeadBox.open(key, AeadBox.aadFor("ourcamellia-history", fileName(c.key)), box);
                if (inner == null) {
                    decryptFailed = true;
                    throw new Errors.Persistence(
                            "history file could not be decrypted (wrong secondary password?); file left untouched");
                }
                root = Json.parse(inner);
            }
            if ((int) Json.reqLong(root, "v") != SCHEMA) {
                throw new Errors.Persistence("unsupported history schema");
            }
            c.recording = Json.optBool(root, "recording", defaultRecording);
            String storedTitle = Json.optStr(root, "title", 256);
            if (storedTitle != null) {
                c.title = storedTitle;
            }
            messages = root.get("messages");
            if (messages != null) {
                if (!messages.isArray() || messages.size() > 100_000) {
                    throw new Errors.Persistence("invalid history messages array");
                }
                for (JsonNode m : messages) {
                    c.persisted.add(new Entry(
                            Ids.requireId(Json.reqStr(m, "id", 64), "message id"),
                            Json.reqStr(m, "sender", 65),
                            Json.reqStr(m, "text", 1024 * 1024),
                            Json.reqLong(m, "ts"),
                            Json.optStr(m, "direction", 8)));
                }
            }
        } catch (Errors.OcException e) {
            if (decryptFailed) {
                // A failed decryption (wrong/missing password) is not corruption:
                // leave the file untouched so the user can retry with the right password.
                c.persisted.clear();
                return;
            }
            AtomicFiles.quarantine(file, "corrupt history: " + e.getMessage());
            c.persisted.clear();
        }
    }

    private void save(Conversation c) {
        var root = Json.object();
        root.put("v", SCHEMA);
        root.put("key", c.key);
        root.put("title", c.title);
        root.put("recording", c.recording);
        var arr = root.putArray("messages");
        for (Entry e : c.persisted) {
            var o = arr.addObject();
            o.put("id", e.id());
            o.put("sender", e.sender());
            o.put("text", e.text());
            o.put("ts", e.ts());
            o.put("direction", e.direction());
        }
        byte[] plain = Json.writeBytes(root);
        byte[] payload;
        if (secondaryPassword != null) {
            byte[] salt = org.ourcamellia.common.CryptoUtil.randomBytes(16);
            byte[] key = AeadBox.deriveKey(secondaryPassword, salt, iterations);
            byte[] box = AeadBox.seal(key, AeadBox.aadFor("ourcamellia-history", fileName(c.key)), plain);
            var sealed = Json.object();
            sealed.put("v", SCHEMA);
            sealed.put("protected", true);
            sealed.put("salt", Base64.getEncoder().encodeToString(salt));
            sealed.put("iterations", iterations);
            sealed.put("box", Base64.getEncoder().encodeToString(box));
            payload = Json.writeBytes(sealed);
        } else {
            payload = plain;
        }
        AtomicFiles.write(historyDir.resolve(fileName(c.key)), payload);
    }

    private static String decodeKey(String base64urlNoPadding) {
        try {
            String padded = base64urlNoPadding + "=".repeat((4 - base64urlNoPadding.length() % 4) % 4);
            return new String(Base64.getUrlDecoder().decode(padded), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}
