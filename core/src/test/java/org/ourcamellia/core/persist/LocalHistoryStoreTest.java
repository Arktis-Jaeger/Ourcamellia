package org.ourcamellia.core.persist;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.ourcamellia.core.app.ExitPolicy;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Stage 7 gate — local JSON history: recording ON/OFF semantics, buffering, manual
 * persistence, deletion scopes, dedup, corruption recovery, secondary-password
 * protection, and the exit-prompt policy.
 */
class LocalHistoryStoreTest {

    private static LocalHistoryStore.Entry entry(String text) {
        return new LocalHistoryStore.Entry(org.ourcamellia.common.Ids.newId(), "peer", text,
                System.currentTimeMillis(), "in");
    }

    @Test
    void recordingOnPersistsImmediately(@TempDir Path dir) throws Exception {
        LocalHistoryStore store = new LocalHistoryStore(dir.resolve("history"), true, null, 12_000);
        store.onMessage("local:bob", "bob", entry("one"));
        assertTrue(Files.exists(dir.resolve("history").resolve(LocalHistoryStore.fileName("local:bob"))));
        assertFalse(store.hasBuffered("local:bob"));
        assertEquals(1, store.messages("local:bob").size());
    }

    @Test
    void recordingOffBuffersWithoutWriting(@TempDir Path dir) throws Exception {
        LocalHistoryStore store = new LocalHistoryStore(dir.resolve("history"), true, null, 12_000);
        store.onMessage("local:bob", "bob", entry("persisted"));
        Path file = dir.resolve("history").resolve(LocalHistoryStore.fileName("local:bob"));
        assertTrue(Files.exists(file));

        store.setRecording("local:bob", "bob", false);
        store.onMessage("local:bob", "bob", entry("buffered-secret"));
        assertTrue(store.hasBuffered("local:bob"));
        // The buffered message must NOT reach the file.
        assertFalse(Files.readString(file).contains("buffered-secret"),
                "recording OFF must never silently write buffered content");
        assertEquals(1, store.messages("local:bob").size());

        // Manual persistence writes exactly the buffered content.
        int n = store.persist("local:bob");
        assertEquals(1, n);
        assertFalse(store.hasBuffered("local:bob"));
        assertEquals(2, store.messages("local:bob").size());
    }

    @Test
    void reenablingRecordingNeverDeletesHistory(@TempDir Path dir) {
        LocalHistoryStore store = new LocalHistoryStore(dir.resolve("history"), true, null, 12_000);
        store.onMessage("local:bob", "bob", entry("saved"));
        store.setRecording("local:bob", "bob", false);
        store.onMessage("local:bob", "bob", entry("buffered"));
        store.setRecording("local:bob", "bob", true);
        store.onMessage("local:bob", "bob", entry("resumed"));
        // Saved history intact, buffered content untouched by the toggle, new message persisted.
        assertEquals(2, store.messages("local:bob").size());
        assertTrue(store.messages("local:bob").stream().anyMatch(e -> e.text().equals("saved")));
        assertTrue(store.messages("local:bob").stream().anyMatch(e -> e.text().equals("resumed")));
        assertTrue(store.hasBuffered("local:bob"));
    }

    @Test
    void bufferedMessagesAreLostWithoutPersist(@TempDir Path dir) {
        LocalHistoryStore store = new LocalHistoryStore(dir.resolve("history"), true, null, 12_000);
        store.setRecording("local:bob", "bob", false);
        store.onMessage("local:bob", "bob", entry("ephemeral"));
        assertTrue(store.hasBuffered("local:bob"));
        // Simulate process end: a fresh store instance has no buffered content.
        LocalHistoryStore fresh = new LocalHistoryStore(dir.resolve("history"), true, null, 12_000);
        assertFalse(fresh.hasBuffered("local:bob"));
        assertTrue(fresh.messages("local:bob").isEmpty());
    }

    @Test
    void deletionScopes(@TempDir Path dir) throws Exception {
        LocalHistoryStore store = new LocalHistoryStore(dir.resolve("history"), true, null, 12_000);
        store.onMessage("local:bob", "bob", entry("b1"));
        store.onMessage("local:carol", "carol", entry("c1"));
        store.onMessage("local:carol", "carol", entry("c2"));
        assertEquals(2, Files.list(dir.resolve("history")).count());

        // Peer scope removes only that peer's files.
        int removed = store.deleteMatching(key -> key.equals("local:carol"));
        assertEquals(1, removed);
        assertEquals(1, store.messages("local:bob").size());

        // Current-conversation scope (via ClientApp path) removes one conversation.
        store.deleteConversation("local:bob");
        assertEquals(0, Files.list(dir.resolve("history")).count());

        // All scope clears everything (incl. unopened files).
        LocalHistoryStore store2 = new LocalHistoryStore(dir.resolve("history"), true, null, 12_000);
        store2.onMessage("local:x", "x", entry("x1"));
        assertEquals(1, store2.deleteAll());
        assertEquals(0, Files.list(dir.resolve("history")).count());
    }

    @Test
    void duplicateIdsAreDeduplicated(@TempDir Path dir) {
        LocalHistoryStore store = new LocalHistoryStore(dir.resolve("history"), true, null, 12_000);
        LocalHistoryStore.Entry e = entry("same");
        store.onMessage("local:bob", "bob", e);
        store.onMessage("local:bob", "bob", e); // retry/duplicate delivery
        assertEquals(1, store.messages("local:bob").size());
        assertEquals(1, store.open("local:bob", "bob").persisted.size());
    }

    @Test
    void corruptedFileIsQuarantinedAndRecovered(@TempDir Path dir) throws Exception {
        Path historyDir = dir.resolve("history");
        Files.createDirectories(historyDir);
        Path file = historyDir.resolve(LocalHistoryStore.fileName("local:bob"));
        Files.writeString(file, "{not valid json at all");

        LocalHistoryStore store = new LocalHistoryStore(historyDir, true, null, 12_000);
        assertTrue(store.messages("local:bob").isEmpty(), "corrupt file must not crash the store");
        // The corrupted file was moved aside, not silently deleted.
        try (var stream = Files.list(historyDir)) {
            List<Path> files = stream.toList();
            assertEquals(1, files.size());
            assertTrue(files.get(0).getFileName().toString().contains(".corrupt-"));
        }
    }

    @Test
    void secondaryPasswordSealsHistory(@TempDir Path dir) throws Exception {
        LocalHistoryStore store = new LocalHistoryStore(dir.resolve("history"), true, "hunter2", 12_000);
        store.onMessage("local:bob", "bob", entry("secret text"));
        Path file = dir.resolve("history").resolve(LocalHistoryStore.fileName("local:bob"));
        String raw = Files.readString(file);
        assertFalse(raw.contains("secret text"), "protected history must be encrypted at rest");
        assertTrue(raw.contains("\"protected\":true"));

        // Reopen with the right password: readable.
        LocalHistoryStore reopen = new LocalHistoryStore(dir.resolve("history"), true, "hunter2", 12_000);
        assertEquals("secret text", reopen.messages("local:bob").get(0).text());

        // Wrong password: decryption fails, file untouched.
        LocalHistoryStore wrong = new LocalHistoryStore(dir.resolve("history"), true, "wrong", 12_000);
        assertTrue(wrong.messages("local:bob").isEmpty());
        assertTrue(Files.exists(file), "wrong password must never touch the file");

        // No password + protected file: clear error, no silent plaintext fallback.
        LocalHistoryStore none = new LocalHistoryStore(dir.resolve("history"), true, null, 12_000);
        assertTrue(none.messages("local:bob").isEmpty());
        assertTrue(Files.exists(file));
    }

    @Test
    void historySurvivesRestart(@TempDir Path dir) {
        LocalHistoryStore store = new LocalHistoryStore(dir.resolve("history"), true, null, 12_000);
        store.onMessage("local:bob", "bob", entry("one"));
        store.setRecording("local:bob", "bob", false);
        LocalHistoryStore fresh = new LocalHistoryStore(dir.resolve("history"), true, null, 12_000);
        assertEquals("one", fresh.messages("local:bob").get(0).text());
        assertFalse(fresh.recording("local:bob"), "per-conversation recording choice must persist");
    }

    @Test
    void exitPolicyNarrowInterpretation() {
        assertFalse(ExitPolicy.decide(false, true).promptNeeded());
        assertFalse(ExitPolicy.decide(false, false).promptNeeded());
        assertTrue(ExitPolicy.decide(true, true).promptNeeded());
        assertFalse(ExitPolicy.decide(true, false).promptNeeded(),
                "non-interactive sessions must not prompt");
        assertNotNull(ExitPolicy.decide(true, false).message(),
                "non-interactive exit must report that buffered content is lost");
    }
}
