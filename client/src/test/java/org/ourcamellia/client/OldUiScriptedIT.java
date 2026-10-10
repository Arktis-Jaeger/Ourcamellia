package org.ourcamellia.client;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.ourcamellia.common.config.ClientConfig;
import org.ourcamellia.core.app.ClientApp;
import org.ourcamellia.core.app.ClientAppFactory;
import org.ourcamellia.core.persist.ClientStateStore;
import org.ourcamellia.core.persist.LocalHistoryStore;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Old-mode presentation tests: scripted (non-interactive) input drives the same
 * application core as Observatory; malformed commands are refused, notification
 * shortcuts work, and the exit-prompt policy reports buffered-content loss instead
 * of prompting when stdin is not interactive.
 */
class OldUiScriptedIT {

    private ClientApp makeApp(Path dir) {
        ClientConfig config = new ClientConfig("old", dir.toString(), true, false, false,
                "127.0.0.1", 56010, 56011, 60, 5000, 30_000, 2000,
                1 << 20, false, 12_000, true, "off");
        ClientStateStore store = new ClientStateStore(dir);
        LocalHistoryStore history = new LocalHistoryStore(dir.resolve("history"), true, null, 12_000);
        return ClientAppFactory.create(config, store, history, dir);
    }

    private String runScript(Path dir, String script) {
        ClientApp app = makeApp(dir);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        OldUi ui = new OldUi(app, new ByteArrayInputStream(script.getBytes(StandardCharsets.UTF_8)),
                new PrintStream(out, true, StandardCharsets.UTF_8));
        ui.run();
        return out.toString(StandardCharsets.UTF_8);
    }

    @Test
    void localModeStatusAndCleanExit(@TempDir Path dir) {
        String out = runScript(dir, """
                ${mode("local", "alice")}
                ${status}
                ${help}
                ${quit}
                """);
        assertTrue(out.contains("Local mode: you are 'alice'"), out);
        assertTrue(out.contains("mode: local"), out);
        assertTrue(out.contains("commands"), out);
        assertTrue(out.contains("Ourcamellia client"), out);
    }

    @Test
    void malformedCommandIsRefusedAndNothingIsSent(@TempDir Path dir) {
        String out = runScript(dir, """
                ${mode("local", "alice")}
                ${inf
                ${say("${info}")}
                ${quit}
                """);
        assertTrue(out.contains("malformed command"), out);
        assertTrue(out.contains("nothing was sent or executed"), out);
    }

    @Test
    void escapedLiteralDollarBraceInMessages(@TempDir Path dir) {
        // Without a conversation, say errors — but the escape processing happens first:
        // the payload reaching the app layer is the literal text (verified via the
        // error message context).
        String out = runScript(dir, """
                ${mode("local", "alice")}
                \\${not a command}
                ${quit}
                """);
        // "\${not a command}" is a plain message (not executed as a command); saying
        // it without a conversation yields the standard "no conversation" error, which
        // proves it was treated as a message, not a command.
        assertTrue(out.contains("no conversation selected"), out);
    }

    @Test
    void notificationShortcutAfterInfo(@TempDir Path dir) {
        String out = runScript(dir, """
                ${mode("local", "alice")}
                ${info}
                ${quit}
                """);
        assertTrue(out.contains("no active notifications"), out);
    }

    @Test
    void exitPromptPolicyNonInteractiveReportsLoss(@TempDir Path dir) {
        // Create buffered content: recording off + a message recorded while off.
        ClientApp app = makeApp(dir);
        app.enterLocal("alice");
        app.history().setRecording("local:bob", "bob", false);
        app.history().onMessage("local:bob", "bob", new LocalHistoryStore.Entry(
                org.ourcamellia.common.Ids.newId(), "alice", "unsaved", System.currentTimeMillis(), "out"));
        app.openConversation(org.ourcamellia.common.domain.ConversationRef.privateChat("bob", false));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        OldUi ui = new OldUi(app, new ByteArrayInputStream("${quit}\n".getBytes(StandardCharsets.UTF_8)),
                new PrintStream(out, true, StandardCharsets.UTF_8));
        ui.run();
        String text = out.toString(StandardCharsets.UTF_8);
        assertTrue(text.contains("unpersisted buffered messages will be lost"), text);
        assertFalse(text.contains("Persist them before exiting? (y/n/c)"), text);
        assertTrue(app.exitRequested());
    }
}
