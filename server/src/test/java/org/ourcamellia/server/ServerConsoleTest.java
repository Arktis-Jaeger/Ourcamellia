package org.ourcamellia.server;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.ourcamellia.common.config.ServerConfig;
import org.ourcamellia.core.server.ServerCore;
import org.ourcamellia.core.server.ServerEvents;
import org.ourcamellia.core.server.ServerStateStore;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

/** Operator console: scripted commands render expected output and quit cleanly. */
class ServerConsoleTest {

    @Test
    void consoleCommands(@TempDir Path dir) throws Exception {
        ServerConfig config = ServerConfig.defaults();
        ServerStateStore store = new ServerStateStore(dir);
        ServerCore server = new ServerCore(config, store, new ServerEvents() {
            @Override
            public void onInfo(String line) {
            }

            @Override
            public void onAudit(String line) {
            }
        });
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ServerConsole console = new ServerConsole(server,
                new ByteArrayInputStream("""
                        ${policy}
                        ${stats}
                        ${groups}
                        ${announce("console test announcement")}
                        ${nope}
                        ${quit}
                        """.getBytes(StandardCharsets.UTF_8)),
                new PrintStream(out, true, StandardCharsets.UTF_8));
        console.run();
        String text = out.toString(StandardCharsets.UTF_8);
        assertTrue(text.contains("registration: auto"), text);
        assertTrue(text.contains("accounts: 0"), text);
        assertTrue(text.contains("announcement posted"), text);
        assertTrue(text.contains("unknown command"), text);
        assertTrue(console.quitRequested());
        // The announcement went through the operator path without a network listener.
        store.close();
        server.close();
    }
}
