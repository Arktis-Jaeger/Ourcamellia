package org.ourcamellia.it;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Cross-process acceptance test: the real server and client executables (shaded
 * jars) are started independently, a scripted Old-mode client registers an account
 * (driven interactively so async server responses are awaited), and the server
 * state is verified on disk. Runs only when the shaded jars exist (i.e. under
 * `mvn package`).
 */
class ProcessIT {

    @Test
    void clientAndServerStartIndependently(@TempDir Path tmp) throws Exception {
        Path serverJar = Path.of("..", "server", "target", "ourcamellia-server.jar");
        Path clientJar = Path.of("..", "client", "target", "ourcamellia-client.jar");
        assumeTrue(Files.exists(serverJar) && Files.exists(clientJar),
                "shaded jars not built yet — run with `mvn package`");

        int port = 56000 + (int) (Math.random() * 200);
        Path srvData = tmp.resolve("srv");
        Files.createDirectories(srvData);
        Path serverConfig = tmp.resolve("server.json");
        Files.writeString(serverConfig, """
                {
                  "bindHost": "127.0.0.1",
                  "port": %d,
                  "serverName": "Process Test Server",
                  "dataDir": "%s",
                  "registrationPolicy": "auto",
                  "requireEmail": true,
                  "adminUsernames": ["@admin"],
                  "logLevel": "off"
                }
                """.formatted(port, srvData.toAbsolutePath()));

        Process server = new ProcessBuilder("java", "-jar", serverJar.toAbsolutePath().toString(),
                "run", "--config", serverConfig.toAbsolutePath().toString())
                .redirectErrorStream(true)
                .directory(tmp.toFile())
                .start();
        try {
            // Wait for the server to bind.
            long deadline = System.currentTimeMillis() + 20_000;
            boolean up = false;
            while (System.currentTimeMillis() < deadline) {
                try (var socket = new java.net.Socket("127.0.0.1", port)) {
                    up = true;
                    break;
                } catch (Exception e) {
                    Thread.sleep(100);
                }
            }
            assertTrue(up, "server process must bind its port");

            // Client 1: register @alice (auto policy → immediately logged in) and exit.
            Path clientData = tmp.resolve("alice-data");
            Path clientConfig = tmp.resolve("client.json");
            Files.writeString(clientConfig, """
                    {"mode":"old","dataDir":"%s","logLevel":"off","listenPort":%d,"discoveryPort":%d}
                    """.formatted(clientData.toAbsolutePath(), port + 1000, port + 1001));
            Process alice = new ProcessBuilder("java", "-jar", clientJar.toAbsolutePath().toString(),
                    "--config", clientConfig.toAbsolutePath().toString())
                    .directory(tmp.toFile())
                    .start();
            String aliceOut = drive(alice,
                    cmd("${mode(\"server\", \"127.0.0.1:%d\")}", port), "connected to server",
                    cmd("${register(\"@alice\", \"password1\", \"alice@example.com\")}"), "logged in as @alice",
                    cmd("${status}"), "mode: server",
                    cmd("${quit}"), null);
            assertTrue(alice.waitFor(20, TimeUnit.SECONDS), "client must exit by itself");
            assertEquals(0, alice.exitValue(), "clean exit expected, output:\n" + aliceOut);

            // Verify durable effects on disk: account exists, password hashed, no plaintext.
            String state = Files.readString(srvData.resolve("server-state.json"));
            assertTrue(state.contains("@alice"));
            assertFalse(state.contains("password1"));
            assertTrue(state.contains("pbkdf2-sha256"));
            assertFalse(state.contains("127.0.0.1"), "server state must not store client IPs");

            // Client 2: register @bob, friend-request @alice (offline → stored pending).
            Path bobData = tmp.resolve("bob-data");
            Path bobConfig = tmp.resolve("bob.json");
            Files.writeString(bobConfig, """
                    {"mode":"old","dataDir":"%s","logLevel":"off","listenPort":%d,"discoveryPort":%d}
                    """.formatted(bobData.toAbsolutePath(), port + 2000, port + 2001));
            Process bob = new ProcessBuilder("java", "-jar", clientJar.toAbsolutePath().toString(),
                    "--config", bobConfig.toAbsolutePath().toString())
                    .directory(tmp.toFile())
                    .start();
            drive(bob,
                    cmd("${mode(\"server\", \"127.0.0.1:%d\")}", port), "connected to server",
                    cmd("${register(\"@bob\", \"password1\", \"bob@example.com\")}"), "logged in as @bob",
                    cmd("${friend-request(@alice)}"), "friend request sent",
                    cmd("${quit}"), null);
            assertTrue(bob.waitFor(20, TimeUnit.SECONDS));
            assertEquals(0, bob.exitValue());
            String state2 = Files.readString(srvData.resolve("server-state.json"));
            assertTrue(state2.contains("@bob"));
            assertTrue(state2.contains("friendRequests"),
                    "pending friend request must be persisted");

            // Graceful shutdown via the console.
            server.getOutputStream().write("${quit}\n".getBytes());
            server.getOutputStream().flush();
            assertTrue(server.waitFor(15, TimeUnit.SECONDS), "server must shut down on ${quit}");
        } finally {
            server.destroyForcibly();
        }
    }

    @Test
    void helpExitsCleanly(@TempDir Path tmp) throws Exception {
        Path serverJar = Path.of("..", "server", "target", "ourcamellia-server.jar");
        Path clientJar = Path.of("..", "client", "target", "ourcamellia-client.jar");
        assumeTrue(Files.exists(serverJar) && Files.exists(clientJar),
                "shaded jars not built yet — run with `mvn package`");
        for (Path jar : new Path[]{serverJar, clientJar}) {
            Process p = new ProcessBuilder("java", "-jar", jar.toAbsolutePath().toString(), "--help")
                    .directory(tmp.toFile()).start();
            String out = new String(p.getInputStream().readAllBytes());
            assertTrue(p.waitFor(15, TimeUnit.SECONDS));
            assertEquals(0, p.exitValue());
            assertTrue(out.contains("usage"), out);
        }
    }

    /** Sends a command and waits for the expected output; returns everything read. */
    private static String drive(Process process, Object... steps) throws Exception {
        OutputStream stdin = process.getOutputStream();
        StringBuilder seen = new StringBuilder();
        byte[] buf = new byte[4096];
        for (int i = 0; i < steps.length; i += 2) {
            String command = (String) steps[i];
            String expected = (String) steps[i + 1];
            stdin.write((command + "\n").getBytes());
            stdin.flush();
            if (expected == null) {
                continue;
            }
            long deadline = System.currentTimeMillis() + 20_000;
            while (System.currentTimeMillis() < deadline && seen.indexOf(expected) < 0) {
                if (process.getInputStream().available() > 0) {
                    int n = process.getInputStream().read(buf);
                    if (n > 0) {
                        seen.append(new String(buf, 0, n));
                    }
                } else {
                    Thread.sleep(50);
                }
            }
            assertTrue(seen.indexOf(expected) >= 0,
                    "expected '" + expected + "' after '" + command + "', got:\n" + seen);
        }
        stdin.close();
        return seen.toString();
    }

    private static String cmd(String template, Object... args) {
        return template.formatted(args);
    }
}
