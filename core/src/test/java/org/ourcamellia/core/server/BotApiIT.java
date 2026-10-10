package org.ourcamellia.core.server;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.ourcamellia.common.Errors;
import org.ourcamellia.common.protocol.Envelope;
import org.ourcamellia.common.protocol.Wire;
import org.ourcamellia.core.botapi.BotHttpServer;
import org.ourcamellia.core.botapi.BotSession;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Stage 6 gate — BOT API: authentication, permission scoping (no admin by default),
 * token revocation, rate limits, BOT visibility, and the localhost HTTP adapter's
 * security (no unauthenticated access, no administrative endpoints).
 */
class BotApiIT {

    private static final AtomicInteger NEXT_PORT = new AtomicInteger(55200);

    private static int port() {
        return NEXT_PORT.getAndAdd(3);
    }

    @Test
    void botLifecycleAndMessaging(@TempDir Path dir) throws Exception {
        ServerTestHarness h = ServerTestHarness.start(dir.resolve("srv"), port(), c -> c);
        ServerTestHarness.ServerClient alice = client(dir, "alice", port(), h);
        register(alice, "@alice");

        // Create a BOT account; token is shown once and stored hashed only.
        ServerCore.BotCredential cred = h.server.createBot("@alice", "@helper");
        assertNotNull(cred.token());
        assertFalse(h.server.store().state().botTokens.values().iterator().next().tokenHash
                .equals(cred.token()), "tokens must be stored as digests, never verbatim");
        assertTrue(h.server.store().state().accounts.get("@helper").bot, "BOT must be marked");

        // Wrong token rejected; right token opens a session.
        assertThrows(Errors.Auth.class, () -> h.server.openBotSession("wrong-token", cred.x25519PrivateKeyBase64()));
        try (BotSession bot = h.server.openBotSession(cred.token(), cred.x25519PrivateKeyBase64())) {
            assertEquals("@helper", bot.botName());

            // BOT can befriend and message like any user (friendship enforced server-side).
            bot.sendFriendRequest("@alice");
            assertTrue(ServerTestHarness.waitFor(() -> !alice.app.server().notificationList().isEmpty(), 8000));
            var req = alice.app.server().notificationList().get(0);
            alice.app.server().acceptFriendRequest("@helper", req.refId());
            assertTrue(ServerTestHarness.waitFor(() -> alice.app.server().friends().contains("@helper"), 8000));

            bot.sendPrivate("@alice", "beep boop");
            assertTrue(alice.events.awaitMessage(8000));
            assertEquals("@helper", alice.events.messages.peek().sender());
            assertEquals("beep boop", alice.events.messages.peek().text());

            alice.app.server().sendPrivate("@helper", "hello bot");
            Envelope message = awaitBotMessage(bot, "hello bot", 8000);
            assertNotNull(message);
            assertEquals(Wire.T_MESSAGE, message.type());
            assertEquals("hello bot", message.body().path("text").asText());
        }

        // Revocation: owner revokes; the token stops working.
        h.server.revokeBotTokens("@alice", "@helper");
        assertThrows(Errors.Auth.class, () -> h.server.openBotSession(cred.token(), cred.x25519PrivateKeyBase64()));

        alice.close();
        h.server.close();
    }

    @Test
    void botHasNoAdministrativePower(@TempDir Path dir) throws Exception {
        ServerTestHarness h = ServerTestHarness.start(dir.resolve("srv"), port(), c -> c);
        ServerCore.BotCredential cred = h.server.createBot("@admin", "@evil");
        try (BotSession bot = h.server.openBotSession(cred.token(), cred.x25519PrivateKeyBase64())) {
            // The BOT API surface contains no administrative operations at all
            // (compile-time property, verified by reflection).
            for (var method : BotSession.class.getDeclaredMethods()) {
                String name = method.getName();
                assertFalse(List.of("announce", "promote", "demote", "modDelete",
                        "approveRegistration", "rejectRegistration", "createBot",
                        "revokeBotTokens").contains(name),
                        "BOT API must not expose administrative operation: " + name);
            }
            // A token does not make the bot an operator.
            assertFalse(h.server.isAdmin("@evil"));
        }
        h.server.close();
    }

    @Test
    void botRateLimit(@TempDir Path dir) throws Exception {
        ServerTestHarness h = ServerTestHarness.start(dir.resolve("srv"), port(), c -> {
            var cfg = c;
            return new org.ourcamellia.common.config.ServerConfig(
                    cfg.bindHost(), cfg.port(), cfg.serverName(), cfg.dataDir(),
                    cfg.tlsAutoGenerate(), cfg.tlsKeystorePath(), cfg.tlsKeystorePassword(),
                    cfg.requiredRegistrationFields(), cfg.requireEmail(), cfg.registrationPolicy(),
                    cfg.pendingTtlMinutes(), cfg.verifier(), cfg.notificationRetentionDays(),
                    cfg.encryptedGroupsAllowed(),
                    new org.ourcamellia.common.config.ServerConfig.BotApiConfig(false, "127.0.0.1", 54700, 3),
                    cfg.rateLimits(), cfg.adminUsernames(), cfg.passwordHashIterations(),
                    cfg.reviewLogRetention(), cfg.maxFrameBytes(), cfg.connectTimeoutMs(),
                    cfg.readTimeoutMs(), cfg.pingIntervalMs(), cfg.logLevel());
        });
        ServerTestHarness.ServerClient alice = client(dir, "alice", port(), h);
        register(alice, "@alice");
        ServerCore.BotCredential cred = h.server.createBot("@alice", "@fast");
        try (BotSession bot = h.server.openBotSession(cred.token(), cred.x25519PrivateKeyBase64())) {
            for (int i = 0; i < 3; i++) {
                bot.sendPrivate("@alice", "msg " + i);
            }
            // The 4th request exceeds the per-token limit (3/min).
            assertThrows(Errors.RateLimited.class, () -> bot.sendPrivate("@alice", "msg 4"));
        }
        alice.close();
        h.server.close();
    }

    @Test
    void httpAdapterRequiresAuthAndHasNoAdminEndpoints(@TempDir Path dir) throws Exception {
        ServerTestHarness h = ServerTestHarness.start(dir.resolve("srv"), port(), c -> {
            var cfg = c;
            int httpPort = port();
            return new org.ourcamellia.common.config.ServerConfig(
                    cfg.bindHost(), cfg.port(), cfg.serverName(), cfg.dataDir(),
                    cfg.tlsAutoGenerate(), cfg.tlsKeystorePath(), cfg.tlsKeystorePassword(),
                    cfg.requiredRegistrationFields(), cfg.requireEmail(), cfg.registrationPolicy(),
                    cfg.pendingTtlMinutes(), cfg.verifier(), cfg.notificationRetentionDays(),
                    cfg.encryptedGroupsAllowed(),
                    new org.ourcamellia.common.config.ServerConfig.BotApiConfig(true, "127.0.0.1", httpPort, 30),
                    cfg.rateLimits(), cfg.adminUsernames(), cfg.passwordHashIterations(),
                    cfg.reviewLogRetention(), cfg.maxFrameBytes(), cfg.connectTimeoutMs(),
                    cfg.readTimeoutMs(), cfg.pingIntervalMs(), cfg.logLevel());
        });
        ServerTestHarness.ServerClient alice = client(dir, "alice", port(), h);
        register(alice, "@alice");
        ServerCore.BotCredential cred = h.server.createBot("@alice", "@webbot");
        BotHttpServer http = new BotHttpServer(h.server, h.config);
        http.start();
        int httpPort = h.config.botApi().port();

        HttpClient client = HttpClient.newHttpClient();
        // No token → 401.
        HttpResponse<String> noAuth = client.send(HttpRequest.newBuilder(
                URI.create("http://127.0.0.1:" + httpPort + "/v1/events")).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(401, noAuth.statusCode());
        // Wrong token → 401.
        HttpResponse<String> badToken = client.send(HttpRequest.newBuilder(
                URI.create("http://127.0.0.1:" + httpPort + "/v1/events?token=wrong")).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(401, badToken.statusCode());
        // Valid token → auth ok and events work.
        HttpResponse<String> auth = client.send(HttpRequest.newBuilder(
                URI.create("http://127.0.0.1:" + httpPort + "/v1/auth"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString("{\"token\":\"" + cred.token() + "\"}"))
                .build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(200, auth.statusCode());
        assertTrue(auth.body().contains("@webbot"));
        // Befriend alice via HTTP, then send a private message (bot → alice).
        HttpResponse<String> fr = client.send(HttpRequest.newBuilder(
                URI.create("http://127.0.0.1:" + httpPort + "/v1/friend-request"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(
                        "{\"token\":\"" + cred.token() + "\",\"to\":\"@alice\"}"))
                .build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(200, fr.statusCode());
        assertTrue(ServerTestHarness.waitFor(() -> !alice.app.server().notificationList().isEmpty(), 8000));
        alice.app.server().acceptFriendRequest("@webbot", alice.app.server().notificationList().get(0).refId());
        assertTrue(ServerTestHarness.waitFor(() -> alice.app.server().friends().contains("@webbot"), 8000));

        HttpResponse<String> send = client.send(HttpRequest.newBuilder(
                URI.create("http://127.0.0.1:" + httpPort + "/v1/send"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(
                        "{\"token\":\"" + cred.token() + "\",\"to\":\"@alice\",\"text\":\"from http\"}"))
                .build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(200, send.statusCode());
        assertTrue(alice.events.awaitMessage(8000));
        // Administrative endpoints do not exist → 404.
        HttpResponse<String> admin = client.send(HttpRequest.newBuilder(
                URI.create("http://127.0.0.1:" + httpPort + "/v1/admin")).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(404, admin.statusCode());

        http.close();
        alice.close();
        h.server.close();
    }

    private static org.ourcamellia.common.protocol.Envelope awaitBotMessage(BotSession bot,
            String text, long timeoutMs) throws InterruptedException {
        long deadline = System.currentTimeMillis() + timeoutMs;
        while (System.currentTimeMillis() < deadline) {
            org.ourcamellia.common.protocol.Envelope e = bot.nextEvent(500);
            if (e != null && Wire.T_MESSAGE.equals(e.type())
                    && text.equals(e.body().path("text").asText())) {
                return e;
            }
        }
        return null;
    }

    private static ServerTestHarness.ServerClient client(Path dir, String name, int listenPort,
                                                         ServerTestHarness h) {
        return ServerTestHarness.client(name, dir, listenPort, "127.0.0.1:" + h.port);
    }

    private static void register(ServerTestHarness.ServerClient client, String name)
            throws InterruptedException {
        client.app.server().register(name, "password1", Map.of("@Email", name.substring(1) + "@example.com"));
        assertTrue(ServerTestHarness.waitFor(() ->
                client.events.infos.stream().anyMatch(t -> t.contains("logged in as " + name)), 8000));
    }
}
