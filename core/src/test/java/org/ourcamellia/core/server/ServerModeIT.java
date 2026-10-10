package org.ourcamellia.core.server;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.ourcamellia.common.Errors;
import org.ourcamellia.common.domain.FriendState;
import org.ourcamellia.common.domain.Message;
import org.ourcamellia.common.domain.Notification;
import org.ourcamellia.common.domain.NotificationKind;
import org.ourcamellia.core.app.ServerSession;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Stage 4/5 gates: registration policies, secure authentication, friendship,
 * private messaging with honest delivery semantics, offline notifications with
 * dedup/expiry, restart persistence, and the no-IP-disclosure rule.
 */
class ServerModeIT {

    private static final java.util.concurrent.atomic.AtomicInteger NEXT_PORT =
            new java.util.concurrent.atomic.AtomicInteger(54900);

    @Test
    void autoRegistrationAndLogin(@TempDir Path dir) throws Exception {
        ServerTestHarness h = ServerTestHarness.start(dir.resolve("srv"), port(), c -> c);
        ServerTestHarness.ServerClient alice = ServerTestHarness.client("alice", dir, port() + 10,
                "127.0.0.1:" + h.port);

        assertTrue(ServerTestHarness.waitFor(() ->
                alice.events.infos.stream().anyMatch(t -> t.contains("connected to server")), 8000));
        alice.app.server().register("@alice", "password1", Map.of("@Email", "alice@example.com"));
        assertTrue(ServerTestHarness.waitFor(() ->
                alice.events.infos.stream().anyMatch(t -> t.contains("logged in as @alice")), 8000),
                "auto registration should log in immediately");
        assertEquals("@alice", alice.app.server().loggedInUser());

        // Wrong password is rejected; right password works after logout.
        alice.app.server().logout();
        ServerTestHarness.waitFor(() -> alice.app.server().loggedInUser() == null, 5000);
        alice.app.server().login("@alice", "wrong");
        assertTrue(ServerTestHarness.waitFor(() ->
                alice.events.infos.stream().anyMatch(t -> t.contains("invalid username or password")), 8000));
        alice.app.server().login("@alice", "password1");
        assertTrue(ServerTestHarness.waitFor(() ->
                alice.events.infos.stream().anyMatch(t -> t.contains("logged in as @alice")), 8000));

        // No plaintext password anywhere on disk.
        String state = Files.readString(dir.resolve("srv").resolve("server-state.json"));
        assertFalse(state.contains("password1"), "plaintext password must never be stored");
        assertTrue(state.contains("pbkdf2-sha256"), "password must be stored as PBKDF2 hash");

        alice.close();
        h.server.close();
    }

    @Test
    void friendshipAndPrivateMessaging(@TempDir Path dir) throws Exception {
        ServerTestHarness h = ServerTestHarness.start(dir.resolve("srv"), port(), c -> c);
        ServerTestHarness.ServerClient alice = ServerTestHarness.client("alice", dir, port() + 20,
                "127.0.0.1:" + h.port);
        ServerTestHarness.ServerClient bob = ServerTestHarness.client("bob", dir, port() + 21,
                "127.0.0.1:" + h.port);
        registerAndWait(alice, "@alice");
        registerAndWait(bob, "@bob");

        // Not friends yet: messaging is denied.
        assertThrows(Errors.Denied.class, () -> alice.app.server().sendPrivate("@bob", "sneak"));

        // Friend request → bob sees a notification; accept via notification action.
        assertTrue(alice.app.server().sendFriendRequest("@bob"));
        assertTrue(ServerTestHarness.waitFor(() -> !bob.app.server().notificationList().isEmpty(), 8000));
        assertEquals(FriendState.PENDING_OUT, alice.app.server().friendState("@bob"));
        assertEquals(FriendState.PENDING_IN, bob.app.server().friendState("@alice"));
        List<Notification> bobNotifs = bob.app.server().notificationList();
        Notification req = bobNotifs.stream()
                .filter(n -> n.kind() == NotificationKind.FRIEND_REQUEST)
                .findFirst().orElseThrow();
        bob.app.server().acceptFriendRequest("@alice", req.refId());
        assertTrue(ServerTestHarness.waitFor(() ->
                alice.app.server().friendState("@bob") == FriendState.ACCEPTED, 8000));

        // Private messaging in both directions.
        alice.app.server().sendPrivate("@bob", "hello from alice");
        assertTrue(bob.events.awaitMessage(8000));
        Message m = bob.events.messages.peek();
        assertEquals("hello from alice", m.text());
        assertEquals("@alice", m.sender());

        bob.app.server().sendPrivate("@alice", "hi back");
        assertTrue(alice.events.awaitMessage(8000));

        // Offline recipient → honest delivery failure, nothing queued.
        bob.app.server().logout();
        ServerTestHarness.waitFor(() -> bob.app.server().loggedInUser() == null, 5000);
        // Wait until the SERVER has processed the disconnect, then send.
        assertTrue(ServerTestHarness.waitFor(() -> h.events.infos.stream()
                .anyMatch(t -> t.contains("@bob disconnected")), 8000));
        alice.app.server().sendPrivate("@bob", "are you there?");
        assertTrue(ServerTestHarness.waitFor(() ->
                alice.events.infos.stream().anyMatch(t -> t.contains("delivery to @bob: failed")), 8000));

        alice.close();
        bob.close();
        h.server.close();
    }

    @Test
    void offlineNotificationsDedupAndAnnouncements(@TempDir Path dir) throws Exception {
        ServerTestHarness h = ServerTestHarness.start(dir.resolve("srv"), port(), c -> c);
        ServerTestHarness.ServerClient alice = ServerTestHarness.client("alice", dir, port() + 30,
                "127.0.0.1:" + h.port);
        ServerTestHarness.ServerClient bob = ServerTestHarness.client("bob", dir, port() + 31,
                "127.0.0.1:" + h.port);
        registerAndWait(alice, "@alice");
        registerAndWait(bob, "@bob");

        // bob goes offline; alice sends a friend request and the operator announces.
        bob.app.server().logout();
        ServerTestHarness.waitFor(() -> bob.app.server().loggedInUser() == null, 5000);
        alice.app.server().sendFriendRequest("@bob");
        h.server.announce("scheduled maintenance tonight");

        // bob logs back in: he receives the friend-request notification and the
        // announcement (offline delivery), each exactly once.
        bob.app.server().login("@bob", "password1");
        assertTrue(ServerTestHarness.waitFor(() -> {
            List<Notification> list = bob.app.server().notificationList();
            return list.stream().anyMatch(n -> n.kind() == NotificationKind.FRIEND_REQUEST)
                    && list.stream().anyMatch(n -> n.kind() == NotificationKind.ANNOUNCEMENT);
        }, 8000));
        List<Notification> list = bob.app.server().notificationList();
        assertEquals(1, list.stream().filter(n -> n.kind() == NotificationKind.ANNOUNCEMENT).count());
        assertEquals(1, list.stream().filter(n -> n.kind() == NotificationKind.FRIEND_REQUEST).count());

        // Reconnect again: no duplicate notifications (stable ids, state persists).
        bob.app.server().logout();
        ServerTestHarness.waitFor(() -> bob.app.server().loggedInUser() == null, 5000);
        bob.app.server().login("@bob", "password1");
        ServerTestHarness.waitFor(() -> bob.app.server().loggedInUser() != null, 8000);
        Thread.sleep(500);
        List<Notification> list2 = bob.app.server().notificationList();
        assertEquals(1, list2.stream().filter(n -> n.kind() == NotificationKind.FRIEND_REQUEST).count());

        // Mark reviewed ("over") → leaves the active list; then it stays gone.
        Notification n = list2.get(0);
        bob.app.server().notifyAction(n, "over");
        ServerTestHarness.waitFor(() -> bob.app.server().notificationList().stream()
                .noneMatch(x -> x.id().equals(n.id())), 8000);

        alice.close();
        bob.close();
        h.server.close();
    }

    @Test
    void manualRegistrationPolicyAndAdminBootstrap(@TempDir Path dir) throws Exception {
        ServerTestHarness h = ServerTestHarness.start(dir.resolve("srv"), port(),
                c -> ServerTestHarness.withPolicy(c, "manual"));
        ServerTestHarness.ServerClient admin = ServerTestHarness.client("admin", dir, port() + 40,
                "127.0.0.1:" + h.port);
        ServerTestHarness.ServerClient alice = ServerTestHarness.client("alice", dir, port() + 41,
                "127.0.0.1:" + h.port);

        // @admin is a bootstrap name: auto policy not needed; operator approves manually.
        admin.app.server().register("@admin", "password1", Map.of("@Email", "admin@example.com"));
        assertTrue(ServerTestHarness.waitFor(() ->
                admin.events.infos.stream().anyMatch(t -> t.contains("pending manual approval")), 8000));
        assertNull(admin.app.server().loggedInUser());

        // Operator approves the ticket; the bootstrap name becomes operator at approval.
        String ticketId = h.server.store().state().registrations.values().iterator().next().ticketId;
        h.server.approveRegistration(ticketId);
        assertTrue(h.server.isAdmin("@admin"));
        admin.app.server().login("@admin", "password1");
        assertTrue(ServerTestHarness.waitFor(() ->
                admin.events.infos.stream().anyMatch(t -> t.contains("logged in as @admin")), 8000));

        // Pending login attempt fails with a clear message.
        alice.app.server().register("@alice", "password1", Map.of("@Email", "a@example.com"));
        assertTrue(ServerTestHarness.waitFor(() ->
                alice.events.infos.stream().anyMatch(t -> t.contains("pending manual approval")), 8000));
        alice.app.server().login("@alice", "password1");
        assertTrue(ServerTestHarness.waitFor(() ->
                alice.events.infos.stream().anyMatch(t -> t.contains("still pending")), 8000));

        admin.close();
        alice.close();
        h.server.close();
    }

    @Test
    void noIpDisclosureAndRestartPersistence(@TempDir Path dir) throws Exception {
        Path srvDir = dir.resolve("srv");
        int port = port();
        ServerTestHarness h = ServerTestHarness.start(srvDir, port, c -> c);
        ServerTestHarness.ServerClient alice = ServerTestHarness.client("alice", dir, port + 50,
                "127.0.0.1:" + h.port);
        ServerTestHarness.ServerClient bob = ServerTestHarness.client("bob", dir, port + 51,
                "127.0.0.1:" + h.port);
        registerAndWait(alice, "@alice");
        registerAndWait(bob, "@bob");
        alice.app.server().sendFriendRequest("@bob");
        assertTrue(ServerTestHarness.waitFor(() -> !bob.app.server().notificationList().isEmpty(), 8000));
        bob.app.server().acceptFriendRequest("@alice", bob.app.server().notificationList().get(0).refId());
        ServerTestHarness.waitFor(() -> alice.app.server().friendState("@bob") == FriendState.ACCEPTED, 8000);
        h.server.announce("persist me");

        // The server's persisted state must not contain client source IPs.
        String state = Files.readString(srvDir.resolve("server-state.json"));
        assertFalse(state.contains("127.0.0.1"), "server state must never contain client IP addresses");

        // Graceful restart: relationships and notifications survive.
        alice.close();
        bob.close();
        h.server.close();

        ServerTestHarness h2 = ServerTestHarness.start(srvDir, port, c -> c);
        ServerTestHarness.ServerClient alice2 = ServerTestHarness.client("alice2", dir, port + 52,
                "127.0.0.1:" + h2.port);
        alice2.app.server().login("@alice", "password1");
        assertTrue(ServerTestHarness.waitFor(() ->
                alice2.app.server().loggedInUser() != null, 8000));
        assertTrue(alice2.app.server().friends().contains("@bob"), "friendship must survive restart");
        assertTrue(ServerTestHarness.waitFor(() -> alice2.app.server().notificationList().stream()
                .anyMatch(n -> n.kind() == NotificationKind.ANNOUNCEMENT), 8000),
                "announcement must survive restart for offline delivery");

        alice2.close();
        h2.server.close();
    }

    @Test
    void expiredNotificationsAreNotDelivered(@TempDir Path dir) throws Exception {
        Path srvDir = dir.resolve("srv");
        int port = port();
        ServerTestHarness h = ServerTestHarness.start(srvDir, port, c -> c);
        ServerTestHarness.ServerClient alice = ServerTestHarness.client("alice", dir, port + 60,
                "127.0.0.1:" + h.port);
        registerAndWait(alice, "@alice");
        alice.close();

        // Inject an already-expired notification directly into the persisted state.
        synchronized (h.server.store()) {
            ServerStateStore.Notif n = new ServerStateStore.Notif();
            n.id = org.ourcamellia.common.Ids.newId();
            n.kind = "announcement";
            n.state = "unread";
            n.from = "Test Server";
            n.text = "expired announcement";
            n.createdAt = System.currentTimeMillis() - 2L * 24 * 3600 * 1000;
            n.expiresAt = System.currentTimeMillis() - 24L * 3600 * 1000;
            n.refId = null;
            h.server.store().state().notifications.computeIfAbsent("@alice", k -> new java.util.ArrayList<>()).add(n);
            h.server.store().save();
        }
        h.server.close();

        // Restart purges the expired notification before delivery.
        ServerTestHarness h2 = ServerTestHarness.start(srvDir, port, c -> c);
        ServerTestHarness.ServerClient alice2 = ServerTestHarness.client("alice2", dir, port + 61,
                "127.0.0.1:" + h2.port);
        alice2.app.server().login("@alice", "password1");
        ServerTestHarness.waitFor(() -> alice2.app.server().loggedInUser() != null, 8000);
        Thread.sleep(400);
        assertTrue(alice2.app.server().notificationList().stream()
                .noneMatch(n -> n.text().equals("expired announcement")),
                "expired notifications must not be delivered");

        alice2.close();
        h2.server.close();
    }

    @Test
    void loginRateLimit(@TempDir Path dir) throws Exception {
        ServerTestHarness h = ServerTestHarness.start(dir.resolve("srv"), port(), c -> {
            var cfg = c;
            return new org.ourcamellia.common.config.ServerConfig(
                    cfg.bindHost(), cfg.port(), cfg.serverName(), cfg.dataDir(),
                    cfg.tlsAutoGenerate(), cfg.tlsKeystorePath(), cfg.tlsKeystorePassword(),
                    cfg.requiredRegistrationFields(), cfg.requireEmail(), cfg.registrationPolicy(),
                    cfg.pendingTtlMinutes(), cfg.verifier(), cfg.notificationRetentionDays(),
                    cfg.encryptedGroupsAllowed(), cfg.botApi(),
                    new org.ourcamellia.common.config.ServerConfig.RateLimitConfig(2, 3, 60, 10, 120, 30),
                    cfg.adminUsernames(), cfg.passwordHashIterations(), cfg.reviewLogRetention(),
                    cfg.maxFrameBytes(), cfg.connectTimeoutMs(), cfg.readTimeoutMs(),
                    cfg.pingIntervalMs(), cfg.logLevel());
        });
        ServerTestHarness.ServerClient alice = ServerTestHarness.client("alice", dir, port() + 70,
                "127.0.0.1:" + h.port);
        registerAndWait(alice, "@alice");
        alice.app.server().logout();
        ServerTestHarness.waitFor(() -> alice.app.server().loggedInUser() == null, 5000);
        for (int i = 0; i < 4; i++) {
            alice.app.server().login("@alice", "bad-password");
        }
        assertTrue(ServerTestHarness.waitFor(() ->
                alice.events.infos.stream().anyMatch(t -> t.contains("too many login attempts")), 8000),
                "login rate limit must engage");

        alice.close();
        h.server.close();
    }

    private static void registerAndWait(ServerTestHarness.ServerClient client, String name)
            throws InterruptedException {
        client.app.server().register(name, "password1", Map.of("@Email", name.substring(1) + "@example.com"));
        assertTrue(ServerTestHarness.waitFor(() ->
                client.events.infos.stream().anyMatch(t -> t.contains("logged in as " + name)), 8000),
                "registration+login for " + name);
    }

    private static int port() {
        return NEXT_PORT.getAndAdd(3);
    }
}
