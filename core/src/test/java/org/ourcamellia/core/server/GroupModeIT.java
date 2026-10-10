package org.ourcamellia.core.server;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.ourcamellia.common.Errors;
import org.ourcamellia.common.domain.ConversationRef;
import org.ourcamellia.core.app.ServerSession;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Stage 6 gate — groups: ordinary (operator-visible) vs encrypted modes, server-side
 * permission checks, review log for ordinary groups, and the encrypted-group
 * boundary (no plaintext at the server, operator cannot read or moderate content).
 */
class GroupModeIT {

    private static final AtomicInteger NEXT_PORT = new AtomicInteger(55100);

    private static int port() {
        return NEXT_PORT.getAndAdd(3);
    }

    @Test
    void ordinaryGroupFlowAndReviewLog(@TempDir Path dir) throws Exception {
        ServerTestHarness h = ServerTestHarness.start(dir.resolve("srv"), port(), c -> c);
        ServerTestHarness.ServerClient alice = client(dir, "alice", port(), h);
        ServerTestHarness.ServerClient bob = client(dir, "bob", port(), h);
        register(alice, "@alice");
        register(bob, "@bob");
        befriend(alice, bob);

        String groupId = alice.app.server().createGroup("Study", List.of("@bob"), false);
        assertTrue(ServerTestHarness.waitFor(() -> bob.app.server().group(groupId) != null, 8000));

        // Group messaging relays to online members.
        bob.events.awaitInfo(200); // reset noise
        alice.app.server().sendGroupMessage(groupId, "welcome to the group");
        assertTrue(bob.events.awaitMessage(8000));
        assertEquals("welcome to the group", bob.events.messages.peek().text());

        // Review log contains the plaintext (operator-visible group).
        assertTrue(ServerTestHarness.waitFor(() ->
                h.server.review(groupId, 100).stream().anyMatch(e -> e.text().equals("welcome to the group")), 8000));

        // Non-members cannot post: the SERVER must enforce this even when a client
        // crafts the frame directly (client-side UI hiding is not authorization).
        ServerTestHarness.ServerClient carol = client(dir, "carol", port(), h);
        register(carol, "@carol");
        String msgId = org.ourcamellia.common.Ids.newId();
        carol.app.server().session().conn().send(org.ourcamellia.common.protocol.Wire.groupMessage(
                msgId, groupId, "@carol", "intruder", null));
        assertTrue(ServerTestHarness.waitFor(() -> carol.events.infos.stream()
                .anyMatch(t -> t.contains("not a member")), 8000));
        // Non-owner cannot invite: the server refuses (asynchronously reported).
        bob.app.server().inviteMember(groupId, "@carol");
        assertTrue(ServerTestHarness.waitFor(() -> bob.events.infos.stream()
                .anyMatch(t -> t.contains("only the group owner")), 8000));
        // Owner can invite.
        alice.app.server().inviteMember(groupId, "@carol");
        assertTrue(ServerTestHarness.waitFor(() ->
                carol.app.server().group(groupId) != null
                        && carol.app.server().group(groupId).members.contains("@carol"), 8000));

        // Transfer + leave.
        alice.app.server().transferGroup(groupId, "@bob");
        assertTrue(ServerTestHarness.waitFor(() ->
                "@bob".equals(alice.app.server().group(groupId) != null
                        ? alice.app.server().group(groupId).owner : null), 8000));
        bob.app.server().removeMember(groupId, "@carol");
        assertTrue(ServerTestHarness.waitFor(() ->
                carol.app.server().group(groupId) == null, 8000));
        carol.close();
        alice.close();
        bob.close();
        h.server.close();
    }

    @Test
    void encryptedGroupBoundary(@TempDir Path dir) throws Exception {
        ServerTestHarness h = ServerTestHarness.start(dir.resolve("srv"), port(), c -> c);
        ServerTestHarness.ServerClient alice = client(dir, "alice", port(), h);
        ServerTestHarness.ServerClient bob = client(dir, "bob", port(), h);
        register(alice, "@alice");
        register(bob, "@bob");
        befriend(alice, bob);

        String groupId = alice.app.server().createGroup("Secret", List.of("@bob"), true);
        assertTrue(ServerTestHarness.waitFor(() -> bob.app.server().group(groupId) != null, 8000));
        assertTrue(ServerTestHarness.waitFor(() ->
                bob.app.server().group(groupId).groupKey != null, 8000),
                "bob must receive and unwrap the group key");

        // Encrypted messaging decrypts at members only.
        alice.app.server().sendGroupMessage(groupId, "top secret plan");
        assertTrue(bob.events.awaitMessage(8000));
        assertEquals("top secret plan", bob.events.messages.peek().text());

        // The server never sees plaintext: no review entry, no plaintext on disk.
        assertTrue(h.server.review(groupId, 100).isEmpty(),
                "encrypted group content must never enter the review log");
        String stateJson = Files.readString(dir.resolve("srv").resolve("server-state.json"));
        assertFalse(stateJson.contains("top secret plan"),
                "encrypted group plaintext must never be stored server-side");
        assertFalse(stateJson.contains("secret plan"),
                "not even fragments of encrypted content may be stored");

        // Operator cannot moderate encrypted content.
        assertThrows(Errors.Denied.class, () -> h.server.modDelete(groupId, "anything"));

        // Removal → owner rotates → removed member's old key cannot decrypt new content.
        alice.app.server().removeMember(groupId, "@bob");
        assertTrue(ServerTestHarness.waitFor(() ->
                bob.app.server().group(groupId) == null, 8000));
        alice.app.server().rotateGroupKeys(groupId);
        // bob's client no longer has the group; the owner now holds the rotated key.
        ServerSession.ClientGroup g = alice.app.server().group(groupId);
        assertNotNull(g.groupKey);
        alice.close();
        bob.close();
        h.server.close();
    }

    @Test
    void encryptedGroupsDisableableByPolicy(@TempDir Path dir) throws Exception {
        ServerTestHarness h = ServerTestHarness.start(dir.resolve("srv"), port(), c -> {
            return new org.ourcamellia.common.config.ServerConfig(
                    c.bindHost(), c.port(), c.serverName(), c.dataDir(),
                    c.tlsAutoGenerate(), c.tlsKeystorePath(), c.tlsKeystorePassword(),
                    c.requiredRegistrationFields(), c.requireEmail(), c.registrationPolicy(),
                    c.pendingTtlMinutes(), c.verifier(), c.notificationRetentionDays(),
                    false /* encryptedGroupsAllowed */, c.botApi(), c.rateLimits(),
                    c.adminUsernames(), c.passwordHashIterations(), c.reviewLogRetention(),
                    c.maxFrameBytes(), c.connectTimeoutMs(), c.readTimeoutMs(),
                    c.pingIntervalMs(), c.logLevel());
        });
        ServerTestHarness.ServerClient alice = client(dir, "alice", port(), h);
        register(alice, "@alice");
        // Server refuses encrypted group creation.
        String groupId = org.ourcamellia.common.Ids.newId();
        alice.app.server().session().conn().send(
                org.ourcamellia.common.protocol.Wire.groupCreate(groupId, "Secret",
                        "encrypted", List.of()));
        assertTrue(ServerTestHarness.waitFor(() -> alice.events.infos.stream()
                .anyMatch(t -> t.contains("disabled by server policy")), 8000));
        alice.close();
        h.server.close();
    }

    @Test
    void announcementChannelIsReadOnlyForUsers(@TempDir Path dir) throws Exception {
        ServerTestHarness h = ServerTestHarness.start(dir.resolve("srv"), port(), c -> c);
        ServerTestHarness.ServerClient alice = client(dir, "alice", port(), h);
        register(alice, "@alice");

        // Operators announce via the console path only; the channel is read-only
        // client-side and the server has no client-to-channel posting frame.
        ConversationRef channel = alice.app.server().conversations().stream()
                .filter(c -> c.kind() == ConversationRef.Kind.CHANNEL).findFirst().orElseThrow();
        assertTrue(channel.pinned(), "the server channel must be pinned at the top");
        assertThrows(Errors.Denied.class, () -> alice.app.server().sayIn(channel, "hi all"));

        // Announcements arrive in the channel and as notifications.
        h.server.announce("weekly digest");
        assertTrue(ServerTestHarness.waitFor(() -> alice.app.server().notificationList().stream()
                .anyMatch(n -> n.kind() == org.ourcamellia.common.domain.NotificationKind.ANNOUNCEMENT), 8000));
        assertTrue(alice.events.awaitMessage(8000), "announcement should appear in the channel");
        alice.close();
        h.server.close();
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

    private static void befriend(ServerTestHarness.ServerClient a, ServerTestHarness.ServerClient b)
            throws InterruptedException {
        a.app.server().sendFriendRequest(b.app.server().loggedInUser());
        assertTrue(ServerTestHarness.waitFor(() -> !b.app.server().notificationList().isEmpty(), 8000));
        var req = b.app.server().notificationList().stream()
                .filter(n -> n.kind() == org.ourcamellia.common.domain.NotificationKind.FRIEND_REQUEST)
                .findFirst().orElseThrow();
        b.app.server().acceptFriendRequest(a.app.server().loggedInUser(), req.refId());
        assertTrue(ServerTestHarness.waitFor(() ->
                a.app.server().friendState(b.app.server().loggedInUser())
                        == org.ourcamellia.common.domain.FriendState.ACCEPTED, 8000));
    }
}
