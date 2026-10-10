package org.ourcamellia.core.app;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.ourcamellia.common.Errors;
import org.ourcamellia.common.domain.FriendState;
import org.ourcamellia.common.domain.Message;
import org.ourcamellia.common.domain.Notification;
import org.ourcamellia.common.domain.NotificationKind;
import org.ourcamellia.common.domain.PeerStatus;

import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Stage 3 gate: two local clients complete the supported flow over real TLS sockets
 * on loopback — connection, first-contact restriction, friend request/accept,
 * messaging with delivery acks, observer-relative status, and the pinning defense.
 */
class LocalModeIT {

    private int portA;
    private int portB;
    private int portC;
    private LocalTestHarness a;
    private LocalTestHarness b;
    private LocalTestHarness c;

    private static final java.util.concurrent.atomic.AtomicInteger NEXT_PORT =
            new java.util.concurrent.atomic.AtomicInteger(54600);

    @BeforeEach
    void setUp(@TempDir Path tmp) {
        int base = NEXT_PORT.getAndAdd(4);
        portA = base;
        portB = base + 1;
        portC = base + 2;
        a = LocalTestHarness.create("alice", portA, tmp.resolve("a"));
        b = LocalTestHarness.create("bob", portB, tmp.resolve("b"));
        c = LocalTestHarness.create("carol", portC, tmp.resolve("c"));
    }

    @AfterEach
    void tearDown() {
        if (a != null) a.close();
        if (b != null) b.close();
        if (c != null) c.close();
    }

    @Test
    void completeFriendAndMessageFlow() throws Exception {
        // Status is honest UNCONFIRMED before any contact.
        assertEquals(PeerStatus.UNCONFIRMED, a.app.peerStatus("bob"));

        // Address-targeted connection attempt.
        a.app.local().connect("127.0.0.1", portB);
        assertTrue(waitFor(() -> a.app.peerStatus("bob") == PeerStatus.CONNECTED, 5000),
                "alice should see bob as CONNECTED");

        // Stranger chat is refused before friendship (first-contact restriction).
        assertThrows(Errors.Denied.class, () -> a.app.local().sendMessage("bob", "sneaky"));

        // Friend request from alice arrives at bob as a notification.
        assertTrue(a.app.sendFriendRequest("bob"));
        assertTrue(waitFor(() -> !b.app.notifications().isEmpty(), 5000), "bob should get a notification");
        List<Notification> notifs = b.app.notifications();
        Notification req = notifs.stream()
                .filter(n -> n.kind() == NotificationKind.FRIEND_REQUEST && n.from().equals("alice"))
                .findFirst().orElseThrow();
        assertEquals(FriendState.PENDING_IN, b.app.friendState("alice"));
        assertEquals(FriendState.PENDING_OUT, a.app.friendState("bob"));

        // Accept via the notification action path (1 pass).
        b.app.notifyAction(1, "pass");
        assertTrue(waitFor(() -> a.app.friendState("bob") == FriendState.ACCEPTED, 5000),
                "alice should see the friendship accepted");
        assertEquals(FriendState.ACCEPTED, b.app.friendState("alice"));

        // Ordinary messaging now works in both directions with delivery ack.
        a.app.openConversation(org.ourcamellia.common.domain.ConversationRef.privateChat("bob", false));
        a.app.say("hello bob!");
        assertTrue(b.events.awaitMessage(5000), "bob should receive the message");
        Message received = b.events.messagesList().get(b.events.messagesList().size() - 1);
        assertEquals("alice", received.sender());
        assertEquals("hello bob!", received.text());

        b.app.openConversation(org.ourcamellia.common.domain.ConversationRef.privateChat("alice", false));
        b.app.say("hi alice");
        assertTrue(a.events.awaitMessage(5000), "alice should receive the reply");

        // History was persisted automatically (recording on by default).
        List<org.ourcamellia.core.persist.LocalHistoryStore.Entry> history =
                a.app.history().messages("local:bob");
        assertTrue(history.stream().anyMatch(e -> e.text().equals("hello bob!")));
        assertTrue(history.stream().anyMatch(e -> e.text().equals("hi alice")));
    }

    @Test
    void strangerCannotSendChatBeforeFriendship() throws Exception {
        // carol connects to alice but they are not friends.
        c.app.local().connect("127.0.0.1", portA);
        assertTrue(waitFor(() -> c.app.peerStatus("alice") == PeerStatus.CONNECTED, 5000));
        assertThrows(Errors.Denied.class, () -> c.app.local().sendMessage("alice", "let me in"));

        // A raw message frame from a non-friend must be refused by the receiver,
        // and the receiver must not record it.
        org.ourcamellia.common.Ids.newId(); // no-op, clarity
        c.app.local().rawSend("alice", org.ourcamellia.common.protocol.Wire.message(
                org.ourcamellia.common.Ids.newId(), "carol", "alice", "raw attempt"));
        assertTrue(waitFor(() -> c.events.infos.stream().anyMatch(
                t -> t.contains("not friends")), 5000), "carol should see the refusal");
        assertTrue(a.events.messagesList().isEmpty(), "alice must not record non-friend messages");
    }

    @Test
    void unreachableFriendRequestIsUndeliverable() {
        // bob's port has nothing listening → request cannot be delivered.
        boolean delivered = a.app.sendFriendRequest("nobody");
        assertFalse(delivered);
        assertEquals(FriendState.UNDELIVERABLE, a.app.friendState("nobody"));
    }

    @Test
    void observerRelativeStatusTransitions() throws Exception {
        assertEquals(PeerStatus.UNCONFIRMED, a.app.peerStatus("bob"));
        a.app.local().connect("127.0.0.1", portB);
        assertTrue(waitFor(() -> a.app.peerStatus("bob") == PeerStatus.CONNECTED, 5000));
        // Close bob's side; alice must fall back to honest UNCONFIRMED, not "offline".
        b.close();
        assertTrue(waitFor(() -> a.app.peerStatus("bob") != PeerStatus.CONNECTED, 5000));
        assertEquals(PeerStatus.UNCONFIRMED, a.app.peerStatus("bob"));
    }

    @Test
    void certificateChangeIsRefused() throws Exception {
        // Establish friendship first.
        a.app.local().connect("127.0.0.1", portB);
        assertTrue(waitFor(() -> a.app.peerStatus("bob") == PeerStatus.CONNECTED, 5000));
        a.app.sendFriendRequest("bob");
        assertTrue(waitFor(() -> !b.app.notifications().isEmpty(), 5000));
        b.app.notifyAction(1, "pass");
        assertTrue(waitFor(() -> a.app.friendState("bob") == FriendState.ACCEPTED, 5000));
        b.close();

        // A new "bob" with a DIFFERENT identity cert on the same port is an impostor.
        LocalTestHarness impostor = LocalTestHarness.create("bob", portB, a.dir.resolve("impostor"));
        try {
            assertThrows(Errors.OcException.class, () -> a.app.local().connect("127.0.0.1", portB));
        } finally {
            impostor.close();
        }
    }

    @Test
    void duplicateFriendRequestIsIdempotent() throws Exception {
        a.app.local().connect("127.0.0.1", portB);
        assertTrue(waitFor(() -> a.app.peerStatus("bob") == PeerStatus.CONNECTED, 5000));
        assertTrue(a.app.sendFriendRequest("bob"));
        assertTrue(waitFor(() -> !b.app.notifications().isEmpty(), 5000));
        int count = b.app.notifications().size();
        // Second request while pending: alice's client refuses to re-send (Conflict).
        assertThrows(Errors.Conflict.class, () -> a.app.sendFriendRequest("bob"));
        assertEquals(count, b.app.notifications().size());
    }

    private static boolean waitFor(java.util.function.BooleanSupplier condition, long timeoutMs)
            throws InterruptedException {
        long deadline = System.currentTimeMillis() + timeoutMs;
        while (System.currentTimeMillis() < deadline) {
            if (condition.getAsBoolean()) {
                return true;
            }
            Thread.sleep(20);
        }
        return condition.getAsBoolean();
    }
}
