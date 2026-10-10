package org.ourcamellia.core.discovery;

import org.junit.jupiter.api.Test;
import org.ourcamellia.common.protocol.Wire;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Discovery capability tests over real UDP on loopback (unicast, since broadcast is
 * network-dependent): the discoverability/connectability 2x2 matrix, reply
 * validation, and malformed-datagram resilience.
 */
class DiscoveryIT {

    @Test
    void discoverableAndConnectableAnswer() throws Exception {
        int responderPort = freeUdpPort();
        int askerPort = freeUdpPort();
        ConcurrentLinkedQueue<org.ourcamellia.common.protocol.WireMessages.DiscoverReply> replies = new ConcurrentLinkedQueue<>();
        CountDownLatch latch = new CountDownLatch(1);

        AtomicBoolean discoverable = new AtomicBoolean(true);
        AtomicBoolean connectable = new AtomicBoolean(true);
        try (DiscoveryService responder = new DiscoveryService(responderPort, discoverable::get, connectable::get,
                () -> "bob", () -> 55501, () -> "f".repeat(64), 60_000, null)) {
            responder.start();
            assertTrue(responder.boundPort() > 0);
            try (DiscoveryService asker = new DiscoveryService(askerPort, () -> false, () -> false,
                    () -> "alice", () -> askerPort, () -> "e".repeat(64), 60_000, null)) {
                asker.setReplySink((reply, source) -> {
                    replies.add(reply);
                    latch.countDown();
                });
                asker.start();
                asker.queryTo(InetAddress.getByName("127.0.0.1"), responderPort);
                assertTrue(latch.await(5, TimeUnit.SECONDS), "discoverable+connectable peer must answer");
                org.ourcamellia.common.protocol.WireMessages.DiscoverReply r = replies.peek();
                assertEquals("bob", r.username());
                assertEquals(55501, r.tcpPort());
                assertTrue(r.expiresAt() > System.currentTimeMillis());
            }
        }
    }

    @Test
    void discoverableOffStaysSilent() throws Exception {
        matrix(false, true);
    }

    @Test
    void connectableOffStaysSilent() throws Exception {
        matrix(true, false);
    }

    @Test
    void bothOffStaysSilent() throws Exception {
        matrix(false, false);
    }

    private void matrix(boolean discoverable, boolean connectable) throws Exception {
        int responderPort = freeUdpPort();
        AtomicBoolean d = new AtomicBoolean(discoverable);
        AtomicBoolean c = new AtomicBoolean(connectable);
        try (DiscoveryService responder = new DiscoveryService(responderPort, d::get, c::get,
                () -> "bob", () -> 55501, () -> "f".repeat(64), 60_000, null)) {
            responder.start();
            ConcurrentLinkedQueue<org.ourcamellia.common.protocol.WireMessages.DiscoverReply> replies = new ConcurrentLinkedQueue<>();
            int askerPort = freeUdpPort();
            try (DiscoveryService asker = new DiscoveryService(askerPort, () -> false, () -> false,
                    () -> "alice", () -> askerPort, () -> "e".repeat(64), 60_000, null)) {
                asker.setReplySink((reply, source) -> replies.add(reply));
                asker.start();
                for (int i = 0; i < 3; i++) {
                    asker.queryTo(InetAddress.getByName("127.0.0.1"), responderPort);
                }
                Thread.sleep(700);
                assertTrue(replies.isEmpty(), "invisible peer must not answer discovery queries");
            }
        }
    }

    @Test
    void malformedDatagramsAreDropped() throws Exception {
        int responderPort = freeUdpPort();
        AtomicBoolean d = new AtomicBoolean(true);
        AtomicBoolean c = new AtomicBoolean(true);
        try (DiscoveryService responder = new DiscoveryService(responderPort, d::get, c::get,
                () -> "bob", () -> 55501, () -> "f".repeat(64), 60_000, null)) {
            responder.start();
            // Garbage and hostile datagrams must be dropped without killing the loop.
            try (java.net.DatagramSocket raw = new java.net.DatagramSocket()) {
                byte[] garbage = "not json at all".getBytes();
                for (int i = 0; i < 5; i++) {
                    raw.send(new java.net.DatagramPacket(garbage, garbage.length,
                            InetAddress.getByName("127.0.0.1"), responderPort));
                }
                byte[] hostile = "{\"type\":\"discover-query\",\"v\":1,\"id\":\"x\"}".getBytes();
                raw.send(new java.net.DatagramPacket(hostile, hostile.length,
                        InetAddress.getByName("127.0.0.1"), responderPort));
            }
            // The service still answers valid queries afterwards.
            ConcurrentLinkedQueue<org.ourcamellia.common.protocol.WireMessages.DiscoverReply> replies = new ConcurrentLinkedQueue<>();
            CountDownLatch latch = new CountDownLatch(1);
            int askerPort = freeUdpPort();
            try (DiscoveryService asker = new DiscoveryService(askerPort, () -> false, () -> false,
                    () -> "alice", () -> askerPort, () -> "e".repeat(64), 60_000, null)) {
                asker.setReplySink((reply, source) -> {
                    replies.add(reply);
                    latch.countDown();
                });
                asker.start();
                asker.queryTo(InetAddress.getByName("127.0.0.1"), responderPort);
                assertTrue(latch.await(5, TimeUnit.SECONDS), "service must survive garbage input");
            }
        }
    }

    private static int freeUdpPort() throws Exception {
        try (java.net.DatagramSocket s = new java.net.DatagramSocket(null)) {
            s.bind(new InetSocketAddress("127.0.0.1", 0));
            return s.getLocalPort();
        }
    }
}
