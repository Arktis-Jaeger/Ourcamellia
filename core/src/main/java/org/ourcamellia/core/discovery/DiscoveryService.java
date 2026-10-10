package org.ourcamellia.core.discovery;

import com.fasterxml.jackson.databind.JsonNode;
import org.ourcamellia.common.Errors;
import org.ourcamellia.common.Ids;
import org.ourcamellia.common.Json;
import org.ourcamellia.common.protocol.Wire;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BooleanSupplier;
import java.util.function.Supplier;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Local-mode UDP discovery (REQUIREMENTS §3.1): a separate capability from direct
 * connections. A query is broadcast; only peers that are BOTH discoverable and
 * connectable answer by unicast with {username, tcpPort, certFingerprint, expiry}.
 * A reply is never interpreted as "online now" — it only feeds the peer directory.
 * On networks where broadcast is unavailable/blocked, queries return nothing and
 * manual address entry remains fully functional (documented limitation).
 */
public final class DiscoveryService implements AutoCloseable {

    private static final Logger LOG = Logger.getLogger(DiscoveryService.class.getName());
    public static final int MAX_DATAGRAM = 4096;

    private final int port;
    private final BooleanSupplier discoverable;
    private final BooleanSupplier connectable;
    private final Supplier<String> username;
    private final Supplier<Integer> tcpPort;
    private final Supplier<String> fingerprint;
    private final long ttlMillis;
    private final InetAddress broadcastOverride; // test hook (unicast to loopback)

    private DatagramSocket socket;
    private Thread receiver;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final AtomicBoolean sendBroadcast = new AtomicBoolean(true);

    public DiscoveryService(int port, BooleanSupplier discoverable, BooleanSupplier connectable,
                            Supplier<String> username, Supplier<Integer> tcpPort,
                            Supplier<String> fingerprint, long ttlMillis,
                            InetAddress broadcastOverride) {
        this.port = port;
        this.discoverable = discoverable;
        this.connectable = connectable;
        this.username = username;
        this.tcpPort = tcpPort;
        this.fingerprint = fingerprint;
        this.ttlMillis = ttlMillis;
        this.broadcastOverride = broadcastOverride;
    }

    /** Binds the UDP socket. Port conflicts surface as a clear, non-fatal error. */
    public void start() {
        try {
            socket = new DatagramSocket(null);
            socket.setReuseAddress(true);
            socket.bind(new InetSocketAddress(port));
            socket.setBroadcast(true);
            running.set(true);
            receiver = Thread.ofVirtual().name("discovery-udp").start(this::receiveLoop);
        } catch (IOException e) {
            socket = null;
            running.set(false);
            LOG.log(Level.WARNING, "discovery unavailable on port {0}: {1}",
                    new Object[]{port, e.getMessage()});
        }
    }

    /** Sends one discovery query; answers arrive asynchronously (see setReplySink). */
    public String query() {
        String id = Ids.newId();
        if (!running.get() || socket == null) {
            return id; // discovery unavailable; empty results
        }
        try {
            byte[] payload = Json.writeBytes(Wire.discoverQuery(id));
            InetAddress target = broadcastOverride != null
                    ? broadcastOverride
                    : InetAddress.getByName("255.255.255.255");
            if (sendBroadcast.get()) {
                socket.send(new DatagramPacket(payload, payload.length, target, port));
            }
        } catch (IOException e) {
            LOG.log(Level.FINE, "discovery query send failed: {0}", e.getMessage());
        }
        return id;
    }

    /** Query sent directly to one address (used by tests and manual refresh). */
    public String queryTo(InetAddress target) {
        return queryTo(target, port);
    }

    /** Query sent directly to one address:port (loopback tests use this overload). */
    public String queryTo(InetAddress target, int targetPort) {
        if (socket == null) {
            return Ids.newId();
        }
        String id = Ids.newId();
        try {
            byte[] payload = Json.writeBytes(Wire.discoverQuery(id));
            socket.send(new DatagramPacket(payload, payload.length, target, targetPort));
        } catch (IOException e) {
            LOG.log(Level.FINE, "discovery unicast failed: {0}", e.getMessage());
        }
        return id;
    }

    /** The actual bound UDP port (0 when unavailable). */
    public int boundPort() {
        return socket == null || !socket.isBound() ? 0 : socket.getLocalPort();
    }

    public void setSendBroadcast(boolean enabled) {
        sendBroadcast.set(enabled);
    }

    public interface ReplySink {
        void onReply(org.ourcamellia.common.protocol.WireMessages.DiscoverReply reply, InetAddress source);
    }

    private volatile ReplySink replySink = (reply, source) -> {};

    public void setReplySink(ReplySink sink) {
        this.replySink = sink;
    }

    private void receiveLoop() {
        byte[] buf = new byte[MAX_DATAGRAM];
        while (running.get()) {
            try {
                DatagramPacket packet = new DatagramPacket(buf, buf.length);
                socket.receive(packet);
                JsonNode root = Json.parse(java.util.Arrays.copyOf(packet.getData(), packet.getLength()));
                String type = root.path("type").asText("");
                if (type.equals(Wire.T_DISCOVER_QUERY)) {
                    handleQuery(packet);
                } else if (type.equals(Wire.T_DISCOVER_REPLY)) {
                    var reply = Wire.parseDiscoverReply(root);
                    if (reply.expiresAt() > System.currentTimeMillis()) {
                        replySink.onReply(reply, packet.getAddress());
                    }
                }
            } catch (Errors.OcException | IOException e) {
                // Malformed datagrams are dropped; the socket keeps serving.
                LOG.log(Level.FINE, "discovery receive skipped: {0}", e.getMessage());
            } catch (RuntimeException e) {
                LOG.log(Level.FINE, "discovery receive error", e);
            }
        }
    }

    private void handleQuery(DatagramPacket packet) {
        if (!discoverable.getAsBoolean() || !connectable.getAsBoolean()) {
            return; // configured invisible: stay silent
        }
        try {
            var query = Wire.parseDiscoverQuery(Json.parse(
                    java.util.Arrays.copyOf(packet.getData(), packet.getLength())));
            String name = username.get();
            String fp = fingerprint.get();
            if (name == null || fp == null) {
                return;
            }
            JsonNode reply = Wire.discoverReply(query.id(), name, tcpPort.get(), fp,
                    System.currentTimeMillis() + ttlMillis);
            byte[] payload = Json.writeBytes(reply);
            socket.send(new DatagramPacket(payload, payload.length,
                    packet.getAddress(), packet.getPort()));
        } catch (Errors.OcException | IOException e) {
            LOG.log(Level.FINE, "discovery reply failed: {0}", e.getMessage());
        }
    }

    public boolean available() {
        return running.get() && socket != null;
    }

    @Override
    public void close() {
        running.set(false);
        if (socket != null) {
            socket.close();
        }
    }
}
