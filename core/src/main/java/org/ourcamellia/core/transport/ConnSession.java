package org.ourcamellia.core.transport;

import org.ourcamellia.common.Errors;
import org.ourcamellia.common.protocol.Envelope;
import org.ourcamellia.common.protocol.Wire;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * One live connection: owns the reader thread (a virtual thread), the heartbeat
 * (ping/pong), read-timeout enforcement, and the handler dispatch. Sends are
 * synchronized through {@link Conn}. Malformed frames or protocol violations close
 * the connection; routine disconnects never crash the process.
 */
public final class ConnSession implements AutoCloseable {

    public interface Handler {
        void onEnvelope(Conn conn, Envelope envelope);

        void onClosed(Conn conn, String reason);
    }

    private static final Logger LOG = Logger.getLogger(ConnSession.class.getName());

    private final ReadableConn conn;
    private final Handler handler;
    private final int pingIntervalMs;
    private final int readTimeoutMs;
    private final AtomicBoolean closed = new AtomicBoolean(false);
    private final Thread reader;
    private volatile long lastReadAt = System.currentTimeMillis();

    public ConnSession(ReadableConn conn, Handler handler, int pingIntervalMs, int readTimeoutMs) {
        this.conn = conn;
        this.handler = handler;
        this.pingIntervalMs = pingIntervalMs;
        this.readTimeoutMs = readTimeoutMs;
        conn.setSoTimeout(Math.max(1000, pingIntervalMs));
        this.reader = Thread.ofVirtual().name("conn-" + conn.remoteDescription()).start(this::readLoop);
    }

    public ReadableConn conn() {
        return conn;
    }

    private void readLoop() {
        String reason = "connection closed";
        try {
            while (conn.isOpen()) {
                Envelope e;
                try {
                    var node = conn.codec().read(conn.inputStream());
                    lastReadAt = System.currentTimeMillis();
                    if (node == null) {
                        reason = "remote closed connection";
                        break;
                    }
                    e = Envelope.of(node);
                } catch (Errors.FrameTimeout timeout) {
                    long now = System.currentTimeMillis();
                    if (now - lastReadAt > readTimeoutMs) {
                        reason = "read timeout";
                        break;
                    }
                    try {
                        conn.send(Wire.ping());
                    } catch (Errors.OcException sendFailure) {
                        reason = "send failed";
                        break;
                    }
                    continue;
                }
                if (e.type().equals(Wire.T_PING)) {
                    conn.send(Wire.pong(e.id()));
                    continue;
                }
                if (e.type().equals(Wire.T_PONG)) {
                    continue;
                }
                if (e.type().equals(Wire.T_BYE)) {
                    reason = "remote said goodbye";
                    break;
                }
                try {
                    handler.onEnvelope(conn, e);
                } catch (Errors.Malformed bad) {
                    LOG.log(Level.WARNING, "malformed frame from {0}: {1}",
                            new Object[]{conn.remoteDescription(), bad.getMessage()});
                    reason = "malformed frame";
                    break;
                }
            }
        } catch (Errors.Malformed e) {
            LOG.log(Level.WARNING, "protocol violation from {0}: {1}",
                    new Object[]{conn.remoteDescription(), e.getMessage()});
            reason = "protocol violation";
        } catch (Errors.Network e) {
            reason = "connection lost";
        } catch (Throwable t) {
            LOG.log(Level.WARNING, "unexpected connection error from " + conn.remoteDescription(), t);
            reason = "internal error";
        } finally {
            close(reason);
        }
    }

    public boolean isOpen() {
        return conn.isOpen();
    }

    @Override
    public void close() {
        close("closed locally");
    }

    private void close(String reason) {
        if (closed.getAndSet(true)) {
            return;
        }
        conn.close();
        try {
            handler.onClosed(conn, reason);
        } catch (RuntimeException e) {
            LOG.log(Level.FINE, "onClosed handler failed", e);
        }
    }
}
