package org.ourcamellia.core.transport;

import org.ourcamellia.common.Errors;
import org.ourcamellia.common.protocol.Envelope;
import org.ourcamellia.common.protocol.FrameCodec;

import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.concurrent.atomic.AtomicBoolean;

/** Conn implementation over a TLS (or raw test) socket. */
public final class SocketConn implements ReadableConn {

    private final java.net.Socket socket;
    private final InputStream in;
    private final OutputStream out;
    private final FrameCodec codec;
    private final String description;
    private final String fingerprint;
    private final AtomicBoolean open = new AtomicBoolean(true);
    private final Object sendLock = new Object();

    public SocketConn(java.net.Socket socket, String description, String fingerprint, int maxFrame) throws IOException {
        this.socket = socket;
        this.in = socket.getInputStream();
        this.out = socket.getOutputStream();
        this.codec = new FrameCodec(maxFrame);
        this.description = description;
        this.fingerprint = fingerprint;
    }

    @Override
    public void send(Envelope envelope) {
        if (!open.get()) {
            throw new Errors.Network("connection closed");
        }
        synchronized (sendLock) {
            codec.write(out, envelope.root());
        }
    }

    /** Returns the raw stream reader used by the session thread. */
    @Override
    public InputStream inputStream() {
        return in;
    }

    @Override
    public FrameCodec codec() {
        return codec;
    }

    @Override
    public void setSoTimeout(int ms) {
        try {
            socket.setSoTimeout(ms);
        } catch (IOException ignored) {
        }
    }

    @Override
    public boolean isOpen() {
        return open.get() && !socket.isClosed();
    }

    @Override
    public String remoteDescription() {
        return description;
    }

    @Override
    public String remoteFingerprint() {
        return fingerprint;
    }

    @Override
    public void close() {
        if (open.getAndSet(false)) {
            try {
                socket.close();
            } catch (IOException ignored) {
            }
        }
    }
}
