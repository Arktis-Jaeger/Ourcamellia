package org.ourcamellia.core.transport;

import org.ourcamellia.common.Errors;
import org.ourcamellia.common.protocol.Envelope;
import org.ourcamellia.common.protocol.FrameCodec;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * In-memory connected pair for protocol tests: two {@link ReadableConn}s whose
 * streams are wired to each other. Not production code — used by tests and by the
 * embedded (in-process) BOT adapter.
 */
public final class InMemoryLink {

    private InMemoryLink() {}

    public static Pair create(String nameA, String nameB, int maxFrame) {
        try {
            PipedInputStream aIn = new PipedInputStream(1 << 20);
            PipedOutputStream aOut = new PipedOutputStream(aIn);
            PipedInputStream bIn = new PipedInputStream(1 << 20);
            PipedOutputStream bOut = new PipedOutputStream(bIn);
            RawConn a = new RawConn(nameA, aIn, aOut, maxFrame);
            RawConn b = new RawConn(nameB, bIn, bOut, maxFrame);
            return new Pair(a, b);
        } catch (IOException e) {
            throw new Errors.Internal("cannot create in-memory link", e);
        }
    }

    public record Pair(ReadableConn a, ReadableConn b) {}

    /** Conn over piped streams; no TLS (test/embedding only). */
    public static final class RawConn implements ReadableConn {
        private final String name;
        private final InputStream in;
        private final OutputStream out;
        private final FrameCodec codec;
        private final AtomicBoolean open = new AtomicBoolean(true);

        RawConn(String name, InputStream in, OutputStream out, int maxFrame) {
            this.name = name;
            this.in = in;
            this.out = out;
            this.codec = new FrameCodec(maxFrame);
        }

        @Override
        public synchronized void send(Envelope envelope) {
            if (!open.get()) {
                throw new Errors.Network("connection closed");
            }
            codec.write(out, envelope.root());
        }

        @Override
        public InputStream inputStream() {
            return in;
        }

        @Override
        public FrameCodec codec() {
            return codec;
        }

        @Override
        public boolean isOpen() {
            return open.get();
        }

        @Override
        public String remoteDescription() {
            return name;
        }

        @Override
        public String remoteFingerprint() {
            return null;
        }

        @Override
        public void close() {
            open.set(false);
        }
    }
}
