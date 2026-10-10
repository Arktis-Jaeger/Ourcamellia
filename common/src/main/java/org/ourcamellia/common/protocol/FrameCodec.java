package org.ourcamellia.common.protocol;

import org.ourcamellia.common.Errors;
import org.ourcamellia.common.Json;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;

/**
 * Length-prefixed JSON framing over a byte stream (TLS sockets in production,
 * in-memory pipes in tests).
 *
 * Frame: 4-byte big-endian length N (1..maxFrame) followed by N UTF-8 JSON bytes.
 * The length bound is the resource-exhaustion defense; anything outside the bound is
 * rejected with a Malformed error and the connection is treated as hostile.
 */
public final class FrameCodec {

    public static final int DEFAULT_MAX_FRAME = 1 << 20; // 1 MiB

    private final int maxFrame;

    public FrameCodec(int maxFrame) {
        if (maxFrame < 1024 || maxFrame > (1 << 24)) {
            throw new IllegalArgumentException("maxFrame out of range");
        }
        this.maxFrame = maxFrame;
    }

    public FrameCodec() {
        this(DEFAULT_MAX_FRAME);
    }

    public void write(OutputStream out, Object payload) {
        byte[] bytes = Json.writeBytes(payload);
        if (bytes.length > maxFrame) {
            throw new Errors.Malformed("frame too large");
        }
        try {
            out.write(new byte[]{
                    (byte) (bytes.length >>> 24),
                    (byte) (bytes.length >>> 16),
                    (byte) (bytes.length >>> 8),
                    (byte) bytes.length});
            out.write(bytes);
            out.flush();
        } catch (IOException e) {
            throw new Errors.Network("connection write failed", e);
        }
    }

    /** Reads one complete frame; returns null on clean EOF, throws on malformed input. */
    public com.fasterxml.jackson.databind.JsonNode read(InputStream in) {
        byte[] lenBuf = readFully(in, 4);
        if (lenBuf == null) {
            return null; // clean EOF
        }
        int len = ((lenBuf[0] & 0xFF) << 24) | ((lenBuf[1] & 0xFF) << 16)
                | ((lenBuf[2] & 0xFF) << 8) | (lenBuf[3] & 0xFF);
        if (len <= 0 || len > maxFrame) {
            throw new Errors.Malformed("frame length out of bounds");
        }
        byte[] body = readFully(in, len);
        if (body == null) {
            throw new Errors.Malformed("truncated frame");
        }
        return Json.parse(body);
    }

    private static byte[] readFully(InputStream in, int n) {
        byte[] buf = new byte[n];
        int off = 0;
        while (off < n) {
            int r;
            try {
                r = in.read(buf, off, n - off);
            } catch (java.net.SocketTimeoutException e) {
                throw new Errors.FrameTimeout();
            } catch (IOException e) {
                throw new Errors.Network("connection read failed", e);
            }
            if (r < 0) {
                if (off == 0) {
                    return null;
                }
                throw new Errors.Malformed("truncated frame");
            }
            off += r;
        }
        return buf;
    }
}
