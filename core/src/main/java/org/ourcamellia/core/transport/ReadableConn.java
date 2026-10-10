package org.ourcamellia.core.transport;

import org.ourcamellia.common.protocol.FrameCodec;

import java.io.InputStream;

/** A Conn that can also be read from directly (used by the session reader thread). */
public interface ReadableConn extends Conn {

    InputStream inputStream();

    FrameCodec codec();

    /** Sets the read timeout used to drive the heartbeat; no-op for non-socket links. */
    default void setSoTimeout(int ms) {
    }
}
