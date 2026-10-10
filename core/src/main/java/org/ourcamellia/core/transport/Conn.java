package org.ourcamellia.core.transport;

import org.ourcamellia.common.protocol.Envelope;

/** A framed, authenticated connection to a peer or server. */
public interface Conn extends AutoCloseable {

    /** Sends one envelope; throws Network on failure. Thread-safe. */
    void send(Envelope envelope);

    /** True while the connection is usable. */
    boolean isOpen();

    /** Human-readable remote address description (for status display, never logged with secrets). */
    String remoteDescription();

    /** TLS certificate fingerprint of the remote side, or null for non-TLS (test) links. */
    String remoteFingerprint();

    @Override
    void close();
}
