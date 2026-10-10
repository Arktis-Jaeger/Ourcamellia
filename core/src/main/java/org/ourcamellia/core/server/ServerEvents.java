package org.ourcamellia.core.server;

/** Sink for server-side operational events (console output and audit log). */
public interface ServerEvents {

    void onInfo(String line);

    /** Audit-worthy administrative action (no secrets, no message content beyond ids). */
    void onAudit(String line);
}
