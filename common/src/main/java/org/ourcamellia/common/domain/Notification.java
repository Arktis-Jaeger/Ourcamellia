package org.ourcamellia.common.domain;

/** A durable notification. IDs are stable; state transitions are explicit. */
public record Notification(
        String id,
        NotificationKind kind,
        NotificationState state,
        String from,        // display name of origin ("@alice", server name, "system")
        String text,
        long createdAt,
        long expiresAt,     // 0 = never
        String refId) {     // referenced entity (friend request id, announcement id, ...)

    public boolean isExpired(long now) {
        return expiresAt > 0 && now > expiresAt;
    }

    public Notification withState(NotificationState s) {
        return new Notification(id, kind, s, from, text, createdAt, expiresAt, refId);
    }
}
