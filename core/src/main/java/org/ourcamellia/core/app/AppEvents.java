package org.ourcamellia.core.app;

import org.ourcamellia.common.domain.ConversationRef;
import org.ourcamellia.common.domain.Message;
import org.ourcamellia.common.domain.Notification;
import org.ourcamellia.common.domain.PeerStatus;

/**
 * Sink for asynchronous application events. The CLI presentation layers (Observatory
 * and Old) implement this; the application layer never touches the terminal.
 * Implementations must be thread-safe (network threads call them).
 */
public interface AppEvents {

    /** A message arrived (inbound) or was confirmed sent (outbound). */
    void onMessage(ConversationRef conversation, Message message);

    /** Conversation list, status region, or peer status changed. */
    void onStatusChanged();

    /** Notification set changed (new, acted on, dismissed, expired). */
    void onNotificationsChanged();

    /** A transient informational line for the UI (errors, confirmations). */
    void onInfo(String text);

    /** Observer-relative status of one peer changed. */
    void onPeerStatus(String peerName, PeerStatus status);

    /** The application is shutting down (UI should stop reading input). */
    void onShutdown();
}
