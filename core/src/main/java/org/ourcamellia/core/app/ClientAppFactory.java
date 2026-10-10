package org.ourcamellia.core.app;

import org.ourcamellia.common.config.ClientConfig;
import org.ourcamellia.core.persist.ClientStateStore;
import org.ourcamellia.core.persist.LocalHistoryStore;

import java.nio.file.Path;

/**
 * Factory that lets the CLI inject the application events AFTER construction but
 * before any UI starts. Kept in core so tests and embedding code share one path.
 */
public final class ClientAppFactory {

    private ClientAppFactory() {}

    public static ClientApp create(ClientConfig config, ClientStateStore store,
                                   LocalHistoryStore history, Path dataDir) {
        return new ClientApp(config, store, history, new AppEvents() {
            @Override
            public void onMessage(org.ourcamellia.common.domain.ConversationRef conversation,
                                  org.ourcamellia.common.domain.Message message) {
                // Events are attached by the UI before the run loop starts.
            }

            @Override
            public void onStatusChanged() {
            }

            @Override
            public void onNotificationsChanged() {
            }

            @Override
            public void onInfo(String text) {
            }

            @Override
            public void onPeerStatus(String peerName, org.ourcamellia.common.domain.PeerStatus status) {
            }

            @Override
            public void onShutdown() {
            }
        }, dataDir);
    }

    /** Replaces the event sink (called once by the CLI before the run loop). */
    public static void attachEvents(ClientApp app, AppEvents events) {
        app.attachEvents(events);
    }
}
