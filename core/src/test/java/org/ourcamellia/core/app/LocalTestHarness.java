package org.ourcamellia.core.app;

import org.ourcamellia.common.config.ClientConfig;
import org.ourcamellia.common.domain.ConversationRef;
import org.ourcamellia.common.domain.Message;
import org.ourcamellia.common.domain.PeerStatus;
import org.ourcamellia.core.persist.ClientStateStore;
import org.ourcamellia.core.persist.LocalHistoryStore;

import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/** Test harness: a full client application in Local mode with recorded events. */
final class LocalTestHarness {

    final ClientApp app;
    final RecordingEvents events;
    final Path dir;
    final int port;

    static LocalTestHarness create(String name, int port, Path dir) {
        ClientConfig cfg = withPort(ClientConfig.defaults(), port);
        RecordingEvents events = new RecordingEvents();
        ClientStateStore store = new ClientStateStore(dir);
        LocalHistoryStore history = new LocalHistoryStore(dir.resolve("history"), true, null, 12_000);
        ClientApp app = new ClientApp(cfg, store, history, events, dir);
        app.enterLocal(name);
        return new LocalTestHarness(app, events, dir, port);
    }

    private LocalTestHarness(ClientApp app, RecordingEvents events, Path dir, int port) {
        this.app = app;
        this.events = events;
        this.dir = dir;
        this.port = port;
    }

    static ClientConfig withPort(ClientConfig base, int port) {
        return new ClientConfig(base.mode(), base.dataDir(), base.defaultRecording(),
                base.discoverable(), base.connectable(), base.listenHost(), port,
                port + 1000, base.discoveryTtlSeconds(), 5000, 30_000, 2000,
                base.maxFrameBytes(), base.secondaryPasswordProtectHistory(),
                base.secondaryPasswordIterations(), base.exitPromptOnBuffered(), base.logLevel());
    }

    /** A client whose connectable flag can be set false after construction. */
    static LocalTestHarness createNonConnectable(String name, int port, Path dir) {
        LocalTestHarness h = create(name, port, dir);
        h.app.setConnectable(false);
        return h;
    }

    void close() {
        app.close();
    }

    static final class RecordingEvents implements AppEvents {
        final ConcurrentLinkedQueue<Message> messages = new ConcurrentLinkedQueue<>();
        final ConcurrentLinkedQueue<String> infos = new ConcurrentLinkedQueue<>();
        final ConcurrentLinkedQueue<String> statusChanges = new ConcurrentLinkedQueue<>();

        @Override
        public void onMessage(ConversationRef conversation, Message message) {
            messages.add(message);
        }

        @Override
        public void onStatusChanged() {
            statusChanges.add("status");
        }

        @Override
        public void onNotificationsChanged() {
        }

        @Override
        public void onInfo(String text) {
            infos.add(text);
        }

        @Override
        public void onPeerStatus(String peerName, PeerStatus status) {
            statusChanges.add(peerName + "=" + status);
        }

        @Override
        public void onShutdown() {
        }

        /** Polls until at least one message arrived (avoids latch/count races). */
        boolean awaitMessage(long ms) throws InterruptedException {
            long deadline = System.currentTimeMillis() + ms;
            while (messages.isEmpty() && System.currentTimeMillis() < deadline) {
                Thread.sleep(10);
            }
            return !messages.isEmpty();
        }

        boolean awaitInfoContaining(String text, long ms) throws InterruptedException {
            long deadline = System.currentTimeMillis() + ms;
            while (System.currentTimeMillis() < deadline) {
                if (infos.stream().anyMatch(t -> t.contains(text))) {
                    return true;
                }
                Thread.sleep(10);
            }
            return infos.stream().anyMatch(t -> t.contains(text));
        }

        List<Message> messagesList() {
            return List.copyOf(messages);
        }
    }
}
