package org.ourcamellia.core.server;

import org.ourcamellia.common.config.ClientConfig;
import org.ourcamellia.common.config.ServerConfig;
import org.ourcamellia.core.app.ClientApp;
import org.ourcamellia.core.persist.ClientStateStore;
import org.ourcamellia.core.persist.LocalHistoryStore;

import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertTrue;

/** Test harness: a running server plus client apps connected to it. */
final class ServerTestHarness {

    final ServerCore server;
    final ServerEventsRecorder events;
    final Path dir;
    final int port;
    final ServerConfig config;

    static ServerTestHarness start(Path dir, int port, java.util.function.Function<ServerConfig, ServerConfig> tweak) {
        ServerConfig cfg = tweak.apply(baseConfig(port, dir));
        cfg.validated();
        ServerEventsRecorder events = new ServerEventsRecorder();
        ServerStateStore store = new ServerStateStore(dir);
        ServerCore core = new ServerCore(cfg, store, events);
        core.start();
        return new ServerTestHarness(core, events, dir, port, cfg);
    }

    private ServerTestHarness(ServerCore server, ServerEventsRecorder events, Path dir, int port,
                              ServerConfig config) {
        this.server = server;
        this.events = events;
        this.dir = dir;
        this.port = port;
        this.config = config;
    }

    static ServerConfig baseConfig(int port, Path dataDir) {
        ServerConfig d = ServerConfig.defaults();
        return new ServerConfig("127.0.0.1", port, "Test Server", dataDir.toString(), true,
                "tls/keystore.p12", "", d.requiredRegistrationFields(), true, "auto",
                d.pendingTtlMinutes(), d.verifier(), d.notificationRetentionDays(), true,
                d.botApi(), d.rateLimits(), List.of("@admin"), 12_000,
                d.reviewLogRetention(), d.maxFrameBytes(), 5000, 30_000, 2000, "off");
    }

    static ServerConfig withPolicy(ServerConfig base, String policy) {
        return new ServerConfig(base.bindHost(), base.port(), base.serverName(), base.dataDir(),
                base.tlsAutoGenerate(), base.tlsKeystorePath(), base.tlsKeystorePassword(),
                base.requiredRegistrationFields(), base.requireEmail(), policy,
                base.pendingTtlMinutes(), base.verifier(), base.notificationRetentionDays(),
                base.encryptedGroupsAllowed(), base.botApi(), base.rateLimits(),
                base.adminUsernames(), base.passwordHashIterations(), base.reviewLogRetention(),
                base.maxFrameBytes(), base.connectTimeoutMs(), base.readTimeoutMs(),
                base.pingIntervalMs(), base.logLevel());
    }

    /** A client app in Server mode, connected to the harness server. */
    static ServerClient client(String dataDirName, Path parentDir, int listenPort, String address) {
        Path dir = parentDir.resolve(dataDirName);
        ClientConfig cfg = new ClientConfig("old", dir.toString(), true, true, false,
                "127.0.0.1", listenPort, listenPort + 500, 60, 5000, 30_000, 2000,
                1 << 20, false, 12_000, true, "off");
        ClientEventsRecorder events = new ClientEventsRecorder();
        ClientStateStore store = new ClientStateStore(dir);
        LocalHistoryStore history = new LocalHistoryStore(dir.resolve("history"), true, null, 12_000);
        ClientApp app = new ClientApp(cfg, store, history, events, dir);
        app.connectServer(address);
        return new ServerClient(app, events);
    }

    static final class ServerClient {
        final ClientApp app;
        final ClientEventsRecorder events;

        ServerClient(ClientApp app, ClientEventsRecorder events) {
            this.app = app;
            this.events = events;
        }

        void close() {
            app.close();
        }
    }

    static final class ServerEventsRecorder implements ServerEvents {
        final ConcurrentLinkedQueue<String> infos = new ConcurrentLinkedQueue<>();
        final ConcurrentLinkedQueue<String> audits = new ConcurrentLinkedQueue<>();

        @Override
        public void onInfo(String line) {
            infos.add(line);
        }

        @Override
        public void onAudit(String line) {
            audits.add(line);
        }
    }

    static final class ClientEventsRecorder implements org.ourcamellia.core.app.AppEvents {
        final ConcurrentLinkedQueue<String> infos = new ConcurrentLinkedQueue<>();
        final ConcurrentLinkedQueue<org.ourcamellia.common.domain.Message> messages =
                new ConcurrentLinkedQueue<>();

        @Override
        public void onMessage(org.ourcamellia.common.domain.ConversationRef conversation,
                              org.ourcamellia.common.domain.Message message) {
            messages.add(message);
        }

        @Override
        public void onStatusChanged() {
        }

        @Override
        public void onNotificationsChanged() {
        }

        @Override
        public void onInfo(String text) {
            infos.add(text);
        }

        @Override
        public void onPeerStatus(String peerName, org.ourcamellia.common.domain.PeerStatus status) {
        }

        @Override
        public void onShutdown() {
        }

        /** Polls until at least one info line arrived. */
        boolean awaitInfo(long ms) throws InterruptedException {
            long deadline = System.currentTimeMillis() + ms;
            while (infos.isEmpty() && System.currentTimeMillis() < deadline) {
                Thread.sleep(10);
            }
            return !infos.isEmpty();
        }

        /** Polls until at least one message arrived. */
        boolean awaitMessage(long ms) throws InterruptedException {
            long deadline = System.currentTimeMillis() + ms;
            while (messages.isEmpty() && System.currentTimeMillis() < deadline) {
                Thread.sleep(10);
            }
            return !messages.isEmpty();
        }
    }

    static boolean waitFor(java.util.function.BooleanSupplier condition, long timeoutMs)
            throws InterruptedException {
        long deadline = System.currentTimeMillis() + timeoutMs;
        while (System.currentTimeMillis() < deadline) {
            if (condition.getAsBoolean()) {
                return true;
            }
            Thread.sleep(25);
        }
        return condition.getAsBoolean();
    }
}
