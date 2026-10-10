package org.ourcamellia.server;

import org.ourcamellia.common.Errors;
import org.ourcamellia.common.config.ConfigLoader;
import org.ourcamellia.common.config.ServerConfig;
import org.ourcamellia.core.server.ServerCore;
import org.ourcamellia.core.server.ServerStateStore;
import org.ourcamellia.core.util.RedactingLog;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/** Server executable entry point. */
public final class ServerMain {

    public static void main(String[] args) {
        int code = run(args);
        System.exit(code);
    }

    static int run(String[] args) {
        try {
            String configPath = null;
            String dataDir = null;
            boolean genkey = false;
            for (int i = 0; i < args.length; i++) {
                switch (args[i]) {
                    case "--help", "-h" -> {
                        System.out.println(usage());
                        return 0;
                    }
                    case "genkey" -> genkey = true;
                    case "--config" -> configPath = value(args, ++i);
                    case "--data-dir" -> dataDir = value(args, ++i);
                    case "run" -> {
                    }
                    default -> {
                        System.err.println("unknown argument: " + args[i]);
                        System.err.println(usage());
                        return 2;
                    }
                }
            }
            Path dir = Path.of(dataDir != null ? dataDir : ServerConfig.defaults().dataDir());
            Path configFile = configPath != null ? Path.of(configPath) : dir.resolve("server.json");
            List<String> warnings = new ArrayList<>();
            ServerConfig config = ConfigLoader.load(configFile, ServerConfig.class,
                    ServerConfig.defaults(), warnings::add).validated();
            warnings.forEach(w -> System.err.println("config warning: " + w));
            if (dataDir != null) {
                config = withDataDir(config, dataDir);
            }
            // The config file's dataDir (or the flag override) is authoritative.
            dir = Path.of(config.dataDir());
            RedactingLog.configure(dir.resolve("logs"), config.logLevel());
            if (genkey) {
                generateKey(config, dir);
                return 0;
            }
            ServerStateStore store = new ServerStateStore(dir);
            ServerCore server = new ServerCore(config, store, new org.ourcamellia.core.server.ServerEvents() {
                @Override
                public void onInfo(String line) {
                    System.out.println("[server] " + line);
                }

                @Override
                public void onAudit(String line) {
                    System.out.println("[audit] " + line);
                }
            });
            server.start();
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                try {
                    server.close();
                } catch (RuntimeException ignored) {
                }
            }));
            // The console drives shutdown when stdin is interactive; when stdin is
            // redirected/closed, the server keeps running (daemon mode) until SIGTERM.
            ServerConsole console = new ServerConsole(server, System.in, System.out);
            console.run();
            if (console.quitRequested()) {
                server.close();
            }
            return 0;
        } catch (Errors.Usage e) {
            System.err.println("usage error: " + e.getMessage());
            return 2;
        } catch (Errors.OcException e) {
            System.err.println("error: " + e.getMessage());
            return 1;
        }
    }

    private static void generateKey(ServerConfig config, Path dir) {
        var generated = org.ourcamellia.common.SelfSignedCerts.generate("ourcamellia-server", 3650);
        Path ks = dir.resolve(config.tlsKeystorePath());
        try {
            java.nio.file.Files.createDirectories(ks.toAbsolutePath().getParent());
        } catch (java.io.IOException e) {
            System.err.println("cannot create keystore directory: " + e.getMessage());
            System.exit(1);
        }
        String password = config.tlsKeystorePassword().isBlank()
                ? org.ourcamellia.common.CryptoUtil.randomHex(16) : config.tlsKeystorePassword();
        org.ourcamellia.common.SelfSignedCerts.saveKeystore(ks, generated.cert(), generated.key(), password);
        System.out.println("generated TLS identity: " + ks);
        System.out.println("fingerprint: " + generated.fingerprint());
        System.out.println("keystore password: " + password + " (set tlsKeystorePassword in the config, or keep the auto-generated tls/keystore.password file)");
    }

    private static ServerConfig withDataDir(ServerConfig c, String dataDir) {
        return new ServerConfig(c.bindHost(), c.port(), c.serverName(), dataDir,
                c.tlsAutoGenerate(), c.tlsKeystorePath(), c.tlsKeystorePassword(),
                c.requiredRegistrationFields(), c.requireEmail(), c.registrationPolicy(),
                c.pendingTtlMinutes(), c.verifier(), c.notificationRetentionDays(),
                c.encryptedGroupsAllowed(), c.botApi(), c.rateLimits(), c.adminUsernames(),
                c.passwordHashIterations(), c.reviewLogRetention(), c.maxFrameBytes(),
                c.connectTimeoutMs(), c.readTimeoutMs(), c.pingIntervalMs(), c.logLevel());
    }

    private static String value(String[] args, int i) {
        if (i >= args.length) {
            System.err.println("missing value for " + args[i - 1]);
            System.exit(2);
        }
        return args[i];
    }

    static String usage() {
        return """
                ourcamellia-server — Ourcamellia independent community server
                usage: ourcamellia-server run [--config path] [--data-dir path]
                       ourcamellia-server genkey [--config path] [--data-dir path]
                  --config path   JSON config file (default: <data-dir>/server.json)
                  --data-dir path data directory (default: ./data)
                """;
    }
}
