package org.ourcamellia.client;

import org.ourcamellia.common.Errors;
import org.ourcamellia.common.config.ClientConfig;
import org.ourcamellia.common.config.ConfigLoader;
import org.ourcamellia.core.app.ClientApp;
import org.ourcamellia.core.app.ClientAppFactory;
import org.ourcamellia.core.persist.ClientStateStore;
import org.ourcamellia.core.persist.LocalHistoryStore;
import org.ourcamellia.core.util.RedactingLog;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/** Argument parsing and application wiring shared by both presentation modes. */
public final class CliSupport {

    public static final int EXIT_OK = 0;
    public static final int EXIT_ERROR = 1;
    public static final int EXIT_USAGE = 2;

    public record Options(String configPath, String dataDir, String mode) {}

    private CliSupport() {}

    public static Options parseArgs(String[] args) {
        String configPath = null;
        String dataDir = null;
        String mode = null;
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--help", "-h" -> {
                    System.out.println(usage());
                    System.exit(EXIT_OK);
                }
                case "--config" -> configPath = requireValue(args, ++i);
                case "--data-dir" -> dataDir = requireValue(args, ++i);
                case "--mode" -> mode = requireValue(args, ++i);
                default -> {
                    System.err.println("unknown argument: " + args[i]);
                    System.err.println(usage());
                    System.exit(EXIT_USAGE);
                }
            }
        }
        return new Options(configPath, dataDir, mode);
    }

    private static String requireValue(String[] args, int i) {
        if (i >= args.length) {
            System.err.println("missing value for " + args[i - 1]);
            System.err.println(usage());
            System.exit(EXIT_USAGE);
        }
        return args[i];
    }

    public static String usage() {
        return """
                ourcamellia-client — Ourcamellia command-line client
                usage: ourcamellia-client [--config path] [--data-dir path] [--mode auto|old|observatory]
                  --config path   JSON config file (default: <data-dir>/config.json)
                  --data-dir path data directory (default: ~/.ourcamellia)
                  --mode          presentation mode; auto picks observatory on a real terminal
                """;
    }

    /** Loads the effective configuration only (no stores are created). */
    public static ClientConfig loadConfigOnly(Options options) {
        Path dataDir = Path.of(options.dataDir() != null
                ? options.dataDir() : ClientConfig.defaults().dataDir());
        Path configFile = options.configPath() != null
                ? Path.of(options.configPath()) : dataDir.resolve("config.json");
        List<String> warnings = new ArrayList<>();
        ClientConfig config = ConfigLoader.load(configFile, ClientConfig.class,
                ClientConfig.defaults(), warnings::add).validated();
        warnings.forEach(w -> System.err.println("config warning: " + w));
        if (options.dataDir() != null) {
            config = withDataDir(config, options.dataDir());
        }
        if (options.mode() != null) {
            config = withMode(config, options.mode());
        }
        return config;
    }

    /** Loads config + stores and builds the ClientApp. */
    public static Launch launch(Options options, String secondaryPassword) {
        ClientConfig config = loadConfigOnly(options);
        Path dataDir = Path.of(config.dataDir());
        try {
            java.nio.file.Files.createDirectories(dataDir);
        } catch (java.io.IOException e) {
            System.err.println("cannot create data directory " + dataDir + ": " + e.getMessage());
            System.exit(EXIT_ERROR);
        }
        RedactingLog.configure(dataDir.resolve("logs"), config.logLevel());
        ClientStateStore store = new ClientStateStore(dataDir);
        LocalHistoryStore history = new LocalHistoryStore(dataDir.resolve("history"),
                config.defaultRecording(), secondaryPassword, config.secondaryPasswordIterations());
        ClientApp app = ClientAppFactory.create(config, store, history, dataDir);
        return new Launch(config, dataDir, app);
    }

    public record Launch(ClientConfig config, Path dataDir, ClientApp app) {}

    private static ClientConfig withDataDir(ClientConfig c, String dataDir) {
        return new ClientConfig(c.mode(), dataDir, c.defaultRecording(), c.discoverable(),
                c.connectable(), c.listenHost(), c.listenPort(), c.discoveryPort(),
                c.discoveryTtlSeconds(), c.connectTimeoutMs(), c.readTimeoutMs(),
                c.pingIntervalMs(), c.maxFrameBytes(), c.secondaryPasswordProtectHistory(),
                c.secondaryPasswordIterations(), c.exitPromptOnBuffered(), c.logLevel());
    }

    private static ClientConfig withMode(ClientConfig c, String mode) {
        if (!mode.equals("auto") && !mode.equals("old") && !mode.equals("observatory")) {
            throw new Errors.Usage("--mode must be auto, old, or observatory");
        }
        return new ClientConfig(mode, c.dataDir(), c.defaultRecording(), c.discoverable(),
                c.connectable(), c.listenHost(), c.listenPort(), c.discoveryPort(),
                c.discoveryTtlSeconds(), c.connectTimeoutMs(), c.readTimeoutMs(),
                c.pingIntervalMs(), c.maxFrameBytes(), c.secondaryPasswordProtectHistory(),
                c.secondaryPasswordIterations(), c.exitPromptOnBuffered(), c.logLevel());
    }
}
