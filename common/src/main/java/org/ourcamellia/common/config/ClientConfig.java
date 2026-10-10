package org.ourcamellia.common.config;

import org.ourcamellia.common.Errors;

import java.nio.file.Path;
import java.util.Map;

/** Client configuration with safe defaults (REQUIREMENTS §9). */
public record ClientConfig(
        String mode,                       // "observatory" | "old" | "auto" (default: auto → tty-based)
        String dataDir,                    // default: ~/.ourcamellia
        boolean defaultRecording,          // automatic history recording for new conversations
        boolean discoverable,              // Local mode: respond to discovery queries
        boolean connectable,               // Local mode: accept inbound connections
        String listenHost,
        int listenPort,
        int discoveryPort,
        int discoveryTtlSeconds,
        int connectTimeoutMs,
        int readTimeoutMs,
        int pingIntervalMs,
        int maxFrameBytes,
        boolean secondaryPasswordProtectHistory,
        int secondaryPasswordIterations,
        boolean exitPromptOnBuffered,
        String logLevel) {

    public static ClientConfig defaults() {
        return new ClientConfig(
                "auto",
                defaultDataDir(),
                true,
                true,
                true,
                "0.0.0.0",
                54536,
                54535,
                60,
                10_000,
                90_000,
                30_000,
                1 << 20,
                false,
                210_000,
                true,
                "info");
    }

    private static String defaultDataDir() {
        String home = System.getProperty("user.home");
        return (home == null ? "." : home) + java.io.File.separator + ".ourcamellia";
    }

    public ClientConfig validated() {
        if (mode != null && !mode.equals("auto") && !mode.equals("observatory") && !mode.equals("old")) {
            throw new Errors.Validation("config: mode must be auto|observatory|old");
        }
        if (listenPort < 1 || listenPort > 65535 || discoveryPort < 1 || discoveryPort > 65535) {
            throw new Errors.Validation("config: invalid port");
        }
        if (listenPort == discoveryPort) {
            throw new Errors.Validation("config: listenPort and discoveryPort must differ");
        }
        if (maxFrameBytes < 1024 || maxFrameBytes > 1 << 24) {
            throw new Errors.Validation("config: maxFrameBytes out of range");
        }
        if (secondaryPasswordIterations < 10_000) {
            throw new Errors.Validation("config: secondaryPasswordIterations too low");
        }
        return this;
    }

    public Path dataDirPath() {
        return Path.of(dataDir);
    }
}
