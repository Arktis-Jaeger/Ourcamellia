package org.ourcamellia.common.config;

import org.ourcamellia.common.Errors;

import java.nio.file.Path;
import java.util.List;

/** Server configuration with safe defaults (REQUIREMENTS §9). */
public record ServerConfig(
        String bindHost,
        int port,
        String serverName,
        String dataDir,
        boolean tlsAutoGenerate,
        String tlsKeystorePath,
        String tlsKeystorePassword,      // empty = generate a random one at first run
        List<String> requiredRegistrationFields,  // fixed core: @UserName, Passwd; extendable
        boolean requireEmail,
        String registrationPolicy,       // auto | manual | external
        int pendingTtlMinutes,
        VerifierConfig verifier,
        int notificationRetentionDays,
        boolean encryptedGroupsAllowed,
        BotApiConfig botApi,
        RateLimitConfig rateLimits,
        List<String> adminUsernames,
        int passwordHashIterations,
        int reviewLogRetention,
        int maxFrameBytes,
        int connectTimeoutMs,
        int readTimeoutMs,
        int pingIntervalMs,
        String logLevel) {

    public record VerifierConfig(
            String url,                    // "" = disabled
            String sharedSecret,
            int timeoutMs,
            int maxRetries,
            boolean allowPrivateTargets,
            int maxRedirects) {
    }

    public record BotApiConfig(boolean enabled, String bindHost, int port, int rateLimitPerMinute) {}

    public record RateLimitConfig(
            int loginPerMinute,
            int registerPerMinute,
            int connectionsPerMinute,
            int friendRequestPerMinute,
            int messagePerMinute,
            int groupOpPerMinute) {}

    public static ServerConfig defaults() {
        return new ServerConfig(
                "0.0.0.0",
                54530,
                "Ourcamellia Server",
                "data",
                true,
                "tls/keystore.p12",
                "",
                List.of("@Email"),
                true,
                "auto",
                10_080,
                new VerifierConfig("", "", 10_000, 2, false, 3),
                30,
                true,
                new BotApiConfig(false, "127.0.0.1", 54700, 120),
                new RateLimitConfig(5, 3, 60, 10, 120, 30),
                List.of("@admin"),
                210_000,
                10_000,
                1 << 20,
                10_000,
                90_000,
                30_000,
                "info");
    }

    public ServerConfig validated() {
        if (port < 1 || port > 65535) {
            throw new Errors.Validation("config: invalid port");
        }
        if (serverName == null || serverName.isBlank() || serverName.length() > 128) {
            throw new Errors.Validation("config: serverName required (1-128 chars)");
        }
        if (!registrationPolicy.equals("auto") && !registrationPolicy.equals("manual")
                && !registrationPolicy.equals("external")) {
            throw new Errors.Validation("config: registrationPolicy must be auto|manual|external");
        }
        if (registrationPolicy.equals("external")) {
            if (verifier == null || verifier.url().isBlank() || verifier.sharedSecret().isBlank()) {
                throw new Errors.Validation("config: external registration policy requires verifier.url and verifier.sharedSecret");
            }
        }
        if (pendingTtlMinutes < 1 || notificationRetentionDays < 1 || reviewLogRetention < 100) {
            throw new Errors.Validation("config: retention values out of range");
        }
        if (passwordHashIterations < 10_000) {
            throw new Errors.Validation("config: passwordHashIterations too low");
        }
        if (maxFrameBytes < 1024 || maxFrameBytes > 1 << 24) {
            throw new Errors.Validation("config: maxFrameBytes out of range");
        }
        if (adminUsernames == null || adminUsernames.isEmpty()) {
            throw new Errors.Validation("config: at least one admin username is required to bootstrap operators");
        }
        for (String a : adminUsernames) {
            org.ourcamellia.common.Text.requireServerName(a);
        }
        for (String f : requiredRegistrationFields) {
            if (f.isBlank() || f.length() > 32) {
                throw new Errors.Validation("config: invalid registration field name");
            }
        }
        return this;
    }

    public Path dataDirPath() {
        return Path.of(dataDir);
    }
}
