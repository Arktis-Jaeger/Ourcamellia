package org.ourcamellia.common.config;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.ourcamellia.common.Errors;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ConfigLoaderTest {

    @Test
    void missingFileYieldsDefaults(@TempDir Path dir) {
        List<String> warnings = new ArrayList<>();
        ClientConfig cfg = ConfigLoader.load(dir.resolve("nope.json"), ClientConfig.class,
                ClientConfig.defaults(), warnings::add);
        assertEquals(ClientConfig.defaults(), cfg);
        assertTrue(warnings.isEmpty());
    }

    @Test
    void overridesAndWarns(@TempDir Path dir) throws Exception {
        Path f = dir.resolve("c.json");
        Files.writeString(f, """
                {"mode":"old","listenPort":12345,"futureKey":true}
                """);
        List<String> warnings = new ArrayList<>();
        ClientConfig cfg = ConfigLoader.load(f, ClientConfig.class, ClientConfig.defaults(), warnings::add);
        assertEquals("old", cfg.mode());
        assertEquals(12345, cfg.listenPort());
        assertTrue(cfg.defaultRecording()); // default preserved
        assertEquals(1, warnings.size());
        assertTrue(warnings.get(0).contains("futureKey"));
    }

    @Test
    void wrongTypeFails(@TempDir Path dir) throws Exception {
        Path f = dir.resolve("c.json");
        Files.writeString(f, "{\"listenPort\":\"banana\"}");
        assertThrows(Errors.OcException.class, () ->
                ConfigLoader.load(f, ClientConfig.class, ClientConfig.defaults(), w -> {}));
    }

    @Test
    void invalidJsonFails(@TempDir Path dir) throws Exception {
        Path f = dir.resolve("c.json");
        Files.writeString(f, "{not json");
        assertThrows(Errors.OcException.class, () ->
                ConfigLoader.load(f, ClientConfig.class, ClientConfig.defaults(), w -> {}));
    }

    @Test
    void serverConfigValidation() {
        ServerConfig d = ServerConfig.defaults().validated();
        assertEquals("auto", d.registrationPolicy());

        assertThrows(Errors.Validation.class, () ->
                new ServerConfig("0.0.0.0", 54530, " ", "data", true, "t", "", List.of(), true,
                        "external", 1, null, 30, true,
                        new ServerConfig.BotApiConfig(false, "127.0.0.1", 54700, 120),
                        new ServerConfig.RateLimitConfig(5, 3, 60, 10, 120, 30),
                        List.of("@admin"), 210_000, 10_000, 1 << 20, 10_000, 90_000, 30_000, "info").validated());
    }
}
