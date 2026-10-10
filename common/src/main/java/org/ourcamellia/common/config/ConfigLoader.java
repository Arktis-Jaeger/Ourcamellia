package org.ourcamellia.common.config;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.ourcamellia.common.Errors;
import org.ourcamellia.common.Json;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

/**
 * JSON configuration loader. Loads a record type from a JSON file, merging with
 * defaults: unknown top-level keys produce warnings (never hard failures, for forward
 * compatibility), missing keys keep default values, wrongly typed keys fail with a
 * clear message. Secrets in config files are the operator's responsibility to protect
 * (0600 recommendation in the operator docs); they are never logged.
 */
public final class ConfigLoader {

    private ConfigLoader() {}

    public static <T extends Record> T load(Path file, Class<T> type, T defaults, Consumer<String> warnings) {
        if (file == null || !Files.exists(file)) {
            return defaults;
        }
        byte[] raw;
        try {
            raw = Files.readAllBytes(file);
        } catch (IOException e) {
            throw new Errors.Persistence("cannot read config file: " + file, e);
        }
        JsonNode root = Json.parse(raw);
        if (!root.isObject()) {
            throw new Errors.Validation("config file must contain a JSON object: " + file);
        }
        List<String> unknown = new ArrayList<>();
        try {
            ObjectNode merged = Json.mapper().valueToTree(defaults);
            root.fields().forEachRemaining(e -> {
                java.util.Arrays.stream(type.getRecordComponents())
                        .filter(c -> c.getName().equals(e.getKey()))
                        .findFirst()
                        .ifPresentOrElse(
                                c -> merged.set(e.getKey(), e.getValue()),
                                () -> unknown.add(e.getKey()));
            });
            if (!unknown.isEmpty() && warnings != null) {
                warnings.accept("unknown config keys ignored: " + String.join(", ", unknown));
            }
            return Json.convert(merged, type);
        } catch (Errors.OcException e) {
            throw new Errors.Validation("invalid config file " + file + ": " + e.getMessage());
        }
    }

    /** Loads and validates; throws Validation with a clear path-prefixed message. */
    public static <T extends Record> T loadStrict(Path file, Class<T> type, T defaults, Consumer<String> warnings) {
        T cfg = load(file, type, defaults, warnings);
        return cfg;
    }
}
