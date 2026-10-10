package org.ourcamellia.common;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * Single JSON policy for the whole product: strict limits (depth, string length,
 * numbers) to bound hostile input, UTF-8, and a versioned schema discipline where
 * unknown fields are tolerated for forward compatibility but validated fields are
 * checked explicitly.
 */
public final class Json {

    public static final int MAX_STRING = 1 << 20;   // 1 MiB per string
    public static final int MAX_DEPTH = 24;

    private static final ObjectMapper MAPPER = createMapper();

    private Json() {}

    private static ObjectMapper createMapper() {
        StreamReadConstraints constraints = StreamReadConstraints.builder()
                .maxStringLength(MAX_STRING)
                .maxNumberLength(64)
                .maxNestingDepth(MAX_DEPTH)
                .build();
        ObjectMapper m = new ObjectMapper();
        m.getFactory().setStreamReadConstraints(constraints);
        m.configure(DeserializationFeature.FAIL_ON_TRAILING_TOKENS, true);
        return m;
    }

    public static ObjectMapper mapper() {
        return MAPPER;
    }

    public static ObjectNode object() {
        return MAPPER.createObjectNode();
    }

    public static ArrayNode array() {
        return MAPPER.createArrayNode();
    }

    public static String write(Object value) {
        try {
            return MAPPER.writeValueAsString(value);
        } catch (JsonProcessingException e) {
            throw new Errors.Internal("JSON encoding failed", e);
        }
    }

    public static byte[] writeBytes(Object value) {
        try {
            return MAPPER.writeValueAsBytes(value);
        } catch (JsonProcessingException e) {
            throw new Errors.Internal("JSON encoding failed", e);
        }
    }

    public static JsonNode parse(byte[] data) {
        try {
            return MAPPER.readTree(data);
        } catch (Exception e) {
            throw new Errors.Malformed("invalid JSON payload");
        }
    }

    public static JsonNode parse(String text) {
        try {
            return MAPPER.readTree(text);
        } catch (Exception e) {
            throw new Errors.Malformed("invalid JSON payload");
        }
    }

    public static <T> T convert(JsonNode node, Class<T> type) {
        try {
            return MAPPER.treeToValue(node, type);
        } catch (JsonProcessingException e) {
            throw new Errors.Malformed("invalid JSON structure");
        }
    }

    /** Parses and converts, throwing Malformed on any structural problem. */
    public static <T> T parse(byte[] data, Class<T> type) {
        return convert(parse(data), type);
    }

    // ----- strict field readers used by protocol codecs -----

    public static String reqStr(JsonNode o, String field, int maxLen) {
        JsonNode n = o.get(field);
        if (n == null || !n.isTextual()) {
            throw new Errors.Malformed("missing field: " + field);
        }
        String v = n.asText();
        if (v.length() > maxLen) {
            throw new Errors.Malformed("field too long: " + field);
        }
        return v;
    }

    public static String optStr(JsonNode o, String field, int maxLen) {
        JsonNode n = o.get(field);
        if (n == null || n.isNull()) {
            return null;
        }
        if (!n.isTextual()) {
            throw new Errors.Malformed("invalid field: " + field);
        }
        String v = n.asText();
        if (v.length() > maxLen) {
            throw new Errors.Malformed("field too long: " + field);
        }
        return v;
    }

    public static long reqLong(JsonNode o, String field) {
        JsonNode n = o.get(field);
        if (n == null || !n.isIntegralNumber()) {
            throw new Errors.Malformed("missing field: " + field);
        }
        return n.asLong();
    }

    public static boolean optBool(JsonNode o, String field, boolean dflt) {
        JsonNode n = o.get(field);
        if (n == null || n.isNull()) {
            return dflt;
        }
        if (!n.isBoolean()) {
            throw new Errors.Malformed("invalid field: " + field);
        }
        return n.asBoolean();
    }

    public static JsonNode reqNode(JsonNode o, String field) {
        JsonNode n = o.get(field);
        if (n == null) {
            throw new Errors.Malformed("missing field: " + field);
        }
        return n;
    }
}
