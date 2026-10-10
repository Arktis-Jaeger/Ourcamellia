package org.ourcamellia.common.protocol;

import com.fasterxml.jackson.databind.JsonNode;
import org.ourcamellia.common.Errors;
import org.ourcamellia.common.Json;

import java.util.Map;

/**
 * Protocol envelope: every frame is {v, id, type, ts, ref?, body?}.
 * v must equal PROTOCOL_VERSION (version rejection is explicit — see Wire.checkVersion);
 * id is a UUIDv4 used for idempotency/retry correlation; ref links replies to requests.
 */
public record Envelope(int v, String id, String type, long ts, String ref, JsonNode body) {

    public static final int PROTOCOL_VERSION = 1;

    public static Envelope of(JsonNode root) {
        if (root == null || !root.isObject()) {
            throw new Errors.Malformed("envelope must be a JSON object");
        }
        int v = (int) Json.reqLong(root, "v");
        if (v != PROTOCOL_VERSION) {
            throw new Errors.Malformed("unsupported protocol version: " + v);
        }
        String id = Json.reqStr(root, "id", 64);
        String type = Json.reqStr(root, "type", 64);
        long ts = Json.reqLong(root, "ts");
        String ref = Json.optStr(root, "ref", 64);
        JsonNode body = root.get("body");
        if (body != null && !body.isObject() && !body.isNull()) {
            throw new Errors.Malformed("envelope body must be an object");
        }
        try {
            org.ourcamellia.common.Ids.requireId(id, "envelope id");
        } catch (Errors.Validation e) {
            throw new Errors.Malformed("envelope id is not a UUID");
        }
        if (ts < 0 || ts > System.currentTimeMillis() + 86_400_000L) {
            throw new Errors.Malformed("envelope timestamp out of range");
        }
        return new Envelope(v, id, type, ts, ref, body == null || body.isNull() ? Json.object() : body);
    }

    public JsonNode root() {
        var o = Json.object();
        o.put("v", v);
        o.put("id", id);
        o.put("type", type);
        o.put("ts", ts);
        if (ref != null) {
            o.put("ref", ref);
        }
        o.set("body", body);
        return o;
    }

    public static Envelope make(String type, JsonNode body, String ref) {
        return new Envelope(PROTOCOL_VERSION, org.ourcamellia.common.Ids.newId(), type,
                System.currentTimeMillis(), ref, body == null ? Json.object() : body);
    }
}
