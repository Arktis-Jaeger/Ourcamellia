package org.ourcamellia.common.protocol;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;
import org.ourcamellia.common.Errors;
import org.ourcamellia.common.Json;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class WireTest {

    @Test
    void envelopeValidation() {
        var root = Json.object();
        root.put("v", 1);
        root.put("id", org.ourcamellia.common.Ids.newId());
        root.put("type", "ping");
        root.put("ts", System.currentTimeMillis());
        Envelope e = Envelope.of(root);
        assertEquals("ping", e.type());

        var bad = Json.object();
        bad.put("v", 99);
        bad.put("id", "not-a-uuid");
        bad.put("type", "x");
        bad.put("ts", 1);
        assertThrows(Errors.Malformed.class, () -> Envelope.of(bad));

        var badTs = Json.object();
        badTs.put("v", 1);
        badTs.put("id", org.ourcamellia.common.Ids.newId());
        badTs.put("type", "x");
        badTs.put("ts", -5);
        assertThrows(Errors.Malformed.class, () -> Envelope.of(badTs));
    }

    @Test
    void messageRoundtrip() {
        Envelope e = Wire.message(org.ourcamellia.common.Ids.newId(), "@alice", "@bob", "hi there");
        var m = Wire.parseMessage(e);
        assertEquals("@alice", m.sender());
        assertEquals("@bob", m.to());
        assertEquals("hi there", m.text());
    }

    @Test
    void rejectsControlCharsInText() {
        Envelope e = Wire.message(org.ourcamellia.common.Ids.newId(), "@a", "@b", "evil\u001b[2J");
        assertThrows(Errors.OcException.class, () -> Wire.parseMessage(e));
    }

    @Test
    void rejectsOversizedText() {
        String big = "x".repeat(20_000);
        Envelope e = Wire.message(org.ourcamellia.common.Ids.newId(), "@a", "@b", big);
        assertThrows(Errors.Malformed.class, () -> Wire.parseMessage(e));
    }

    @Test
    void groupMessageNeedsExactlyOnePayload() {
        String msgId = org.ourcamellia.common.Ids.newId();
        String groupId = org.ourcamellia.common.Ids.newId();
        Envelope onlyText = Wire.groupMessage(msgId, groupId, "@a", "text", null);
        var m = Wire.parseGroupMessage(onlyText);
        assertEquals("text", m.text());

        Envelope onlyBox = Wire.groupMessage(msgId, groupId, "@a", null, "aGVsbG8=");
        var m2 = Wire.parseGroupMessage(onlyBox);
        assertEquals("aGVsbG8=", m2.box());

        var b = (com.fasterxml.jackson.databind.node.ObjectNode) onlyText.body();
        b.put("box", "aGVsbG8=");
        assertThrows(Errors.Malformed.class, () -> Wire.parseGroupMessage(onlyText));
    }

    @Test
    void discoveryReplyValidation() {
        JsonNode ok = Wire.discoverReply(org.ourcamellia.common.Ids.newId(), "peer1", 54536,
                "a".repeat(64), System.currentTimeMillis() + 60_000);
        var r = Wire.parseDiscoverReply(ok);
        assertEquals("peer1", r.username());

        JsonNode badPort = Wire.discoverReply(org.ourcamellia.common.Ids.newId(), "p", 70000,
                "a".repeat(64), 1);
        assertThrows(Errors.Malformed.class, () -> Wire.parseDiscoverReply(badPort));

        JsonNode badFp = Wire.discoverReply(org.ourcamellia.common.Ids.newId(), "p", 54536, "ZZ", 1);
        assertThrows(Errors.Malformed.class, () -> Wire.parseDiscoverReply(badFp));
    }

    @Test
    void registrationFieldsBounded() {
        Envelope e = Wire.register("@alice", "pw", null, Map.of("@Email", "a@b.c"),
                java.util.Base64.getEncoder().encodeToString(new byte[32]));
        var r = Wire.parseRegister(e);
        assertEquals("a@b.c", r.fields().get("@Email"));

        JsonNode huge = e.body();
        var f = Json.object();
        f.put("@Email", "x".repeat(10_000));
        ((com.fasterxml.jackson.databind.node.ObjectNode) huge).set("fields", f);
        assertThrows(Errors.OcException.class, () -> Wire.parseRegister(e));
    }

    @Test
    void notifyActionValidation() {
        Envelope e = Wire.notifyAction(org.ourcamellia.common.Ids.newId(), "pass");
        assertEquals("pass", Wire.parseNotifyAction(e).action());
        ((com.fasterxml.jackson.databind.node.ObjectNode) e.body()).put("action", "destroy");
        assertThrows(Errors.Malformed.class, () -> Wire.parseNotifyAction(e));
    }
}
