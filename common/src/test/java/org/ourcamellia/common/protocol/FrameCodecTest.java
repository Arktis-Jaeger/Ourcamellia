package org.ourcamellia.common.protocol;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;
import org.ourcamellia.common.Errors;
import org.ourcamellia.common.Json;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

import static org.junit.jupiter.api.Assertions.*;

class FrameCodecTest {

    @Test
    void roundtrip() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        FrameCodec codec = new FrameCodec(4096);
        var payload = Json.object();
        payload.put("x", "y");
        codec.write(out, payload);
        JsonNode back = codec.read(new ByteArrayInputStream(out.toByteArray()));
        assertEquals("y", back.get("x").asText());
    }

    @Test
    void cleanEofReturnsNull() {
        FrameCodec codec = new FrameCodec();
        assertNull(codec.read(new ByteArrayInputStream(new byte[0])));
    }

    @Test
    void oversizedFrameRejected() {
        FrameCodec codec = new FrameCodec(2048);
        StringBuilder big = new StringBuilder();
        for (int i = 0; i < 3000; i++) {
            big.append('a');
        }
        var payload = Json.object();
        payload.put("x", big.toString());
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        assertThrows(Errors.Malformed.class, () -> codec.write(out, payload));
    }

    @Test
    void hostileLengthRejected() {
        FrameCodec codec = new FrameCodec(4096);
        byte[] hostile = new byte[]{(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 1};
        assertThrows(Errors.Malformed.class, () -> codec.read(new ByteArrayInputStream(hostile)));
    }

    @Test
    void truncatedFrameRejected() {
        FrameCodec codec = new FrameCodec(4096);
        byte[] truncated = new byte[]{0, 0, 0, 10, 1, 2};
        assertThrows(Errors.OcException.class, () -> codec.read(new ByteArrayInputStream(truncated)));
    }

    @Test
    void invalidJsonRejected() {
        FrameCodec codec = new FrameCodec(4096);
        byte[] body = "not json".getBytes();
        byte[] frame = new byte[4 + body.length];
        frame[3] = (byte) body.length;
        System.arraycopy(body, 0, frame, 4, body.length);
        assertThrows(Errors.Malformed.class, () -> codec.read(new ByteArrayInputStream(frame)));
    }
}
