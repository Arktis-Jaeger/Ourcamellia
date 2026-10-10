package org.ourcamellia.client;

import org.junit.jupiter.api.Test;

import java.io.PrintWriter;
import java.io.StringWriter;

import static org.junit.jupiter.api.Assertions.*;

/** LineEditor logic tests: editing, cursor movement, UTF-8, and submit behavior. */
class LineEditorTest {

    private static void feed(LineEditor e, String text) {
        for (byte b : text.getBytes(java.nio.charset.StandardCharsets.UTF_8)) {
            e.feed(b & 0xFF);
        }
    }

    @Test
    void typingAndSubmit() {
        LineEditor e = new LineEditor();
        feed(e, "hello");
        assertEquals("hello", e.text());
        assertEquals("hello", e.feed(13));
        assertEquals("", e.text());
    }

    @Test
    void backspaceAndCursor() {
        LineEditor e = new LineEditor();
        feed(e, "abc");
        e.feed(127);
        assertEquals("ab", e.text());
        e.escape("D"); // left
        e.escape("D");
        feed(e, "X"); // insert at cursor
        assertEquals("Xab", e.text());
        e.escape("F"); // end
        feed(e, "Y");
        assertEquals("XabY", e.text());
    }

    @Test
    void ctrlCAndCtrlU() {
        LineEditor e = new LineEditor();
        feed(e, "abc");
        e.feed(3);
        assertEquals("", e.text());
        feed(e, "xyz");
        e.feed(21);
        assertEquals("", e.text());
    }

    @Test
    void utf8Input() {
        LineEditor e = new LineEditor();
        feed(e, "你好");
        assertEquals("你好", e.text());
        feed(e, "组");
        assertEquals("你好组", e.text());
    }

    @Test
    void ctrlDOnEmptyIsEof() {
        LineEditor e = new LineEditor();
        assertEquals("", e.feed(4)); // EOF signal on empty buffer
        feed(e, "abc");
        e.escape("H"); // cursor to start
        assertNull(e.feed(4)); // ctrl-D deletes the char under the cursor
        assertEquals("bc", e.text());
    }

    @Test
    void renderStripsHostileControlChars() {
        LineEditor e = new LineEditor();
        feed(e, "hi\u001bthere"); // embedded ESC must never reach the terminal
        StringWriter sw = new StringWriter();
        e.render(new PrintWriter(sw), "> ", 120);
        assertFalse(sw.toString().contains("hi\u001bthere"));
        assertTrue(sw.toString().contains("hithere"),
                "hostile control characters must never be rendered");
    }
}
