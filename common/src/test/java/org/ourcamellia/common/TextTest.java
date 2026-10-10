package org.ourcamellia.common;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class TextTest {

    @Test
    void names() {
        assertEquals("alice_1.b", Text.requireLocalName("alice_1.b"));
        assertThrows(Errors.Validation.class, () -> Text.requireLocalName(""));
        assertThrows(Errors.Validation.class, () -> Text.requireLocalName("a b"));
        assertThrows(Errors.Validation.class, () -> Text.requireLocalName("x".repeat(65)));
        assertThrows(Errors.Validation.class, () -> Text.requireLocalName("bad\u001bname"));
        assertEquals("@alice", Text.requireServerName("@alice"));
        assertThrows(Errors.Validation.class, () -> Text.requireServerName("alice"));
    }

    @Test
    void controlCharsDetected() {
        assertTrue(Text.hasControlChars("a\u001bb"));
        assertTrue(Text.hasControlChars("a\u007fb"));
        assertFalse(Text.hasControlChars("normal\ntext\tok"));
    }

    @Test
    void renderableStripsEscapes() {
        assertEquals("a\uFFFDb", Text.renderable("a\u001bb"));
        assertEquals("ok\nnext", Text.renderable("ok\nnext"));
    }

    @Test
    void unpairedSurrogatesStripped() {
        String bad = "a\ud800b"; // lone high surrogate
        String clean = Text.stripUnpairedSurrogates(bad);
        assertEquals("ab", clean);
    }

    @Test
    void emails() {
        assertEquals("a@b.c", Text.requireEmail("a@b.c"));
        assertThrows(Errors.Validation.class, () -> Text.requireEmail("not-an-email"));
        assertThrows(Errors.Validation.class, () -> Text.requireEmail("a@b@c"));
        assertThrows(Errors.Validation.class, () -> Text.requireEmail("a b@c.d"));
    }
}
