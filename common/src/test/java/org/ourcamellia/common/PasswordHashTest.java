package org.ourcamellia.common;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PasswordHashTest {

    @Test
    void hashAndVerify() {
        String stored = PasswordHash.hash("correct horse", 12_000);
        assertTrue(stored.startsWith("pbkdf2-sha256$v1$12000$"));
        assertTrue(PasswordHash.verify("correct horse", stored));
        assertFalse(PasswordHash.verify("wrong", stored));
    }

    @Test
    void uniqueSalts() {
        String a = PasswordHash.hash("same", 12_000);
        String b = PasswordHash.hash("same", 12_000);
        assertNotEquals(a, b);
        assertTrue(PasswordHash.verify("same", a));
        assertTrue(PasswordHash.verify("same", b));
    }

    @Test
    void rejectsMalformedRecords() {
        assertFalse(PasswordHash.verify("x", null));
        assertFalse(PasswordHash.verify("x", ""));
        assertFalse(PasswordHash.verify("x", "md5$abc"));
        assertFalse(PasswordHash.verify("x", "pbkdf2-sha256$v1$999$aGk$aGk"));
        assertFalse(PasswordHash.verify("x", "pbkdf2-sha256$v1$12000$!!!$???"));
        assertFalse(PasswordHash.verify("x", "pbkdf2-sha256$v1$12000$"
                + java.util.Base64.getEncoder().encodeToString(new byte[16]) + "$short"));
    }

    @Test
    void iterationsEnforced() {
        assertThrows(Errors.Validation.class, () -> PasswordHash.hash("x", 1_000));
    }
}
