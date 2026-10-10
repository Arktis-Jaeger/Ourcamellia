package org.ourcamellia.common;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/**
 * Login-password hashing: PBKDF2-HMAC-SHA256 with a per-password random salt and a
 * configurable work factor. The stored record is self-describing and versioned:
 * {@code pbkdf2-sha256$v1$<iterations>$<saltB64>$<hashB64>}. Plaintext passwords are
 * never stored or logged. Iterations default to 210000 and are operator-configurable
 * (raise toward OWASP's 600000 when the host permits).
 */
public final class PasswordHash {

    public static final int SALT_BYTES = 16;
    public static final int HASH_BYTES = 32;
    public static final int DEFAULT_ITERATIONS = 210_000;

    private PasswordHash() {}

    public static String hash(String password, int iterations) {
        if (password == null) {
            throw new Errors.Validation("password must not be empty");
        }
        if (iterations < 10_000) {
            throw new Errors.Validation("password iterations too low");
        }
        byte[] salt = CryptoUtil.randomBytes(SALT_BYTES);
        byte[] dk = derive(password.toCharArray(), salt, iterations);
        return "pbkdf2-sha256$v1$" + iterations + "$"
                + Base64.getEncoder().encodeToString(salt) + "$"
                + Base64.getEncoder().encodeToString(dk);
    }

    /** Constant-time verification against a stored record; rejects unknown formats. */
    public static boolean verify(String password, String stored) {
        if (stored == null || !stored.startsWith("pbkdf2-sha256$v1$")) {
            return false;
        }
        String[] parts = stored.split("\\$");
        if (parts.length != 5) {
            return false;
        }
        int iterations;
        try {
            iterations = Integer.parseInt(parts[2]);
        } catch (NumberFormatException e) {
            return false;
        }
        if (iterations < 10_000 || iterations > 10_000_000) {
            return false;
        }
        byte[] salt;
        byte[] expected;
        try {
            salt = Base64.getDecoder().decode(parts[3]);
            expected = Base64.getDecoder().decode(parts[4]);
        } catch (IllegalArgumentException e) {
            return false;
        }
        if (salt.length != SALT_BYTES || expected.length != HASH_BYTES) {
            return false;
        }
        byte[] actual = derive(password.toCharArray(), salt, iterations);
        boolean ok = CryptoUtil.constantTimeEquals(actual, expected);
        Arrays.fill(actual, (byte) 0);
        return ok;
    }

    private static byte[] derive(char[] password, byte[] salt, int iterations) {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, HASH_BYTES * 8);
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                    .generateSecret(spec).getEncoded();
        } catch (GeneralSecurityException e) {
            throw new Errors.Internal("PBKDF2 unavailable", e);
        } finally {
            spec.clearPassword();
        }
    }

    // exposed for tests only
    static byte[] deriveRaw(char[] password, byte[] salt, int iterations) {
        return derive(password, salt, iterations);
    }
}
