package org.ourcamellia.common;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;

/** Small crypto utility surface. All primitives come from the JCA provider. */
public final class CryptoUtil {

    private static final SecureRandom RANDOM = new SecureRandom();

    private CryptoUtil() {}

    public static SecureRandom random() {
        return RANDOM;
    }

    public static byte[] randomBytes(int n) {
        byte[] b = new byte[n];
        RANDOM.nextBytes(b);
        return b;
    }

    public static String randomHex(int bytes) {
        return HexFormat.of().formatHex(randomBytes(bytes));
    }

    public static String randomToken() {
        // 256-bit URL-safe token for BOT API credentials.
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes(32));
    }

    public static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (GeneralSecurityException e) {
            throw new Errors.Internal("SHA-256 unavailable", e);
        }
    }

    public static String sha256Hex(byte[] data) {
        return HexFormat.of().formatHex(sha256(data));
    }

    public static String sha256Hex(String data) {
        return sha256Hex(data.getBytes(StandardCharsets.UTF_8));
    }

    public static byte[] hmacSha256(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new Errors.Internal("HMAC-SHA256 unavailable", e);
        }
    }

    public static boolean constantTimeEquals(byte[] a, byte[] b) {
        return MessageDigest.isEqual(a, b);
    }

    public static boolean constantTimeEquals(String a, String b) {
        return MessageDigest.isEqual(
                a.getBytes(StandardCharsets.UTF_8),
                b.getBytes(StandardCharsets.UTF_8));
    }

    /** Compares two possibly-null strings without leaking length/timing. */
    public static boolean safeEquals(String a, String b) {
        byte[] x = a == null ? new byte[0] : a.getBytes(StandardCharsets.UTF_8);
        byte[] y = b == null ? new byte[0] : b.getBytes(StandardCharsets.UTF_8);
        return MessageDigest.isEqual(x, y);
    }
}
