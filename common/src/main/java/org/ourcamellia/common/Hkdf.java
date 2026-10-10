package org.ourcamellia.common;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/**
 * HKDF-SHA256 (RFC 5869), implemented over the JCA HMAC primitive and validated
 * against the RFC 5869 test vectors (see HkdfTest). Used to derive keys from
 * X25519 shared secrets for group message encryption.
 */
public final class Hkdf {

    private Hkdf() {}

    public static byte[] extract(byte[] salt, byte[] ikm) {
        return hmac(salt == null || salt.length == 0 ? new byte[32] : salt, ikm);
    }

    public static byte[] expand(byte[] prk, byte[] info, int length) {
        if (length < 0 || length > 255 * 32) {
            throw new IllegalArgumentException("invalid HKDF output length");
        }
        byte[] t = new byte[0];
        byte[] out = new byte[length];
        int copied = 0;
        byte counter = 1;
        while (copied < length) {
            byte[] block = hmac(prk, concat(t, info, new byte[]{counter}));
            int take = Math.min(block.length, length - copied);
            System.arraycopy(block, 0, out, copied, take);
            copied += take;
            t = block;
            counter++;
        }
        Arrays.fill(t, (byte) 0);
        return out;
    }

    /** extract + expand in one call; salt may be null (treated as zero-length per RFC). */
    public static byte[] derive(byte[] ikm, byte[] salt, byte[] info, int length) {
        return expand(extract(salt, ikm), info, length);
    }

    private static byte[] hmac(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new Errors.Internal("HMAC-SHA256 unavailable", e);
        }
    }

    private static byte[] concat(byte[] a, byte[] b, byte[] c) {
        byte[] out = new byte[a.length + b.length + c.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        System.arraycopy(c, 0, out, a.length + b.length, c.length);
        return out;
    }
}
