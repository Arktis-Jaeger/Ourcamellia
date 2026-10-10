package org.ourcamellia.common;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/**
 * Authenticated-encryption sealed box used for (a) secondary-password-protected local
 * history files and (b) encrypted-group message payloads and wrapped group keys.
 *
 * Format (bytes): magic "OCB1" | nonce(12) | ciphertext||tag(AES-256-GCM).
 * The key is always 32 bytes. AAD binds the ciphertext to its context (file name,
 * conversation id, or group id) so ciphertexts cannot be replayed into another context.
 * Unique random nonces are generated for every seal operation.
 */
public final class AeadBox {

    public static final byte[] MAGIC = new byte[]{'O', 'C', 'B', '1'};
    public static final int KEY_BYTES = 32;
    public static final int NONCE_BYTES = 12;

    private AeadBox() {}

    public static byte[] seal(byte[] key, byte[] aad, byte[] plaintext) {
        if (key == null || key.length != KEY_BYTES) {
            throw new IllegalArgumentException("AEAD key must be 32 bytes");
        }
        byte[] nonce = CryptoUtil.randomBytes(NONCE_BYTES);
        try {
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(128, nonce));
            if (aad != null && aad.length > 0) {
                c.updateAAD(aad);
            }
            byte[] ct = c.doFinal(plaintext);
            byte[] out = new byte[MAGIC.length + NONCE_BYTES + ct.length];
            System.arraycopy(MAGIC, 0, out, 0, MAGIC.length);
            System.arraycopy(nonce, 0, out, MAGIC.length, NONCE_BYTES);
            System.arraycopy(ct, 0, out, MAGIC.length + NONCE_BYTES, ct.length);
            return out;
        } catch (GeneralSecurityException e) {
            throw new Errors.Internal("AES-GCM unavailable", e);
        }
    }

    /** Returns null when authentication fails (wrong key or tampered data); throws on malformed input. */
    public static byte[] open(byte[] key, byte[] aad, byte[] box) {
        if (key == null || key.length != KEY_BYTES) {
            throw new IllegalArgumentException("AEAD key must be 32 bytes");
        }
        if (box == null || box.length < MAGIC.length + NONCE_BYTES + 16) {
            throw new Errors.Malformed("sealed box too short");
        }
        for (int i = 0; i < MAGIC.length; i++) {
            if (box[i] != MAGIC[i]) {
                throw new Errors.Malformed("sealed box has wrong magic");
            }
        }
        byte[] nonce = Arrays.copyOfRange(box, MAGIC.length, MAGIC.length + NONCE_BYTES);
        byte[] ct = Arrays.copyOfRange(box, MAGIC.length + NONCE_BYTES, box.length);
        try {
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(128, nonce));
            if (aad != null && aad.length > 0) {
                c.updateAAD(aad);
            }
            return c.doFinal(ct);
        } catch (GeneralSecurityException e) {
            return null; // authentication failure
        }
    }

    /** Derives the file-protection key for the secondary password (PBKDF2-HMAC-SHA256). */
    public static byte[] deriveKey(String secondaryPassword, byte[] salt, int iterations) {
        if (secondaryPassword == null || secondaryPassword.isEmpty()) {
            throw new Errors.Validation("secondary password must not be empty");
        }
        // The caller keeps the salt: it must be persisted next to the sealed data so
        // the key can be re-derived later.
        return PasswordHash.deriveRaw(secondaryPassword.toCharArray(), salt, iterations);
    }

    public static byte[] aadFor(String... parts) {
        return String.join("|", parts).getBytes(StandardCharsets.UTF_8);
    }
}
