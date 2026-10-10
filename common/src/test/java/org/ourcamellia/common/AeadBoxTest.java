package org.ourcamellia.common;

import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class AeadBoxTest {

    @Test
    void roundtrip() {
        byte[] key = CryptoUtil.randomBytes(32);
        byte[] plain = "secret message \u00fc".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] box = AeadBox.seal(key, AeadBox.aadFor("history", "conv-1"), plain);
        byte[] out = AeadBox.open(key, AeadBox.aadFor("history", "conv-1"), box);
        assertArrayEquals(plain, out);
    }

    @Test
    void wrongKeyFails() {
        byte[] key = CryptoUtil.randomBytes(32);
        byte[] other = CryptoUtil.randomBytes(32);
        byte[] box = AeadBox.seal(key, null, "data".getBytes());
        assertNull(AeadBox.open(other, null, box));
    }

    @Test
    void tamperedCiphertextFails() {
        byte[] key = CryptoUtil.randomBytes(32);
        byte[] box = AeadBox.seal(key, null, "data".getBytes());
        box[box.length - 1] ^= 0x01;
        assertNull(AeadBox.open(key, null, box));
    }

    @Test
    void wrongAadFails() {
        byte[] key = CryptoUtil.randomBytes(32);
        byte[] box = AeadBox.seal(key, AeadBox.aadFor("file-a"), "data".getBytes());
        assertNull(AeadBox.open(key, AeadBox.aadFor("file-b"), box));
    }

    @Test
    void noncesAreUnique() {
        byte[] key = CryptoUtil.randomBytes(32);
        byte[] a = AeadBox.seal(key, null, new byte[]{1});
        byte[] b = AeadBox.seal(key, null, new byte[]{1});
        assertFalse(Arrays.equals(a, b));
    }

    @Test
    void malformedBoxThrows() {
        byte[] key = CryptoUtil.randomBytes(32);
        assertThrows(Errors.Malformed.class, () -> AeadBox.open(key, null, new byte[]{1, 2, 3}));
        assertThrows(Errors.Malformed.class, () -> AeadBox.open(key, null, "NOPE...".getBytes()));
    }

    @Test
    void deriveKeyIsStableForSameSalt() {
        byte[] salt = CryptoUtil.randomBytes(16);
        byte[] k1 = AeadBox.deriveKey("hunter2", salt, 12_000);
        byte[] k2 = AeadBox.deriveKey("hunter2", salt, 12_000);
        assertArrayEquals(k1, k2);
        byte[] k3 = AeadBox.deriveKey("hunter3", salt, 12_000);
        assertFalse(Arrays.equals(k1, k3));
    }
}
