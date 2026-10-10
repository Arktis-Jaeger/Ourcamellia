package org.ourcamellia.common;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.*;

/** RFC 5869 test vectors (test case 1, 2, 3). */
class HkdfTest {

    private static byte[] h(String hex) {
        return HexFormat.of().parseHex(hex);
    }

    private static String hex(byte[] b) {
        return HexFormat.of().formatHex(b);
    }

    @Test
    void rfc5869Case1() {
        byte[] ikm = h("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        byte[] salt = h("000102030405060708090a0b0c");
        byte[] info = h("f0f1f2f3f4f5f6f7f8f9");
        byte[] okm = Hkdf.derive(ikm, salt, info, 42);
        assertEquals(
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
                hex(okm));
    }

    @Test
    void rfc5869Case2() {
        byte[] ikm = h("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                + "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
                + "404142434445464748494a4b4c4d4e4f");
        byte[] salt = h("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
                + "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
                + "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
        byte[] info = h("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
                + "d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef"
                + "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        byte[] okm = Hkdf.derive(ikm, salt, info, 82);
        assertEquals(
                "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"
                        + "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71"
                        + "cc30c58179ec3e87c14c01d5c1f3434f1d87",
                hex(okm));
    }

    @Test
    void rfc5869Case3() {
        byte[] ikm = h("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        byte[] salt = new byte[0];
        byte[] info = new byte[0];
        byte[] okm = Hkdf.derive(ikm, salt, info, 42);
        assertEquals(
                "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
                        + "9d201395faa4b61a96c8",
                hex(okm));
    }

    @Test
    void nullSaltEqualsZeroSalt() {
        byte[] ikm = "input".getBytes(StandardCharsets.UTF_8);
        byte[] a = Hkdf.derive(ikm, null, new byte[]{1}, 32);
        byte[] b = Hkdf.derive(ikm, new byte[0], new byte[]{1}, 32);
        assertArrayEquals(a, b);
    }

    @Test
    void differentInfoDifferentKeys() {
        byte[] ikm = CryptoUtil.randomBytes(32);
        byte[] k1 = Hkdf.derive(ikm, null, "group:a".getBytes(), 32);
        byte[] k2 = Hkdf.derive(ikm, null, "group:b".getBytes(), 32);
        assertFalse(java.util.Arrays.equals(k1, k2));
    }
}
