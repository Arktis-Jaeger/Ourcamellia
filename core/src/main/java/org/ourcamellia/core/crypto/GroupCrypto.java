package org.ourcamellia.core.crypto;

import org.ourcamellia.common.AeadBox;
import org.ourcamellia.common.CryptoUtil;
import org.ourcamellia.common.Errors;
import org.ourcamellia.common.Hkdf;

import javax.crypto.KeyAgreement;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.XECPublicKeySpec;

/**
 * Encrypted-group cryptography (SECURITY.md §4): X25519 key agreement (JCA XDH) +
 * HKDF-SHA256 (RFC 5869) + AES-256-GCM (JCA). The server relays only wrapped key
 * blobs and ciphertext — it never sees group keys or plaintext.
 *
 * Honest limitations (disclosed in THREAT_MODEL.md and the UI):
 * - no post-compromise security: a removed member who captured earlier ciphertext
 *   can decrypt old messages;
 * - newly added members cannot read pre-join history (nothing is stored server-side);
 * - the server can drop messages or exclude members (availability attacks), but
 *   cannot forge or read content.
 */
public final class GroupCrypto {

    public static final int GROUP_KEY_BYTES = 32;

    private GroupCrypto() {}

    /** Reconstructs an X25519 private key from PKCS#8 bytes. */
    public static PrivateKey privateKeyFrom(byte[] pkcs8) {
        try {
            return java.security.KeyFactory.getInstance("X25519")
                    .generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(pkcs8));
        } catch (GeneralSecurityException e) {
            throw new Errors.Malformed("invalid X25519 private key");
        }
    }

    /** Reconstructs an X25519 public key from raw 32-byte encoding. */
    public static PublicKey publicKeyFrom(byte[] raw) {
        try {
            return java.security.KeyFactory.getInstance("X25519").generatePublic(
                    new XECPublicKeySpec(java.security.spec.NamedParameterSpec.X25519,
                            new java.math.BigInteger(1, raw)));
        } catch (GeneralSecurityException e) {
            throw new Errors.Malformed("invalid X25519 public key");
        }
    }

    /** Raw 32-byte public key of a keypair. */
    public static byte[] publicKeyBytes(java.security.KeyPair kp) {
        byte[] u = ((java.security.interfaces.XECPublicKey) kp.getPublic()).getU().toByteArray();
        // strip a possible leading zero byte added by BigInteger sign handling
        if (u.length == 33 && u[0] == 0) {
            return java.util.Arrays.copyOfRange(u, 1, 33);
        }
        return u;
    }

    /** ECDH(X25519) shared secret. */
    public static byte[] sharedSecret(PrivateKey priv, byte[] peerPublic) {
        try {
            KeyAgreement ka = KeyAgreement.getInstance("XDH");
            ka.init(priv);
            ka.doPhase(publicKeyFrom(peerPublic), true);
            return ka.generateSecret();
        } catch (GeneralSecurityException e) {
            throw new Errors.Internal("XDH agreement failed", e);
        }
    }

    private static byte[] derive(byte[] shared, String groupId, long generation) {
        byte[] info = ("ourcamellia/group/v1/" + groupId + "/" + generation)
                .getBytes(StandardCharsets.UTF_8);
        return Hkdf.derive(shared, null, info, 32);
    }

    /** Wraps the group key for one member (used on create/invite/rotation). */
    public static String wrapGroupKey(PrivateKey senderPriv, byte[] memberPublic,
                                      String groupId, long generation, byte[] groupKey) {
        byte[] shared = sharedSecret(senderPriv, memberPublic);
        byte[] kek = derive(shared, groupId, generation);
        byte[] box = AeadBox.seal(kek, AeadBox.aadFor("ourcamellia", "group-key", groupId, String.valueOf(generation)),
                groupKey);
        return java.util.Base64.getEncoder().encodeToString(box);
    }

    /** Unwraps a group key blob addressed to us. Returns null on any failure. */
    public static byte[] unwrapGroupKey(PrivateKey myPriv, byte[] senderPublic,
                                        String groupId, long generation, String boxBase64) {
        try {
            byte[] box = java.util.Base64.getDecoder().decode(boxBase64);
            byte[] shared = sharedSecret(myPriv, senderPublic);
            byte[] kek = derive(shared, groupId, generation);
            return AeadBox.open(kek, AeadBox.aadFor("ourcamellia", "group-key", groupId,
                    String.valueOf(generation)), box);
        } catch (IllegalArgumentException | Errors.OcException e) {
            return null;
        }
    }

    /** Encrypts one group message with the group key. */
    public static String encryptMessage(byte[] groupKey, String groupId, byte[] plaintext) {
        byte[] box = AeadBox.seal(groupKey,
                AeadBox.aadFor("ourcamellia", "group-message", groupId), plaintext);
        return java.util.Base64.getEncoder().encodeToString(box);
    }

    /** Decrypts one group message; returns null on authentication failure. */
    public static String decryptMessage(byte[] groupKey, String groupId, String boxBase64) {
        try {
            byte[] box = java.util.Base64.getDecoder().decode(boxBase64);
            byte[] plain = AeadBox.open(groupKey,
                    AeadBox.aadFor("ourcamellia", "group-message", groupId), box);
            return plain == null ? null : new String(plain, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException | Errors.OcException e) {
            return null;
        }
    }

    public static byte[] randomGroupKey() {
        return CryptoUtil.randomBytes(GROUP_KEY_BYTES);
    }
}
