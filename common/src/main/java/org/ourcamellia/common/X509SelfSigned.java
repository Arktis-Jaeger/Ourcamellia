package org.ourcamellia.common;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Date;

/**
 * Minimal self-signed X.509 v3 certificate generation using only public JCA APIs
 * (KeyPairGenerator, Signature, CertificateFactory). No internal JDK packages, no
 * extra dependencies — required for "standard JVM" portability.
 *
 * Produces: RSA-2048, signature SHA256withRSA, subject CN=<name>, no extensions.
 * Validity: from (now - 1h) to (now + validityDays). The generated certificate is
 * round-tripped through {@link CertificateFactory} before being returned, and the
 * TLS handshake tests exercise it end-to-end, so a malformed encoding fails tests.
 */
public final class X509SelfSigned {

    // OIDs
    private static final byte[] OID_RSA = new byte[]{0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0x0D, 0x01, 0x01, 0x01};
    private static final byte[] OID_SHA256_RSA = new byte[]{0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0x0D, 0x01, 0x01, 0x0B};
    private static final byte[] OID_CN = new byte[]{0x55, 0x04, 0x03};
    private static final byte[] OID_KEY_USAGE = new byte[]{0x55, 0x1D, 0x0F};
    private static final byte[] OID_BASIC_CONSTRAINTS = new byte[]{0x55, 0x1D, 0x13};

    private X509SelfSigned() {}

    public record Generated(X509Certificate cert, PrivateKey key) {}

    public static Generated generate(String commonName, int validityDays) {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair kp = kpg.generateKeyPair();

            byte[] tbs = buildTbs(kp, commonName, validityDays);
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initSign(kp.getPrivate());
            sig.update(tbs);
            byte[] signature = sig.sign();

            byte[] certDer = sequence(
                    tbs,
                    algorithmIdentifier(OID_SHA256_RSA),
                    bitString(signature));

            // Self-check: parse with the JDK's own certificate parser.
            X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new java.io.ByteArrayInputStream(certDer));
            cert.checkValidity();
            cert.verify(cert.getPublicKey());
            return new Generated(cert, kp.getPrivate());
        } catch (Exception e) {
            throw new Errors.Internal("self-signed certificate generation failed", e);
        }
    }

    private static byte[] buildTbs(KeyPair kp, String cn, int validityDays) throws Exception {
        RSAPublicKey pub = (RSAPublicKey) kp.getPublic();
        byte[] rsaPubDer = sequence(integer(pub.getModulus()), integer(pub.getPublicExponent()));
        byte[] spki = sequence(algorithmIdentifier(OID_RSA), bitString(rsaPubDer));

        BigInteger serial = new BigInteger(128, CryptoUtil.random());
        byte[] version = explicit(0, integer(BigInteger.valueOf(2))); // v3

        ZonedDateTime notBefore = ZonedDateTime.now(ZoneOffset.UTC).minusHours(1);
        ZonedDateTime notAfter = notBefore.plusDays(validityDays);
        DateTimeFormatter fmt = DateTimeFormatter.ofPattern("yyMMddHHmmss'Z'");
        byte[] validity = sequence(utcTime(notBefore.format(fmt)), utcTime(notAfter.format(fmt)));

        byte[] name = sequence(set(sequence(oid(OID_CN), utf8String(sanitizeCn(cn)))));

        // Extensions: KeyUsage(digitalSignature|keyEncipherment|dataEncipherment),
        // BasicConstraints(CA=false). These are required for JSSE to select the
        // certificate for TLS (incl. TLS 1.3 client authentication).
        byte[] keyUsage = sequence(
                oid(OID_KEY_USAGE),
                booleanTrue(),
                octetString(bitStringWithUnused(new byte[]{(byte) 0xB0}, 3)));
        byte[] basicConstraints = sequence(
                oid(OID_BASIC_CONSTRAINTS),
                booleanTrue(),
                octetString(sequence()));
        byte[] extensions = explicit(3, sequence(keyUsage, basicConstraints));

        return sequence(version, integer(serial), algorithmIdentifier(OID_SHA256_RSA), name,
                validity, name, spki, extensions);
    }

    private static String sanitizeCn(String cn) {
        String s = cn == null || cn.isBlank() ? "ourcamellia" : cn;
        return s.replaceAll("[^A-Za-z0-9._-]", "-");
    }

    // ---------- minimal DER helpers ----------

    private static byte[] tag(int tag, byte[] content) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(tag);
        writeLength(out, content.length);
        out.writeBytes(content);
        return out.toByteArray();
    }

    private static byte[] sequence(byte[]... parts) {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        for (byte[] p : parts) {
            body.writeBytes(p);
        }
        return tag(0x30, body.toByteArray());
    }

    private static byte[] set(byte[] content) {
        return tag(0x31, content);
    }

    private static byte[] integer(BigInteger v) {
        byte[] raw = v.toByteArray();
        return tag(0x02, raw);
    }

    private static byte[] oid(byte[] encoded) {
        return tag(0x06, encoded);
    }

    private static byte[] utf8String(String s) {
        return tag(0x0C, s.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    private static byte[] utcTime(String s) {
        return tag(0x17, s.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
    }

    private static byte[] nullValue() {
        return new byte[]{0x05, 0x00};
    }

    private static byte[] booleanTrue() {
        return new byte[]{0x01, 0x01, (byte) 0xFF};
    }

    private static byte[] octetString(byte[] content) {
        return tag(0x04, content);
    }

    private static byte[] bitString(byte[] content) {
        return bitStringWithUnused(content, 0);
    }

    private static byte[] bitStringWithUnused(byte[] content, int unusedBits) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0x03);
        writeLength(out, content.length + 1);
        out.write(unusedBits);
        out.writeBytes(content);
        return out.toByteArray();
    }

    private static byte[] algorithmIdentifier(byte[] oid) {
        return sequence(oid(oid), nullValue());
    }

    private static byte[] explicit(int number, byte[] content) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0xA0 + number);
        writeLength(out, content.length);
        out.writeBytes(content);
        return out.toByteArray();
    }

    private static void writeLength(ByteArrayOutputStream out, int len) {
        if (len < 0x80) {
            out.write(len);
        } else if (len <= 0xFF) {
            out.write(0x81);
            out.write(len);
        } else if (len <= 0xFFFF) {
            out.write(0x82);
            out.write(len >>> 8);
            out.write(len & 0xFF);
        } else {
            out.write(0x83);
            out.write(len >>> 16);
            out.write((len >>> 8) & 0xFF);
            out.write(len & 0xFF);
        }
    }
}
