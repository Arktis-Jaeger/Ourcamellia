package org.ourcamellia.common;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HexFormat;

/**
 * Self-signed certificate generation and keystore handling.
 *
 * TLS identity for every Ourcamellia endpoint (server, local peer) is a self-signed
 * certificate. Peers and clients pin the SHA-256 fingerprint of the certificate they
 * first see (trust-on-first-use); the product therefore provides
 * "identity = address + pinned key fingerprint" association, which SECURITY.md allows
 * as long as it is honestly described (see THREAT_MODEL.md). Operators who want a real
 * CA identity can drop their own PKCS12 keystore into the server configuration.
 *
 * Certificates are generated with {@link X509SelfSigned} (pure JCA, no internal JDK
 * APIs, no extra dependencies).
 */
public final class SelfSignedCerts {

    public static final String KEYSTORE_TYPE = "PKCS12";
    public static final String DEFAULT_ALIAS = "ourcamellia";

    private SelfSignedCerts() {}

    /** Generates an RSA-2048 self-signed certificate valid for the given number of days. */
    public static GeneratedCert generate(String commonName, int validityDays) {
        var generated = X509SelfSigned.generate(commonName, validityDays);
        return new GeneratedCert(generated.cert(), generated.key());
    }

    /** SHA-256 fingerprint of the DER-encoded certificate (lowercase hex, no separators). */
    public static String fingerprint(X509Certificate cert) {
        try {
            return HexFormat.of().formatHex(CryptoUtil.sha256(cert.getEncoded()));
        } catch (CertificateEncodingException e) {
            throw new Errors.Internal("certificate encoding failed", e);
        }
    }

    /** Saves cert + key as a PKCS12 keystore file (0600 permissions on POSIX). */
    public static void saveKeystore(Path path, X509Certificate cert, PrivateKey key, String password) {
        try {
            KeyStore ks = KeyStore.getInstance(KEYSTORE_TYPE);
            ks.load(null, null);
            ks.setKeyEntry(DEFAULT_ALIAS, key, password.toCharArray(),
                    new java.security.cert.Certificate[]{cert});
            try (OutputStream out = Files.newOutputStream(path)) {
                ks.store(out, password.toCharArray());
            }
            try {
                Files.setPosixFilePermissions(path,
                        java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
            } catch (UnsupportedOperationException ignored) {
                // non-POSIX filesystem
            }
        } catch (GeneralSecurityException | IOException e) {
            throw new Errors.Persistence("keystore save failed", e);
        }
    }

    /** Loads a PKCS12 keystore and extracts the first private-key entry. */
    public static GeneratedCert loadKeystore(Path path, String password) {
        try {
            KeyStore ks = KeyStore.getInstance(KEYSTORE_TYPE);
            try (InputStream in = Files.newInputStream(path)) {
                ks.load(in, password.toCharArray());
            }
            String alias = ks.aliases().hasMoreElements() ? ks.aliases().nextElement() : null;
            if (alias == null) {
                throw new Errors.Persistence("keystore contains no entries");
            }
            X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
            PrivateKey key = (PrivateKey) ks.getKey(alias, password.toCharArray());
            if (cert == null || key == null) {
                throw new Errors.Persistence("keystore entry unusable");
            }
            return new GeneratedCert(cert, key);
        } catch (GeneralSecurityException | IOException e) {
            throw new Errors.Persistence("keystore load failed (check path and password)", e);
        }
    }

    /** Loads a certificate (PEM or DER) for pinning/validation. */
    public static X509Certificate loadCertificate(Path path) {
        try (InputStream in = Files.newInputStream(path)) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(in);
        } catch (GeneralSecurityException | IOException e) {
            throw new Errors.Persistence("certificate load failed", e);
        }
    }

    /**
     * Creates an SSLContext whose trust manager pins one specific certificate
     * (compared by full certificate equality, i.e. DER bytes). Used by clients for
     * trust-on-first-use against servers and peers.
     */
    public static SSLContext pinningContext(X509Certificate trusted, KeyStore identity, char[] identityPassword) {
        try {
            KeyStore trust = KeyStore.getInstance(KEYSTORE_TYPE);
            trust.load(null, null);
            trust.setCertificateEntry(DEFAULT_ALIAS, trusted);

            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trust);
            X509TrustManager tm = (X509TrustManager) tmf.getTrustManagers()[0];

            KeyManagerFactory kmf = null;
            if (identity != null) {
                kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                kmf.init(identity, identityPassword);
            }

            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(kmf == null ? null : kmf.getKeyManagers(), new javax.net.ssl.TrustManager[]{tm}, new SecureRandom());
            return ctx;
        } catch (GeneralSecurityException | IOException e) {
            throw new Errors.Internal("TLS context creation failed", e);
        }
    }

    /** SSLContext presenting a local identity and trusting nothing (server side). */
    public static SSLContext serverContext(KeyStore identity, char[] identityPassword) {
        try {
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(identity, identityPassword);
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(kmf.getKeyManagers(), null, new SecureRandom());
            return ctx;
        } catch (GeneralSecurityException e) {
            throw new Errors.Internal("TLS context creation failed", e);
        }
    }

    /**
     * Server-side context for MUTUAL TLS (Local mode): presents the local identity and
     * accepts any client certificate at the TLS layer. This is safe because peer
     * identity is established above TLS by fingerprint pinning (PinGuard) and the
     * name/fingerprint binding in the HELLO handshake. (A null trust-manager list
     * breaks TLS 1.3 client authentication in JSSE — the server then sends a
     * CertificateRequest no client can satisfy — hence the trust-all manager here.)
     */
    public static SSLContext serverContextWithTrustAll(KeyStore identity, char[] identityPassword) {
        try {
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(identity, identityPassword);
            javax.net.ssl.TrustManager[] trustAll = new javax.net.ssl.TrustManager[]{
                    new javax.net.ssl.X509TrustManager() {
                        @Override
                        public void checkClientTrusted(X509Certificate[] chain, String authType) {
                        }

                        @Override
                        public void checkServerTrusted(X509Certificate[] chain, String authType) {
                        }

                        @Override
                        public X509Certificate[] getAcceptedIssuers() {
                            return new X509Certificate[0];
                        }
                    }};
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(kmf.getKeyManagers(), trustAll, new SecureRandom());
            return ctx;
        } catch (GeneralSecurityException e) {
            throw new Errors.Internal("TLS context creation failed", e);
        }
    }

    /**
     * Client-side context that accepts any server certificate at the TLS layer.
     * This is safe ONLY because the caller verifies the peer's certificate
     * fingerprint immediately after the handshake (trust-on-first-use pinning) —
     * the TLS layer merely provides encryption; identity is established by the pin.
     */
    public static SSLContext trustAllContext(KeyStore identity, char[] identityPassword) {
        try {
            javax.net.ssl.TrustManager[] trustAll = new javax.net.ssl.TrustManager[]{
                    new javax.net.ssl.X509TrustManager() {
                        @Override
                        public void checkClientTrusted(X509Certificate[] chain, String authType) {
                        }

                        @Override
                        public void checkServerTrusted(X509Certificate[] chain, String authType) {
                        }

                        @Override
                        public X509Certificate[] getAcceptedIssuers() {
                            return new X509Certificate[0];
                        }
                    }};
            KeyManagerFactory kmf = null;
            if (identity != null) {
                kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                kmf.init(identity, identityPassword);
            }
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(kmf == null ? null : kmf.getKeyManagers(), trustAll, new SecureRandom());
            return ctx;
        } catch (GeneralSecurityException e) {
            throw new Errors.Internal("TLS context creation failed", e);
        }
    }

    public record GeneratedCert(X509Certificate cert, PrivateKey key) {
        public String fingerprint() {
            return SelfSignedCerts.fingerprint(cert);
        }
    }
}
