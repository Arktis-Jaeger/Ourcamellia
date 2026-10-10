package org.ourcamellia.core.transport;

import org.ourcamellia.common.Errors;
import org.ourcamellia.common.SelfSignedCerts;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.cert.X509Certificate;

/**
 * TLS connection establishment (JSSE) with trust-on-first-use certificate pinning.
 *
 * Client side: when {@code expectedFingerprint} is null, the presented certificate is
 * accepted and its fingerprint returned (the caller persists the pin — TOFU). When a
 * pin exists and the presented fingerprint differs, the connection is refused with a
 * clear warning (possible impersonation; SECURITY.md threat: impersonation).
 *
 * Server side: presents the configured identity certificate.
 */
public final class TlsConnections {

    private TlsConnections() {}

    /** Attempts a pinned TLS client connection; returns the connected socket + fingerprint. */
    public static ConnectionResult connect(String host, int port, String expectedFingerprint,
                                          SSLContext clientContext, int connectTimeoutMs) {
        try {
            SSLSocketFactory factory = clientContext.getSocketFactory();
            Socket raw = new Socket();
            raw.connect(new InetSocketAddress(host, port), connectTimeoutMs);
            SSLSocket ssl = (SSLSocket) factory.createSocket(
                    raw, host, port, true);
            ssl.setUseClientMode(true);
            ssl.startHandshake();
            X509Certificate cert = (X509Certificate) ssl.getSession().getPeerCertificates()[0];
            String actual = SelfSignedCerts.fingerprint(cert);
            if (expectedFingerprint != null && !expectedFingerprint.equalsIgnoreCase(actual)) {
                ssl.close();
                throw new Errors.Network(
                        "certificate fingerprint mismatch for " + host + ":" + port
                                + " (possible impersonation); connection refused. "
                                + "Expected pin " + expectedFingerprint + " but got " + actual);
            }
            return new ConnectionResult(ssl, actual);
        } catch (Errors.OcException e) {
            throw e;
        } catch (IOException e) {
            throw new Errors.Network("cannot connect to " + host + ":" + port + ": " + e.getMessage(), e);
        }
    }

    /** Accepts one inbound TLS connection on a server socket created for this port. */
    public static SSLSocket accept(javax.net.ssl.SSLServerSocket serverSocket, int handshakeTimeoutMs) {
        try {
            Socket raw = serverSocket.accept();
            raw.setTcpNoDelay(true);
            if (!(raw instanceof SSLSocket ssl)) {
                raw.close();
                throw new Errors.Network("unexpected plain socket");
            }
            ssl.setUseClientMode(false);
            ssl.setSoTimeout(handshakeTimeoutMs);
            ssl.startHandshake();
            ssl.setSoTimeout(0);
            return ssl;
        } catch (IOException e) {
            throw new Errors.Network("TLS accept failed: " + e.getMessage(), e);
        }
    }

    /** Creates a TLS server socket bound to host:port with the given identity context. */
    public static javax.net.ssl.SSLServerSocket listen(String host, int port, SSLContext serverContext) {
        return listen(host, port, serverContext, false);
    }

    /**
     * Creates a TLS server socket; when requireClientAuth is set, clients must present
     * a certificate (used by Local mode so both peers authenticate with their local
     * identity certificates — identity = address + key fingerprint).
     */
    public static javax.net.ssl.SSLServerSocket listen(String host, int port, SSLContext serverContext,
                                                       boolean requireClientAuth) {
        try {
            var factory = serverContext.getServerSocketFactory();
            javax.net.ssl.SSLServerSocket ss = (javax.net.ssl.SSLServerSocket) factory.createServerSocket();
            ss.setReuseAddress(true);
            if (requireClientAuth) {
                ss.setNeedClientAuth(true);
            }
            ss.bind(new InetSocketAddress(host, port));
            return ss;
        } catch (IOException e) {
            throw new Errors.Network("cannot bind " + host + ":" + port + ": " + e.getMessage(), e);
        }
    }

    public record ConnectionResult(SSLSocket socket, String fingerprint) {}
}
