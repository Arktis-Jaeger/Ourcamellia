package org.ourcamellia.core.transport;

import org.junit.jupiter.api.Test;
import org.ourcamellia.common.SelfSignedCerts;

import javax.net.ssl.SSLContext;

import static org.junit.jupiter.api.Assertions.*;

class TlsRawIT {

    @Test
    void clientServerHandshakeWorks() throws Exception {
        var serverCert = SelfSignedCerts.generate("tls-test", 30);
        var ks = java.security.KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("k", serverCert.key(), "pw".toCharArray(),
                new java.security.cert.Certificate[]{serverCert.cert()});
        SSLContext serverCtx = SelfSignedCerts.serverContext(ks, "pw".toCharArray());
        SSLContext clientCtx = SelfSignedCerts.trustAllContext(null, null);

        var listener = TlsConnections.listen("127.0.0.1", 55400, serverCtx);
        Thread.ofVirtual().start(() -> {
            try {
                var ssl = TlsConnections.accept(listener, 5000);
                ssl.getOutputStream().write("hi".getBytes());
                ssl.getOutputStream().flush();
                ssl.close();
            } catch (Exception e) {
                System.err.println("ACCEPT EX: " + e);
            }
        });
        var result = TlsConnections.connect("127.0.0.1", 55400, null, clientCtx, 5000);
        byte[] buf = result.socket().getInputStream().readNBytes(2);
        assertEquals("hi", new String(buf));
        listener.close();
    }

    @Test
    void identityClientContextHandshakeWorks() throws Exception {
        // Reproduces the LocalSession setup: client context carries an identity key manager.
        var serverCert = SelfSignedCerts.generate("tls-test", 30);
        var sks = java.security.KeyStore.getInstance("PKCS12");
        sks.load(null, null);
        sks.setKeyEntry("k", serverCert.key(), "pw".toCharArray(),
                new java.security.cert.Certificate[]{serverCert.cert()});
        SSLContext serverCtx = SelfSignedCerts.serverContext(sks, "pw".toCharArray());

        var clientCert = SelfSignedCerts.generate("client", 30);
        var cks = java.security.KeyStore.getInstance("PKCS12");
        cks.load(null, null);
        cks.setKeyEntry("k", clientCert.key(), "pw".toCharArray(),
                new java.security.cert.Certificate[]{clientCert.cert()});
        SSLContext clientCtx = SelfSignedCerts.trustAllContext(cks, "pw".toCharArray());

        var listener = TlsConnections.listen("127.0.0.1", 55401, serverCtx);
        Thread.ofVirtual().start(() -> {
            try {
                var ssl = TlsConnections.accept(listener, 5000);
                ssl.getOutputStream().write("ok".getBytes());
                ssl.getOutputStream().flush();
                ssl.close();
            } catch (Exception e) {
                System.err.println("ACCEPT EX: " + e);
            }
        });
        var result = TlsConnections.connect("127.0.0.1", 55401, null, clientCtx, 5000);
        byte[] buf = result.socket().getInputStream().readNBytes(2);
        assertEquals("ok", new String(buf));
        listener.close();
    }
}
