package org.ourcamellia.core.transport;

import org.junit.jupiter.api.Test;
import org.ourcamellia.common.SelfSignedCerts;

import javax.net.ssl.SSLContext;

import static org.junit.jupiter.api.Assertions.*;

class TlsClientAuthIT {

    @Test
    void clientPresentsCertificate() throws Exception {
        var serverCert = SelfSignedCerts.generate("srv", 30);
        var sks = java.security.KeyStore.getInstance("PKCS12");
        sks.load(null, null);
        sks.setKeyEntry("k", serverCert.key(), "pw".toCharArray(),
                new java.security.cert.Certificate[]{serverCert.cert()});
        SSLContext serverCtx = SelfSignedCerts.serverContextWithTrustAll(sks, "pw".toCharArray());

        var clientCert = SelfSignedCerts.generate("client", 30);
        var cks = java.security.KeyStore.getInstance("PKCS12");
        cks.load(null, null);
        cks.setKeyEntry("k", clientCert.key(), "pw".toCharArray(),
                new java.security.cert.Certificate[]{clientCert.cert()});
        SSLContext clientCtx = SelfSignedCerts.trustAllContext(cks, "pw".toCharArray());

        var listener = TlsConnections.listen("127.0.0.1", 55420, serverCtx, true);
        Thread.ofVirtual().start(() -> {
            try {
                var ssl = TlsConnections.accept(listener, 5000);
                var chain = ssl.getSession().getPeerCertificates();
                System.err.println("SERVER GOT CLIENT CERT: "
                        + ((java.security.cert.X509Certificate) chain[0]).getSubjectX500Principal());
                ssl.getOutputStream().write("ok".getBytes());
                ssl.getOutputStream().flush();
                ssl.close();
            } catch (Exception e) {
                System.err.println("ACCEPT EX: " + e);
            }
        });
        var result = TlsConnections.connect("127.0.0.1", 55420, null, clientCtx, 5000);
        byte[] buf = result.socket().getInputStream().readNBytes(2);
        assertEquals("ok", new String(buf));
        listener.close();
    }
}
