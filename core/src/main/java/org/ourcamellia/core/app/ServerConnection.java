package org.ourcamellia.core.app;

import org.ourcamellia.common.Errors;
import org.ourcamellia.common.SelfSignedCerts;
import org.ourcamellia.common.protocol.Envelope;
import org.ourcamellia.common.protocol.Wire;
import org.ourcamellia.core.persist.AtomicFiles;
import org.ourcamellia.core.transport.Conn;
import org.ourcamellia.core.transport.ConnSession;
import org.ourcamellia.core.transport.SocketConn;
import org.ourcamellia.core.transport.TlsConnections;

import java.nio.file.Path;

/**
 * Server-mode connection establishment with TOFU pinning of the server certificate.
 * The client stores the pinned fingerprint per server address in its state; a changed
 * fingerprint is refused (possible impersonation) unless the user clears the pin.
 *
 * Full server protocol handling (login/register/friends/groups/notifications) is
 * implemented by ServerProtocol in Stage 4/5; this class owns the socket lifecycle.
 */
final class ServerConnection {

    private ServerConnection() {}

    static void connect(ServerSession session, String host, int port, String address) {
        var cfg = session.config();
        Path dataDir = session.app().dataDir();
        SelfSignedCerts.GeneratedCert identity;
        Path ks = dataDir.resolve("server-identity.p12");
        String ksPassword = readServerKsPassword(dataDir); // creates the password on first use
        try {
            if (java.nio.file.Files.exists(ks)) {
                identity = SelfSignedCerts.loadKeystore(ks, ksPassword);
            } else {
                identity = SelfSignedCerts.generate("ourcamellia-client", 3650);
                SelfSignedCerts.saveKeystore(ks, identity.cert(), identity.key(), ksPassword);
            }
        } catch (Errors.OcException e) {
            throw new Errors.Persistence("client identity unavailable: " + e.getMessage(), e);
        }
        // Client identity is presented only if the server asks for mutual TLS (v1 does not).
        var clientContext = SelfSignedCerts.trustAllContext(null, null);

        String expectedPin = PinGuard.expectedFingerprint(session.store(), address);
        var result = TlsConnections.connect(host, port, expectedPin, clientContext, cfg.connectTimeoutMs());
        PinGuard.check(session.store(), result.fingerprint(), address);
        String desc = host + ":" + port;
        SocketConn conn;
        try {
            conn = new SocketConn(result.socket(), desc, result.fingerprint(), cfg.maxFrameBytes());
        } catch (java.io.IOException e) {
            throw new Errors.Network("connection setup failed", e);
        }
        ConnSession cs = new ConnSession(conn, new ConnSession.Handler() {
            @Override
            public void onEnvelope(Conn c, Envelope envelope) {
                ServerProtocol.handle(session, c, envelope);
            }

            @Override
            public void onClosed(Conn c, String reason) {
                session.onClosed(reason);
            }
        }, cfg.pingIntervalMs(), cfg.readTimeoutMs());
        session.setSession(cs);
        cs.conn().send(Wire.hello("ourcamellia-client", String.valueOf(Envelope.PROTOCOL_VERSION)));
    }

    private static String readServerKsPassword(Path dataDir) {
        byte[] raw = AtomicFiles.readOrNull(dataDir.resolve("server-identity.password"));
        if (raw != null) {
            return new String(raw, java.nio.charset.StandardCharsets.US_ASCII).trim();
        }
        return createServerKsPassword(dataDir);
    }

    private static String createServerKsPassword(Path dataDir) {
        String pw = org.ourcamellia.common.CryptoUtil.randomHex(16);
        AtomicFiles.writeString(dataDir.resolve("server-identity.password"), pw + "\n");
        try {
            java.nio.file.Files.setPosixFilePermissions(dataDir.resolve("server-identity.password"),
                    java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
        } catch (Exception ignored) {
        }
        return pw;
    }
}
