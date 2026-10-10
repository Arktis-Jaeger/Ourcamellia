package org.ourcamellia.common;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class SelfSignedCertsTest {

    @Test
    void generateIsStableAndLoadable(@TempDir Path dir) throws Exception {
        var gen = SelfSignedCerts.generate("Test Peer", 365);
        assertNotNull(gen.cert());
        assertEquals("CN=Test-Peer", gen.cert().getSubjectX500Principal().getName());
        String fp = gen.fingerprint();
        assertEquals(64, fp.length());
        assertTrue(fp.matches("[0-9a-f]{64}"));

        Path ks = dir.resolve("k.p12");
        SelfSignedCerts.saveKeystore(ks, gen.cert(), gen.key(), "pass123");
        assertTrue(java.nio.file.Files.exists(ks));

        var loaded = SelfSignedCerts.loadKeystore(ks, "pass123");
        assertEquals(fp, loaded.fingerprint());
        assertEquals(gen.cert().getSerialNumber(), loaded.cert().getSerialNumber());
    }

    @Test
    void wrongKeystorePasswordFails(@TempDir Path dir) {
        var gen = SelfSignedCerts.generate("X", 30);
        Path ks = dir.resolve("k.p12");
        SelfSignedCerts.saveKeystore(ks, gen.cert(), gen.key(), "right");
        assertThrows(Errors.Persistence.class, () -> SelfSignedCerts.loadKeystore(ks, "wrong"));
    }

    @Test
    void pinningContextWorks(@TempDir Path dir) throws Exception {
        var gen = SelfSignedCerts.generate("Pin", 30);
        Path ks = dir.resolve("k.p12");
        SelfSignedCerts.saveKeystore(ks, gen.cert(), gen.key(), "pw");
        javax.net.ssl.SSLContext ctx =
                SelfSignedCerts.pinningContext(gen.cert(), null, null);
        assertNotNull(ctx);
    }
}
