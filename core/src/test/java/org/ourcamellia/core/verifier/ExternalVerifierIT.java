package org.ourcamellia.core.verifier;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.ourcamellia.common.CryptoUtil;

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/**
 * External verifier integration: HMAC-signed requests, authenticated receipts,
 * forged-receipt rejection, and SSRF protection. A local HttpServer plays the
 * operator-configured verifier (private targets are enabled for the test only —
 * the SSRF test verifies the default blocks loopback).
 */
class ExternalVerifierIT {

    @Test
    void approvesWithValidSignedReceipt() throws Exception {
        String secret = "test-secret";
        AtomicReference<String> receivedSignature = new AtomicReference<>();
        AtomicReference<String> receivedBody = new AtomicReference<>();
        HttpServer verifier = startVerifier((ticketId, nonce) -> {
            String canonical = nonce + "|" + ticketId + "|approved";
            byte[] sig = CryptoUtil.hmacSha256(secret.getBytes(StandardCharsets.UTF_8),
                    canonical.getBytes(StandardCharsets.UTF_8));
            return "{\"ticketId\":\"" + ticketId + "\",\"status\":\"approved\",\"nonce\":\""
                    + nonce + "\",\"signature\":\"" + java.util.HexFormat.of().formatHex(sig)
                    + "\",\"message\":\"ok\"}";
        }, receivedBody, receivedSignature);

        ExternalVerifier client = new ExternalVerifier("http://127.0.0.1:" + verifier.getAddress().getPort() + "/verify",
                secret, 5000, 1, true, 3);
        var result = client.submit("ticket-1", "@alice", Map.of("@Email", "a@b.c"));
        assertEquals(ExternalVerifier.Decision.APPROVED, result.decision());

        // The request was signed by us and carried the fields (not passwords).
        String body = receivedBody.get();
        assertTrue(body.contains("ticket-1"));
        assertTrue(body.contains("a@b.c"));
        assertFalse(body.toLowerCase().contains("password"));
        byte[] expected = CryptoUtil.hmacSha256(secret.getBytes(StandardCharsets.UTF_8),
                receivedBody.get().getBytes(StandardCharsets.UTF_8));
        assertEquals(java.util.HexFormat.of().formatHex(expected), receivedSignature.get());
        verifier.stop(0);
    }

    @Test
    void forgedReceiptIsRejected() throws Exception {
        String secret = "test-secret";
        HttpServer verifier = startVerifier((ticketId, nonce) ->
                "{\"ticketId\":\"" + ticketId + "\",\"status\":\"approved\",\"nonce\":\""
                        + nonce + "\",\"signature\":\"" + "0".repeat(64) + "\"}", null, null);
        ExternalVerifier client = new ExternalVerifier("http://127.0.0.1:" + verifier.getAddress().getPort() + "/verify",
                secret, 5000, 1, true, 3);
        var result = client.submit("ticket-2", "@alice", Map.of());
        assertEquals(ExternalVerifier.Decision.ERROR, result.decision());
        assertTrue(result.message().contains("signature"), "unauthenticated callback must be rejected");
        verifier.stop(0);
    }

    @Test
    void mismatchedTicketOrNonceIsRejected() throws Exception {
        String secret = "test-secret";
        HttpServer verifier = startVerifier((ticketId, nonce) -> {
            String canonical = nonce + "|" + ticketId + "|approved";
            byte[] sig = CryptoUtil.hmacSha256(secret.getBytes(StandardCharsets.UTF_8),
                    canonical.getBytes(StandardCharsets.UTF_8));
            return "{\"ticketId\":\"OTHER\",\"status\":\"approved\",\"nonce\":\""
                    + nonce + "\",\"signature\":\"" + java.util.HexFormat.of().formatHex(sig) + "\"}";
        }, null, null);
        ExternalVerifier client = new ExternalVerifier("http://127.0.0.1:" + verifier.getAddress().getPort() + "/verify",
                secret, 5000, 1, true, 3);
        var result = client.submit("ticket-3", "@alice", Map.of());
        assertEquals(ExternalVerifier.Decision.ERROR, result.decision());
        assertTrue(result.message().contains("did not match"));
        verifier.stop(0);
    }

    @Test
    void ssrfBlocksPrivateTargetsByDefault() {
        // Default policy (allowPrivateTargets=false) refuses loopback/private hosts.
        assertThrows(org.ourcamellia.common.Errors.Validation.class, () ->
                new ExternalVerifier("http://127.0.0.1:8080/verify", "s", 5000, 1, false, 3));
        assertThrows(org.ourcamellia.common.Errors.Validation.class, () ->
                new ExternalVerifier("http://192.168.1.10/verify", "s", 5000, 1, false, 3));
        assertThrows(org.ourcamellia.common.Errors.Validation.class, () ->
                new ExternalVerifier("http://[::1]/verify", "s", 5000, 1, false, 3));
        assertThrows(org.ourcamellia.common.Errors.Validation.class, () ->
                new ExternalVerifier("file:///etc/passwd", "s", 5000, 1, false, 3));
    }

    @Test
    void ssrfRedirectValidationBlocksPrivateTargets() {
        // Redirect targets are re-validated per hop under the operator's policy:
        // a redirect from a public verifier to a private address is refused.
        // IP literals keep this test hermetic (no DNS in the assertion path).
        java.net.URI base = java.net.URI.create("https://8.8.8.8/verify");
        assertNull(SsrGuard.validateRedirect(base, "http://127.0.0.1:1/steal", false));
        assertNull(SsrGuard.validateRedirect(base, "http://192.168.1.10/x", false));
        assertNull(SsrGuard.validateRedirect(base, "http://10.0.0.5/x", false));
        assertNull(SsrGuard.validateRedirect(base, "file:///etc/passwd", false));
        // Public redirect targets pass the same policy.
        assertNotNull(SsrGuard.validateRedirect(base, "https://8.8.8.8/verify", false));
    }

    @Test
    void redirectsAreFollowedWhenPolicyAllows() throws Exception {
        String secret = "test-secret";
        // Final hop approves with a valid receipt.
        HttpServer finalHop = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        finalHop.createContext("/final", exchange -> {
            try {
                String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
                var root = org.ourcamellia.common.Json.parse(body);
                String ticketId = root.path("ticketId").asText();
                String nonce = root.path("nonce").asText();
                byte[] sig = CryptoUtil.hmacSha256(secret.getBytes(StandardCharsets.UTF_8),
                        (nonce + "|" + ticketId + "|approved").getBytes(StandardCharsets.UTF_8));
                String response = "{\"ticketId\":\"" + ticketId
                        + "\",\"status\":\"approved\",\"nonce\":\"" + nonce
                        + "\",\"signature\":\"" + java.util.HexFormat.of().formatHex(sig) + "\"}";
                byte[] out = response.getBytes(StandardCharsets.UTF_8);
                exchange.sendResponseHeaders(200, out.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(out);
                }
            } catch (Exception e) {
                exchange.close();
            }
        });
        finalHop.start();
        HttpServer firstHop = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        firstHop.createContext("/verify", exchange -> {
            exchange.getResponseHeaders().add("Location",
                    "http://127.0.0.1:" + finalHop.getAddress().getPort() + "/final");
            exchange.sendResponseHeaders(302, -1);
            exchange.close();
        });
        firstHop.start();
        // Loopback is allowed for this test deployment; the redirect is followed.
        ExternalVerifier client = new ExternalVerifier(
                "http://127.0.0.1:" + firstHop.getAddress().getPort() + "/verify",
                secret, 5000, 1, true, 3);
        var result = client.submit("ticket-4", "@alice", Map.of());
        assertEquals(ExternalVerifier.Decision.APPROVED, result.decision());
        firstHop.stop(0);
        finalHop.stop(0);
    }

    @Test
    void unavailableVerifierYieldsErrorNotApproval() {
        ExternalVerifier client = new ExternalVerifier("http://127.0.0.1:1/verify",
                "secret", 1500, 0, true, 3);
        var result = client.submit("ticket-5", "@alice", Map.of());
        assertEquals(ExternalVerifier.Decision.ERROR, result.decision());
    }

    interface VerifierBehavior {
        String respond(String ticketId, String nonce);
    }

    private HttpServer startVerifier(VerifierBehavior behavior,
                                     AtomicReference<String> bodyOut,
                                     AtomicReference<String> sigOut) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/verify", exchange -> {
            try {
                String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
                var root = org.ourcamellia.common.Json.parse(body);
                String ticketId = root.path("ticketId").asText();
                String nonce = root.path("nonce").asText();
                if (bodyOut != null) {
                    bodyOut.set(body);
                }
                if (sigOut != null) {
                    sigOut.set(exchange.getRequestHeaders().getFirst("X-Ourcamellia-Signature"));
                }
                String response = behavior.respond(ticketId, nonce);
                byte[] out = response.getBytes(StandardCharsets.UTF_8);
                exchange.sendResponseHeaders(200, out.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(out);
                }
            } catch (Exception e) {
                exchange.close();
            }
        });
        server.start();
        return server;
    }
}
