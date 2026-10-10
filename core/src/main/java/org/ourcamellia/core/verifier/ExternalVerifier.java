package org.ourcamellia.core.verifier;

import com.fasterxml.jackson.databind.JsonNode;
import org.ourcamellia.common.CryptoUtil;
import org.ourcamellia.common.Errors;
import org.ourcamellia.common.Json;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;

/**
 * External registration verifier client (REQUIREMENTS §4.2, SECURITY.md §6).
 *
 * Contract (documented in PROTOCOL.md):
 * - POST JSON {@code {v, ticketId, username, nonce, fields}} with headers
 *   {@code X-Ourcamellia-Ticket} and {@code X-Ourcamellia-Signature} =
 *   hex(HMAC-SHA256(sharedSecret, body)).
 * - The verifier replies JSON {@code {ticketId, status: approved|rejected|pending,
 *   nonce, signature}} where signature = hex(HMAC-SHA256(secret,
 *   nonce + "|" + ticketId + "|" + status)). Only a valid signature, matching
 *   ticketId, and echoed nonce are accepted — an unauthenticated callback is never
 *   treated as approval.
 * - Bounded timeout, retry limit, idempotent per ticket. No passwords or secondary
 *   passwords are ever sent; only the configured registration fields.
 * - Targets are operator-configured and SSRF-guarded (SsrGuard); redirects are
 *   followed manually with re-validation, up to maxRedirects.
 */
public final class ExternalVerifier {

    public enum Decision { APPROVED, REJECTED, PENDING, ERROR }

    public record Result(Decision decision, String message) {}

    private final String url;
    private final String secret;
    private final int timeoutMs;
    private final int maxRetries;
    private final boolean allowPrivateTargets;
    private final int maxRedirects;
    private final HttpClient client;

    public ExternalVerifier(String url, String secret, int timeoutMs, int maxRetries,
                            boolean allowPrivateTargets, int maxRedirects) {
        this.url = url;
        this.secret = secret;
        this.timeoutMs = timeoutMs;
        this.maxRetries = maxRetries;
        this.allowPrivateTargets = allowPrivateTargets;
        this.maxRedirects = maxRedirects;
        SsrGuard.check(url, allowPrivateTargets, maxRedirects);
        this.client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofMillis(timeoutMs))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

    /** Sends a registration decision request; never throws (network problems → ERROR). */
    public Result submit(String ticketId, String username, Map<String, String> fields) {
        String nonce = CryptoUtil.randomHex(16);
        var body = Json.object();
        body.put("v", 1);
        body.put("ticketId", ticketId);
        body.put("username", username);
        body.put("nonce", nonce);
        var f = body.putObject("fields");
        fields.forEach(f::put);
        String payload = Json.write(body);

        int attempts = maxRetries + 1;
        for (int attempt = 0; attempt < attempts; attempt++) {
            try {
                HttpResponse<String> response = send(url, payload, ticketId);
                if (response.statusCode() >= 300 && response.statusCode() < 400) {
                    String location = response.headers().firstValue("location").orElse(null);
                    URI next = SsrGuard.validateRedirect(URI.create(url), location, allowPrivateTargets);
                    if (next == null) {
                        return new Result(Decision.ERROR, "verifier redirect target rejected (SSRF)");
                    }
                    return follow(next, 1, payload, ticketId, nonce);
                }
                return parse(response.body(), ticketId, nonce);
            } catch (Errors.OcException e) {
                return new Result(Decision.ERROR, e.getMessage());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return new Result(Decision.ERROR, "interrupted");
            } catch (Exception e) {
                if (attempt == attempts - 1) {
                    return new Result(Decision.ERROR, "verifier unreachable: " + e.getMessage());
                }
            }
        }
        return new Result(Decision.ERROR, "verifier unreachable");
    }

    private Result follow(URI target, int depth, String payload, String ticketId, String nonce) {
        if (depth > maxRedirects) {
            return new Result(Decision.ERROR, "too many verifier redirects");
        }
        try {
            HttpResponse<String> response = send(target.toString(), payload, ticketId);
            if (response.statusCode() >= 300 && response.statusCode() < 400) {
                String location = response.headers().firstValue("location").orElse(null);
                URI next = SsrGuard.validateRedirect(target, location, allowPrivateTargets);
                if (next == null) {
                    return new Result(Decision.ERROR, "verifier redirect target rejected (SSRF)");
                }
                return follow(next, depth + 1, payload, ticketId, nonce);
            }
            return parse(response.body(), ticketId, nonce);
        } catch (Errors.OcException e) {
            return new Result(Decision.ERROR, e.getMessage());
        } catch (Exception e) {
            return new Result(Decision.ERROR, "verifier unreachable: " + e.getMessage());
        }
    }

    private HttpResponse<String> send(String targetUrl, String payload, String ticketId)
            throws Exception {
        byte[] signature = CryptoUtil.hmacSha256(secret.getBytes(StandardCharsets.UTF_8),
                payload.getBytes(StandardCharsets.UTF_8));
        HttpRequest request = HttpRequest.newBuilder(URI.create(targetUrl))
                .timeout(Duration.ofMillis(timeoutMs))
                .header("Content-Type", "application/json")
                .header("X-Ourcamellia-Ticket", ticketId)
                .header("X-Ourcamellia-Signature", java.util.HexFormat.of().formatHex(signature))
                .POST(HttpRequest.BodyPublishers.ofString(payload, StandardCharsets.UTF_8))
                .build();
        return client.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    }

    private Result parse(String responseBody, String ticketId, String nonce) {
        JsonNode root;
        try {
            root = Json.parse(responseBody == null ? "" : responseBody);
        } catch (Errors.Malformed e) {
            return new Result(Decision.ERROR, "verifier returned invalid JSON");
        }
        String gotTicket = root.path("ticketId").asText("");
        String status = root.path("status").asText("");
        String gotNonce = root.path("nonce").asText("");
        String signature = root.path("signature").asText("");
        if (!gotTicket.equals(ticketId) || !gotNonce.equals(nonce)) {
            return new Result(Decision.ERROR, "verifier receipt did not match the request (forged?)");
        }
        if (!status.equals("approved") && !status.equals("rejected") && !status.equals("pending")) {
            return new Result(Decision.ERROR, "verifier returned an unknown status");
        }
        String canonical = nonce + "|" + ticketId + "|" + status;
        byte[] expected = CryptoUtil.hmacSha256(secret.getBytes(StandardCharsets.UTF_8),
                canonical.getBytes(StandardCharsets.UTF_8));
        String expectedHex = java.util.HexFormat.of().formatHex(expected);
        if (!CryptoUtil.safeEquals(expectedHex, signature)) {
            return new Result(Decision.ERROR, "verifier receipt signature invalid (rejected)");
        }
        String message = root.path("message").asText("");
        return new Result(switch (status) {
            case "approved" -> Decision.APPROVED;
            case "rejected" -> Decision.REJECTED;
            default -> Decision.PENDING;
        }, message);
    }
}
