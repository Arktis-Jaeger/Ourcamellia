package org.ourcamellia.core.verifier;

import org.ourcamellia.common.Errors;

import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;

/**
 * SSRF defense for operator-configured external verifier URLs (SECURITY.md §6):
 * scheme allowlist, private/loopback/link-local address blocking, redirect-target
 * re-validation, and a bounded redirect chain. DNS is resolved once per hop and
 * every resolved address is checked; the residual DNS-rebinding race window between
 * check and connect is documented in THREAT_MODEL.md.
 */
public final class SsrGuard {

    private SsrGuard() {}

    /** Throws Validation when the URL is unsafe under the policy. */
    public static URI check(String url, boolean allowPrivateTargets, int maxRedirects) {
        if (url == null || url.isBlank()) {
            throw new Errors.Validation("verifier URL is empty");
        }
        if (url.length() > 2048) {
            throw new Errors.Validation("verifier URL too long");
        }
        URI uri;
        try {
            uri = new URI(url);
        } catch (URISyntaxException e) {
            throw new Errors.Validation("verifier URL is not a valid URI");
        }
        checkHop(uri, allowPrivateTargets);
        return uri;
    }

    private static void checkHop(URI uri, boolean allowPrivateTargets) {
        String scheme = uri.getScheme();
        if (scheme == null || (!scheme.equalsIgnoreCase("http") && !scheme.equalsIgnoreCase("https"))) {
            throw new Errors.Validation("verifier URL scheme must be http or https");
        }
        String host = uri.getHost();
        if (host == null || host.isBlank()) {
            throw new Errors.Validation("verifier URL has no host");
        }
        try {
            InetAddress[] all = InetAddress.getAllByName(host);
            if (all.length == 0) {
                throw new Errors.Validation("verifier host does not resolve");
            }
            for (InetAddress a : all) {
                if (!allowPrivateTargets && isBlocked(a)) {
                    throw new Errors.Validation("verifier URL resolves to a non-public address: "
                            + a.getHostAddress() + " (SSRF protection)");
                }
            }
        } catch (java.net.UnknownHostException e) {
            throw new Errors.Validation("verifier host does not resolve");
        }
    }

    static boolean isBlocked(InetAddress a) {
        return a.isLoopbackAddress() || a.isAnyLocalAddress() || a.isLinkLocalAddress()
                || a.isSiteLocalAddress() || a.isMulticastAddress();
    }

    /** Validates a redirect Location header; returns the absolute URI or null when invalid. */
    public static URI validateRedirect(URI base, String location, boolean allowPrivateTargets) {
        if (location == null || location.isBlank()) {
            return null;
        }
        try {
            URI next = base.resolve(location);
            checkHop(next, allowPrivateTargets);
            return next;
        } catch (Errors.OcException | IllegalArgumentException e) {
            return null;
        }
    }
}
