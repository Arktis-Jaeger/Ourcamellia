package org.ourcamellia.core.app;

import java.util.Comparator;

/**
 * Conversation-list ordering required by REQUIREMENTS §2.3: alphabetically A–Z,
 * then digits 1–0; deterministic tie-break by exact string comparison. Letter
 * comparison is case-insensitive (stable, documented rule for ties).
 */
public final class SortUtil {

    private SortUtil() {}

    public static final Comparator<String> SPEC_ORDER = (a, b) -> {
        int n = Math.min(a.length(), b.length());
        for (int i = 0; i < n; i++) {
            int ra = rank(a.charAt(i));
            int rb = rank(b.charAt(i));
            if (ra != rb) {
                return Integer.compare(ra, rb);
            }
            char ca = Character.toLowerCase(a.charAt(i));
            char cb = Character.toLowerCase(b.charAt(i));
            if (ca != cb) {
                return Character.compare(ca, cb);
            }
        }
        int len = Integer.compare(a.length(), b.length());
        if (len != 0) {
            return len;
        }
        return a.compareTo(b); // deterministic tie-break
    };

    private static int rank(char c) {
        if (Character.isLetter(c)) {
            return 0;
        }
        if (Character.isDigit(c)) {
            return 1;
        }
        return 2;
    }
}
