package org.ourcamellia.common;

import java.util.UUID;

/** Stable identifier helpers. All cross-system IDs are UUIDv4 strings; nothing is derived from them. */
public final class Ids {

    private Ids() {}

    public static String newId() {
        return UUID.randomUUID().toString();
    }

    /** Validates a client-supplied ID string without trusting its content. */
    public static String requireId(String id, String what) {
        if (id == null || id.length() > 64) {
            throw new Errors.Validation(what + ": invalid identifier");
        }
        try {
            // Strict canonical UUID form only; anything else is rejected.
            UUID u = UUID.fromString(id);
            if (!u.toString().equals(id)) {
                throw new Errors.Validation(what + ": invalid identifier");
            }
            return id;
        } catch (IllegalArgumentException e) {
            throw new Errors.Validation(what + ": invalid identifier");
        }
    }

    public static boolean looksLikeId(String id) {
        if (id == null || id.length() > 64) {
            return false;
        }
        try {
            UUID u = UUID.fromString(id);
            return u.toString().equals(id);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
}
