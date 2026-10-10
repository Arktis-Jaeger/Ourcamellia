package org.ourcamellia.common.domain;

import org.ourcamellia.common.Errors;
import org.ourcamellia.common.Text;

/**
 * An identity in one namespace. Local-mode names are bare; Server-mode names carry
 * the "@" prefix and are scoped to one server. The two namespaces never mix.
 */
public record Identity(Mode mode, String name) {

    public enum Mode { LOCAL, SERVER }

    public static Identity local(String name) {
        return new Identity(Mode.LOCAL, Text.requireLocalName(name));
    }

    public static Identity server(String name) {
        return new Identity(Mode.SERVER, Text.requireServerName(name));
    }

    public static Identity parse(Mode mode, String raw) {
        return mode == Mode.LOCAL ? local(raw) : server(raw);
    }

    /** Stable key for maps/files within a client instance. */
    public String key() {
        return mode.name().toLowerCase() + ":" + name;
    }

    @Override
    public String toString() {
        return name;
    }

    public static Identity require(String keyLike, String what) {
        if (keyLike == null) {
            throw new Errors.Validation(what + ": missing identity");
        }
        if (keyLike.startsWith("@")) {
            return server(keyLike);
        }
        return local(keyLike);
    }
}
