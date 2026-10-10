package org.ourcamellia.common;

/**
 * Typed error hierarchy. Every user-facing failure carries a stable category so the
 * presentation layer can render consistent messages, and the API layer can map to
 * stable error codes. Messages must never contain secrets.
 */
public class Errors {

    /** Stable error categories, mirrored in the BOT API and CLI output. */
    public enum Category {
        USAGE,        // bad command line / wrong arguments
        VALIDATION,   // field content rejected by rules
        AUTH,         // authentication failure
        DENIED,       // authorization failure
        NOT_FOUND,    // target does not exist
        CONFLICT,     // state conflict (duplicate, busy)
        NETWORK,      // connection / timeout / transport
        MALFORMED,    // hostile or broken protocol data
        PERSISTENCE,  // storage failure
        RATE_LIMITED, // too many attempts
        INTERNAL      // unexpected bug
    }

    public static class OcException extends RuntimeException {
        public final Category category;

        public OcException(Category category, String message) {
            super(message);
            this.category = category;
        }

        public OcException(Category category, String message, Throwable cause) {
            super(message, cause);
            this.category = category;
        }
    }

    public static class Usage extends OcException {
        public Usage(String message) { super(Category.USAGE, message); }
    }

    public static class Validation extends OcException {
        public Validation(String message) { super(Category.VALIDATION, message); }
    }

    public static class Auth extends OcException {
        public Auth(String message) { super(Category.AUTH, message); }
    }

    public static class Denied extends OcException {
        public Denied(String message) { super(Category.DENIED, message); }
    }

    public static class NotFound extends OcException {
        public NotFound(String message) { super(Category.NOT_FOUND, message); }
    }

    public static class Conflict extends OcException {
        public Conflict(String message) { super(Category.CONFLICT, message); }
    }

    public static class Network extends OcException {
        public Network(String message) { super(Category.NETWORK, message); }

        public Network(String message, Throwable cause) {
            super(Category.NETWORK, message, cause);
        }
    }

    /** Socket read timeout — used internally to drive the heartbeat; not user-visible. */
    public static class FrameTimeout extends Network {
        public FrameTimeout() { super("frame read timeout"); }
    }

    public static class Malformed extends OcException {
        public Malformed(String message) { super(Category.MALFORMED, message); }
    }

    public static class Persistence extends OcException {
        public Persistence(String message, Throwable cause) { super(Category.PERSISTENCE, message, cause); }

        public Persistence(String message) { super(Category.PERSISTENCE, message); }
    }

    public static class RateLimited extends OcException {
        public RateLimited(String message) { super(Category.RATE_LIMITED, message); }
    }

    public static class Internal extends OcException {
        public Internal(String message, Throwable cause) { super(Category.INTERNAL, message, cause); }
    }
}
