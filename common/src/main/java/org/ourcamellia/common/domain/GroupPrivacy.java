package org.ourcamellia.common.domain;

/** Group privacy modes. Selected explicitly at creation; never conflated. */
public enum GroupPrivacy {
    /** Server operator may read content and moderate. */
    OPERATOR_VISIBLE,
    /** Server relays only ciphertext; operator cannot read content. */
    ENCRYPTED;

    public static GroupPrivacy parse(String s) {
        return switch (s == null ? "" : s.toLowerCase()) {
            case "open", "visible", "operator-visible" -> OPERATOR_VISIBLE;
            case "encrypted" -> ENCRYPTED;
            default -> throw new org.ourcamellia.common.Errors.Validation("unknown group privacy mode: " + s);
        };
    }

    public String wireName() {
        return this == OPERATOR_VISIBLE ? "operator-visible" : "encrypted";
    }
}
