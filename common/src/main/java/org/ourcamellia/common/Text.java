package org.ourcamellia.common;

/**
 * Text safety and identity validation. All user-supplied text crosses these rules
 * before it is stored, displayed, or sent — this is the terminal-escape-injection
 * defense (SECURITY.md threat item: terminal escape-sequence injection).
 */
public final class Text {

    public static final int MAX_MESSAGE = 16_384;      // 16 KiB per message
    public static final int MAX_NAME = 64;
    public static final int MAX_GROUP_NAME = 64;
    public static final int MAX_EMAIL = 254;

    private Text() {}

    /** True if the string contains C0/C1 control characters (including ESC). */
    public static boolean hasControlChars(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < 0x20 && c != '\n' && c != '\t' && c != '\r') {
                return true;
            }
            if (c >= 0x7F && c <= 0x9F) {
                return true;
            }
        }
        return false;
    }

    /** Validates free-form user text (messages). Newlines allowed; other controls rejected. */
    public static String requireCleanText(String text, String what, int maxLen) {
        if (text == null || text.isEmpty()) {
            throw new Errors.Validation(what + ": text must not be empty");
        }
        if (text.length() > maxLen) {
            throw new Errors.Validation(what + ": text exceeds " + maxLen + " characters");
        }
        if (hasControlChars(text)) {
            throw new Errors.Validation(what + ": text contains forbidden control characters");
        }
        return text;
    }

    /** Replaces unpaired surrogates, keeping the string valid UTF-8 after encoding. */
    public static String stripUnpairedSurrogates(String s) {
        if (s == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (Character.isHighSurrogate(c)) {
                if (i + 1 < s.length() && Character.isLowSurrogate(s.charAt(i + 1))) {
                    sb.append(c).append(s.charAt(i + 1));
                    i++;
                }
                // else drop the lone surrogate
            } else if (!Character.isLowSurrogate(c)) {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    /** Identity name rules: 1-64 chars from a conservative printable set. */
    public static final java.util.regex.Pattern NAME_RE =
            java.util.regex.Pattern.compile("[A-Za-z0-9._-]{1,64}");

    public static String requireLocalName(String name) {
        if (name == null || !NAME_RE.matcher(name).matches()) {
            throw new Errors.Validation(
                    "local username must be 1-64 characters of A-Z a-z 0-9 . _ -");
        }
        return name;
    }

    public static String requireServerName(String name) {
        if (name == null || !name.startsWith("@") || name.length() > 65) {
            throw new Errors.Validation("server username must start with @ and be at most 65 characters");
        }
        requireLocalName(name.substring(1));
        return name;
    }

    public static String requireDisplayName(String name, String what) {
        return requireCleanText(name, what, MAX_NAME);
    }

    public static String requireGroupName(String name) {
        return requireCleanText(name, "group name", MAX_GROUP_NAME);
    }

    public static String requireEmail(String email) {
        if (email == null || email.length() > MAX_EMAIL) {
            throw new Errors.Validation("email: invalid address");
        }
        if (hasControlChars(email)) {
            throw new Errors.Validation("email: invalid address");
        }
        int at = email.indexOf('@');
        if (at <= 0 || at != email.lastIndexOf('@') || at == email.length() - 1
                || email.contains(" ")) {
            throw new Errors.Validation("email: invalid address");
        }
        return email;
    }

    /** Renders text for terminal output, guaranteeing no raw ESC/control bytes reach the screen. */
    public static String renderable(String s) {
        if (s == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\n') {
                sb.append('\n'); // deliberate newlines are fine
            } else if (c == '\t') {
                sb.append(' ');
            } else if (c < 0x20 || (c >= 0x7F && c <= 0x9F)) {
                sb.append('\uFFFD');
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }
}
