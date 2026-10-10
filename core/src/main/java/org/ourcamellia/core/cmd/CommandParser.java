package org.ourcamellia.core.cmd;

import java.util.ArrayList;
import java.util.List;

/**
 * Deterministic, non-recursive parser for the formal grammar in
 * docs/COMMAND_GRAMMAR.md. A single pass over the characters; no recursion into
 * payloads; strict whole-line matching with trailing spaces permitted.
 */
public final class CommandParser {

    public static final int MAX_ARGS = 16;
    public static final int MAX_LINE = 64 * 1024;

    /**
     * Parses one logical input line.
     *
     * @param oldModeNewlineEscape when true, "\n" inside message text becomes a
     *                             newline (Old-mode convention); "\${" is always
     *                             unescaped to "${" in message text.
     */
    public static ParsedInput parse(String line, boolean oldModeNewlineEscape) {
        if (line == null) {
            return new ParsedInput.Blank();
        }
        if (line.length() > MAX_LINE) {
            return new ParsedInput.Malformed("input exceeds " + MAX_LINE + " characters");
        }
        if (line.isBlank()) {
            return new ParsedInput.Blank();
        }
        if (line.startsWith("${")) {
            return parseCommand(line);
        }
        return new ParsedInput.Message(unescapeMessage(line, oldModeNewlineEscape));
    }

    public static ParsedInput parse(String line) {
        return parse(line, false);
    }

    // ---------- message escape processing ----------

    public static String unescapeMessage(String text, boolean newlineEscape) {
        if (text.indexOf('\\') < 0) {
            return text;
        }
        StringBuilder sb = new StringBuilder(text.length());
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == '\\' && i + 1 < text.length()) {
                char next = text.charAt(i + 1);
                if (next == '$' && i + 2 < text.length() && text.charAt(i + 2) == '{') {
                    sb.append("${");
                    i += 2;
                    continue;
                }
                if (next == 'n' && newlineEscape) {
                    sb.append('\n');
                    i += 1;
                    continue;
                }
                // unknown escape: keep the backslash literally
                sb.append('\\');
                continue;
            }
            sb.append(c);
        }
        return sb.toString();
    }

    // ---------- command parsing ----------

    private static ParsedInput parseCommand(String line) {
        int i = 2; // past "${"
        int n = line.length();

        // name
        int nameStart = i;
        while (i < n && isNameChar(line.charAt(i), i == nameStart)) {
            i++;
        }
        if (i == nameStart) {
            return malformed("expected a command name");
        }
        String name = line.substring(nameStart, i);

        List<Arg> args = new ArrayList<>();

        if (i >= n) {
            return malformed("unterminated command (missing '}')");
        }
        char c = line.charAt(i);
        if (c == '}') {
            return finishAfterClose(line, i + 1, name, args);
        }
        if (c == ' ' || c == '\t') {
            return malformed("arguments must be inside parentheses: ${" + name + "(...)}");
        }
        if (c != '(') {
            return malformed("unexpected character '" + c + "' after command name");
        }
        i++; // past '('

        boolean expectArg = true;
        while (true) {
            i = skipSpaces(line, i, n);
            if (i >= n) {
                return malformed("unterminated command (missing ')')");
            }
            c = line.charAt(i);
            if (c == ')') {
                if (expectArg && !args.isEmpty()) {
                    return malformed("trailing comma before ')'");
                }
                return finishAfterParen(line, i + 1, name, args);
            }
            if (args.size() >= MAX_ARGS) {
                return malformed("too many arguments (max " + MAX_ARGS + ")");
            }
            int[] end = new int[1];
            Arg arg = parseArg(line, i, n, end);
            if (arg == null) {
                return malformed("malformed argument at position " + i);
            }
            args.add(arg);
            i = end[0];
            expectArg = false;

            int j = skipSpaces(line, i, n);
            if (j >= n) {
                return malformed("unterminated command (missing ')')");
            }
            char sep = line.charAt(j);
            if (sep == ',') {
                i = j + 1;
                expectArg = true;
                continue;
            }
            if (sep == ')') {
                return finishAfterParen(line, j + 1, name, args);
            }
            if (isArgStart(sep)) {
                // space-separated arguments are accepted (canonical separator is ',')
                i = j;
                continue;
            }
            return malformed("expected ',' or ')' but found '" + sep + "'");
        }
    }

    private static int skipSpaces(String line, int i, int n) {
        while (i < n && (line.charAt(i) == ' ' || line.charAt(i) == '\t')) {
            i++;
        }
        return i;
    }

    /** i is just after ')': skip spaces, require '}', then trailing-whitespace check. */
    private static ParsedInput finishAfterParen(String line, int i, String name, List<Arg> args) {
        int n = line.length();
        i = skipSpaces(line, i, n);
        if (i >= n) {
            return malformed("unterminated command (missing '}')");
        }
        if (line.charAt(i) != '}') {
            return malformed("unexpected content after command arguments");
        }
        return finishAfterClose(line, i + 1, name, args);
    }

    /** i is just after '}': only trailing spaces/tabs are allowed. */
    private static ParsedInput finishAfterClose(String line, int i, String name, List<Arg> args) {
        int n = line.length();
        while (i < n) {
            char c = line.charAt(i);
            if (c != ' ' && c != '\t') {
                return malformed("unexpected content after command");
            }
            i++;
        }
        return new ParsedInput.Command(name, List.copyOf(args));
    }

    /** Parses one argument; records the end index in {@code end[0]}. */
    private static Arg parseArg(String line, int i, int n, int[] end) {
        char c = line.charAt(i);
        if (c == '"') {
            return parseString(line, i, n, end);
        }
        if (c == '-' || Character.isDigit(c)) {
            Arg num = parseNumber(line, i, n, end);
            return num != null ? num : parseAtom(line, i, n, end);
        }
        if (isNameChar(c, true)) {
            // boolean literals must be a complete token
            if (line.startsWith("true", i)) {
                int e = i + 4;
                if (e >= n || isArgBoundary(line.charAt(e))) {
                    end[0] = e;
                    return new Arg.Bool(true);
                }
            }
            if (line.startsWith("false", i)) {
                int e = i + 5;
                if (e >= n || isArgBoundary(line.charAt(e))) {
                    end[0] = e;
                    return new Arg.Bool(false);
                }
            }
            return parseAtom(line, i, n, end);
        }
        // atoms may start with '$', '{', '}', '@', '.', '_', '-', digits etc.
        if (isAtomChar(c)) {
            return parseAtom(line, i, n, end);
        }
        return null;
    }

    private static Arg parseString(String line, int i, int n, int[] end) {
        StringBuilder sb = new StringBuilder();
        i++; // opening quote
        while (i < n) {
            char c = line.charAt(i);
            if (c == '"') {
                end[0] = i + 1;
                return new Arg.Str(sb.toString());
            }
            if (c == '\\' && i + 1 < n) {
                char e = line.charAt(i + 1);
                switch (e) {
                    case '\\' -> sb.append('\\');
                    case '"' -> sb.append('"');
                    case 'n' -> sb.append('\n');
                    case 't' -> sb.append('\t');
                    case '$' -> sb.append('$');
                    case '{' -> sb.append('{');
                    default -> sb.append('\\').append(e); // unknown escape kept literally
                }
                i += 2;
                continue;
            }
            if (c == '\n' || c == '\r') {
                return null; // raw newline inside a quoted string is not allowed
            }
            if (c < 0x20 || (c >= 0x7F && c <= 0x9F)) {
                return null; // control characters rejected
            }
            sb.append(c);
            i++;
        }
        return null; // unterminated string
    }

    private static Arg parseNumber(String line, int i, int n, int[] end) {
        int start = i;
        if (line.charAt(i) == '-') {
            i++;
            if (i >= n || !Character.isDigit(line.charAt(i))) {
                return null; // lone '-' → atom
            }
        }
        while (i < n && Character.isDigit(line.charAt(i))) {
            i++;
        }
        if (i < n && line.charAt(i) == '.') {
            i++;
            if (i >= n || !Character.isDigit(line.charAt(i))) {
                return null; // "12." → atom
            }
            while (i < n && Character.isDigit(line.charAt(i))) {
                i++;
            }
        }
        if (i < n && !isArgBoundary(line.charAt(i))) {
            return null; // "12abc" → atom
        }
        String raw = line.substring(start, i);
        try {
            double v = Double.parseDouble(raw);
            if (Double.isInfinite(v) || Double.isNaN(v)) {
                return null;
            }
            end[0] = i;
            return new Arg.Num(v, raw);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private static Arg parseAtom(String line, int i, int n, int[] end) {
        int start = i;
        while (i < n && isAtomChar(line.charAt(i))) {
            i++;
        }
        if (i == start) {
            return null;
        }
        end[0] = i;
        return new Arg.Atom(line.substring(start, i));
    }

    private static boolean isArgBoundary(char c) {
        return c == ' ' || c == '\t' || c == ',' || c == ')';
    }

    private static boolean isArgStart(char c) {
        return c != ' ' && c != '\t' && c != ',' && c != ')' && c != '(';
    }

    private static boolean isNameChar(char c, boolean first) {
        if (c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
            return true;
        }
        return !first && (Character.isDigit(c) || c == '-' || c == '_');
    }

    private static boolean isAtomChar(char c) {
        return c != ' ' && c != '\t' && c != '"' && c != ',' && c != '(' && c != ')'
                && c != '\\' && c != '\n' && c != '\r'
                && !(c < 0x20) && !(c >= 0x7F && c <= 0x9F);
    }

    private static ParsedInput malformed(String reason) {
        return new ParsedInput.Malformed(reason);
    }
}
