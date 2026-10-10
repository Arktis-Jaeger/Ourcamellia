package org.ourcamellia.client;

import org.jline.terminal.Terminal;
import org.jline.terminal.TerminalBuilder;

import java.io.PrintWriter;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.util.Optional;

/**
 * Minimal raw-mode line editor over JLine's terminal: buffer + cursor, backspace,
 * left/right/home/end, Ctrl-C (cancel line), Ctrl-D (EOF on empty line), Ctrl-U
 * (clear). UTF-8 input is decoded incrementally; malformed bytes are dropped. No
 * line-wrapping for very long input (documented limitation).
 */
final class LineEditor {

    private final StringBuilder buf = new StringBuilder();
    private int cursor = 0;
    private final byte[] pending = new byte[8];   // incomplete UTF-8 bytes
    private int pendingLen = 0;
    private final java.nio.charset.CharsetDecoder decoder =
            java.nio.charset.StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT);

    void reset() {
        buf.setLength(0);
        cursor = 0;
        pendingLen = 0;
    }

    String text() {
        return buf.toString();
    }

    int cursor() {
        return cursor;
    }

    /** Feeds one byte; returns the submitted line (empty = blank submit), or null. */
    String feed(int b) {
        if (b < 0) {
            return null;
        }
        // --- control keys ---
        if (b == 13 || b == 10) { // enter
            String line = buf.toString();
            reset();
            return line;
        }
        if (b == 127 || b == 8) { // backspace
            if (cursor > 0) {
                buf.deleteCharAt(cursor - 1);
                cursor--;
            }
            return null;
        }
        if (b == 3) { // ctrl-c: cancel line
            reset();
            return null;
        }
        if (b == 4) { // ctrl-d
            if (buf.isEmpty()) {
                return ""; // EOF signal
            }
            if (cursor < buf.length()) {
                buf.deleteCharAt(cursor);
            }
            return null;
        }
        if (b == 21) { // ctrl-u: clear
            reset();
            return null;
        }
        if (b == 27) { // escape sequence — parsed by the caller
            return null;
        }
        if (b == 9) { // tab: ignored
            return null;
        }
        // --- printable UTF-8 (incremental decode) ---
        if (pendingLen >= pending.length) {
            pendingLen = 0; // give up on an over-long sequence
        }
        pending[pendingLen++] = (byte) b;
        java.nio.ByteBuffer in = java.nio.ByteBuffer.wrap(pending, 0, pendingLen);
        java.nio.CharBuffer out = java.nio.CharBuffer.allocate(4);
        java.nio.charset.CoderResult r = decoder.decode(in, out, false);
        // Emit any fully decoded characters first; underflow only means the decoder
        // wants more input for a possible continuation (the char may still be out).
        out.flip();
        while (out.hasRemaining()) {
            char c = out.get();
            if (!Character.isISOControl(c) && c != 127) {
                buf.insert(cursor, c);
                cursor++;
            }
        }
        if (r.isError()) {
            pendingLen = 0; // malformed byte dropped
            return null;
        }
        if (in.remaining() == 0) {
            pendingLen = 0; // input fully consumed
        }
        return null;
    }

    /** ANSI escape parser: D=left C=right A/B=history(no-op) H=home F=end. */
    void escape(String seq) {
        switch (seq) {
            case "D" -> cursor = Math.max(0, cursor - 1);
            case "C" -> cursor = Math.min(buf.length(), cursor + 1);
            case "H" -> cursor = 0;
            case "F" -> cursor = buf.length();
            default -> {
            }
        }
    }

    /** Draws prompt + buffer and positions the cursor at the end of the input. */
    void render(PrintWriter writer, String prompt, int terminalWidth) {
        String content = prompt + buf;
        String safe = org.ourcamellia.common.Text.renderable(content);
        if (safe.length() > terminalWidth) {
            // keep the cursor visible: show the tail of the input
            int keep = Math.max(prompt.length() + 1, terminalWidth - 1);
            safe = safe.substring(safe.length() - keep);
            writer.print(safe);
            writer.flush();
            return;
        }
        writer.print(safe);
        int back = buf.length() - cursor;
        if (back > 0) {
            writer.print("\u001b[" + back + "D");
        }
        writer.flush();
    }
}
