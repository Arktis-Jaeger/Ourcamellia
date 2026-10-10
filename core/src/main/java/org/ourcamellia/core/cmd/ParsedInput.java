package org.ourcamellia.core.cmd;

import java.util.List;

/**
 * Result of parsing one logical input line.
 *
 * - {@link Message}: ordinary text (default `say` operation). Never command-parsed.
 * - {@link Command}: exactly one complete command expression matched.
 * - {@link Malformed}: input starts with "${" but does not match the grammar; the UI
 *   must show the reason and execute nothing.
 * - {@link Blank}: empty/whitespace-only input; no-op.
 */
public sealed interface ParsedInput permits ParsedInput.Message, ParsedInput.Command,
        ParsedInput.Malformed, ParsedInput.Blank {

    record Message(String text) implements ParsedInput {}

    record Command(String name, List<Arg> args) implements ParsedInput {}

    record Malformed(String reason) implements ParsedInput {}

    record Blank() implements ParsedInput {}
}
