package org.ourcamellia.core.cmd;

import java.util.List;

/**
 * Result of executing one command: success lines, error (with stable category), or
 * exit request. The presentation layer renders lines; business logic never writes to
 * the terminal.
 */
public record CommandResult(Status status, List<String> lines, boolean exitRequested) {

    public enum Status { OK, ERROR }

    public static CommandResult ok(String... lines) {
        return new CommandResult(Status.OK, List.of(lines), false);
    }

    public static CommandResult ok(List<String> lines) {
        return new CommandResult(Status.OK, List.copyOf(lines), false);
    }

    public static CommandResult error(String message) {
        return new CommandResult(Status.ERROR, List.of("error: " + message), false);
    }

    public static CommandResult exit(String... lines) {
        return new CommandResult(Status.OK, List.of(lines), true);
    }

    /** True when there is nothing worth displaying. */
    public boolean isEmpty() {
        return lines.isEmpty() || (lines.size() == 1 && lines.get(0).isEmpty());
    }
}
