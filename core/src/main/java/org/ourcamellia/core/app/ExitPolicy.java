package org.ourcamellia.core.app;

/**
 * Exit-prompt policy (REQUIREMENTS §8.2, approved narrow interpretation P3):
 * prompt only when the current conversation has buffered, unpersisted messages;
 * never prompt when nothing is buffered; never prompt when input is non-interactive
 * (the caller reports that buffered content will be lost instead).
 */
public final class ExitPolicy {

    public enum Action { PERSIST_AND_EXIT, DISCARD_AND_EXIT, CANCEL }

    public record Decision(boolean promptNeeded, Action defaultAction, String message) {}

    private ExitPolicy() {}

    public static Decision decide(boolean hasBufferedMessages, boolean interactive) {
        if (!hasBufferedMessages) {
            return new Decision(false, Action.DISCARD_AND_EXIT, null);
        }
        if (!interactive) {
            return new Decision(false, Action.DISCARD_AND_EXIT,
                    "note: unpersisted buffered messages will be lost (recording is off; "
                            + "use ${persist} before exiting to keep them)");
        }
        return new Decision(true, Action.CANCEL,
                "the current conversation has unpersisted buffered messages. Persist them before exiting? (y/n/c)");
    }
}
