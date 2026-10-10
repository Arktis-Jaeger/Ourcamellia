package org.ourcamellia.client;

import org.ourcamellia.common.domain.ConversationRef;
import org.ourcamellia.common.domain.Message;
import org.ourcamellia.common.domain.PeerStatus;
import org.ourcamellia.common.domain.SessionMode;
import org.ourcamellia.core.app.AppEvents;
import org.ourcamellia.core.app.ClientApp;
import org.ourcamellia.core.app.ClientAppFactory;
import org.ourcamellia.core.app.CommandSet;
import org.ourcamellia.core.app.ExitPolicy;
import org.ourcamellia.core.cmd.CommandDef;
import org.ourcamellia.core.cmd.CommandDispatcher;
import org.ourcamellia.core.cmd.CommandResult;
import org.ourcamellia.core.cmd.ParsedInput;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Old mode: traditional line-oriented I/O (REQUIREMENTS §2.1). No ANSI cursor
 * positioning, no screen clearing — suitable for scripts, logs, pipes, and limited
 * terminals. Shares the identical application core and command semantics as
 * Observatory mode. Input convention: "\n" inside a message is a newline; "\${" is a
 * literal "${".
 */
public final class OldUi {

    private final ClientApp app;
    private final BufferedReader in;
    private final PrintStream out;
    private final boolean interactive;
    private final CommandDispatcher dispatcher = new CommandDispatcher();
    private boolean notifyMode = false;

    public OldUi(ClientApp app, InputStream stdin, PrintStream stdout) {
        this.app = app;
        this.in = new BufferedReader(new InputStreamReader(stdin, StandardCharsets.UTF_8));
        this.out = stdout;
        this.interactive = System.console() != null;
        new CommandSet(app, new CommandSet.Prompts() {
            @Override
            public String promptSecret(String label) {
                out.print(label + ": ");
                out.flush();
                try {
                    String line = in.readLine();
                    if (line == null) {
                        throw new org.ourcamellia.common.Errors.Usage("no input available for " + label);
                    }
                    return line;
                } catch (IOException e) {
                    throw new org.ourcamellia.common.Errors.Usage("cannot read input");
                }
            }

            @Override
            public String promptLine(String label) {
                return promptSecret(label);
            }
        }).install(dispatcher);
    }

    public void run() {
        ClientAppFactory.attachEvents(app, new OldEvents());
        out.println("Ourcamellia client (old mode). Type ${help} for commands, ${quit} to exit.");
        while (!app.exitRequested()) {
            String line = readLine();
            if (line == null) {
                // EOF: treat as quit with the exit-prompt policy.
                if (handleExit()) {
                    break;
                }
                continue;
            }
            handleLine(line);
        }
        app.close();
    }

    private void handleLine(String line) {
        // Old mode trims the input line (documented; quoted strings preserve inner spaces).
        line = line.strip();
        ParsedInput parsed = org.ourcamellia.core.cmd.CommandParser.parse(line, true);
        if (parsed instanceof ParsedInput.Command cmd) {
            // "${info}" / "${notify}" open the notification list: the next input line
            // may use the "<n> pass|reject|over" shortcut.
            notifyMode = (cmd.name().equals("info") || cmd.name().equals("notify"))
                    && cmd.args().isEmpty();
            CommandResult result = dispatcher.dispatch(cmd, context());
            printResult(result);
            if (result.exitRequested()) {
                if (handleExit()) {
                    app.requestExit();
                }
            }
            return;
        }
        if (parsed instanceof ParsedInput.Malformed mal) {
            notifyMode = false;
            out.println("error: malformed command — " + mal.reason() + " (nothing was sent or executed)");
            return;
        }
        if (parsed instanceof ParsedInput.Blank) {
            return;
        }
        ParsedInput.Message message = (ParsedInput.Message) parsed;
        // Notification shortcuts: "<n> pass|reject|over" while the notification list is open.
        if (notifyMode && message.text().matches("^\\d+\\s+(pass|reject|over)$")) {
            String[] parts = message.text().split("\\s+");
            int index = Integer.parseInt(parts[0]);
            out.println(app.notifyAction(index, parts[1]));
            return;
        }
        notifyMode = false;
        try {
            app.say(message.text());
        } catch (org.ourcamellia.common.Errors.OcException e) {
            out.println("error: " + e.getMessage());
        }
    }

    private void printResult(CommandResult result) {
        for (String line : result.lines()) {
            if (!line.isBlank()) {
                out.println(line);
            }
        }
    }

    private CommandDef.Context context() {
        if (app.mode() == SessionMode.NONE) {
            return CommandDef.Context.L1;
        }
        return app.currentConversation() == null ? CommandDef.Context.L2 : CommandDef.Context.L3;
    }

    private String readLine() {
        out.print(prompt());
        out.flush();
        try {
            return in.readLine();
        } catch (IOException e) {
            out.println("error: input failed: " + e.getMessage());
            return null;
        }
    }

    private String prompt() {
        return switch (context()) {
            case L1 -> "(menu)> ";
            case L2 -> "(list)> ";
            case L3 -> "(" + app.currentConversation().title() + ")> ";
            case ANY -> "> ";
        };
    }

    /** Exit-prompt policy (P3): prompt only for buffered content; never non-interactively. */
    private boolean handleExit() {
        String key = currentKeyOrNull();
        boolean buffered = key != null && app.hasBuffered(key);
        ExitPolicy.Decision decision = ExitPolicy.decide(buffered, interactive);
        if (!decision.promptNeeded()) {
            if (decision.message() != null) {
                out.println(decision.message());
            }
            return true;
        }
        while (true) {
            out.print("the current conversation has unpersisted buffered messages. Persist them before exiting? (y/n/c): ");
            out.flush();
            try {
                String answer = in.readLine();
                if (answer == null) {
                    return true;
                }
                switch (answer.trim().toLowerCase()) {
                    case "y" -> {
                        int n = app.persist(key);
                        out.println("persisted " + n + " message(s)");
                        return true;
                    }
                    case "n" -> {
                        out.println("buffered messages discarded");
                        return true;
                    }
                    case "c" -> {
                        out.println("exit cancelled");
                        return false;
                    }
                    default -> out.println("please answer y, n, or c");
                }
            } catch (IOException e) {
                return true;
            }
        }
    }

    private String currentKeyOrNull() {
        ConversationRef cur = app.currentConversation();
        if (cur == null) {
            return null;
        }
        if (app.mode() == SessionMode.LOCAL && app.local() != null) {
            return app.local().convKey(cur.id());
        }
        if (app.mode() == SessionMode.SERVER && app.server() != null) {
            return app.server().convKey(cur);
        }
        return null;
    }

    private final class OldEvents implements AppEvents {
        @Override
        public void onMessage(ConversationRef conversation, Message message) {
            out.println(message.sender() + "> " + org.ourcamellia.common.Text.renderable(message.text()));
        }

        @Override
        public void onStatusChanged() {
        }

        @Override
        public void onNotificationsChanged() {
        }

        @Override
        public void onInfo(String text) {
            out.println("· " + text);
        }

        @Override
        public void onPeerStatus(String peerName, PeerStatus status) {
            out.println("· " + peerName + " is now " + status.name().toLowerCase());
        }

        @Override
        public void onShutdown() {
        }
    }
}
