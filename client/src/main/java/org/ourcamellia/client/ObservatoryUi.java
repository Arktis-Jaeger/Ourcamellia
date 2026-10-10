package org.ourcamellia.client;

import org.jline.terminal.Terminal;
import org.jline.terminal.TerminalBuilder;
import org.ourcamellia.common.Errors;
import org.ourcamellia.common.Text;
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

import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;

/**
 * Observatory mode (REQUIREMENTS §2.1): fixed-layout terminal UI — a fixed-height
 * status region on top, an adaptive conversation region, and an input region at the
 * bottom. One render loop owns the display; asynchronous network events only mark
 * the view dirty, so the input cursor is never corrupted. Supports resize (WINCH),
 * narrow windows (compact fallback), and a clear error when the terminal is not
 * capable. Message content is sanitized (control characters stripped) before it
 * reaches the screen (terminal-injection defense).
 */
public final class ObservatoryUi {

    private static final int STATUS_LINES = 3;
    private static final int MAX_TRANSCRIPT_LINES = 2000;

    private final ClientApp app;
    private final Terminal terminal;
    private final PrintWriter writer;
    private final CommandDispatcher dispatcher = new CommandDispatcher();
    private final LineEditor editor = new LineEditor();
    private final ConcurrentLinkedQueue<String> infoLines = new ConcurrentLinkedQueue<>();
    private final ConcurrentLinkedQueue<String> chatLines = new ConcurrentLinkedQueue<>();
    private final List<String> transcript = new ArrayList<>();
    private volatile boolean dirty = true;
    private boolean notifyMode = false;
    private String activePrompt;   // non-null while a prompt is awaiting input
    private String promptResult;   // filled when the prompt line is submitted
    private String pendingExitAnswer; // y/n/c decision pending
    private StringBuilder escapeSeq;   // ANSI escape accumulation
    private int width = 80;
    private int height = 24;

    public static boolean supported() {
        try {
            TerminalBuilder.builder().system(true).dumb(true).build().close();
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    public ObservatoryUi(ClientApp app) throws IOException {
        this.app = app;
        this.terminal = TerminalBuilder.builder().system(true).build();
        if (terminal.getType() == null || terminal.getType().equals("dumb")) {
            throw new Errors.Usage("this terminal is not capable of Observatory mode — run with --mode old");
        }
        this.writer = terminal.writer();
        new CommandSet(app, new CommandSet.Prompts() {
            @Override
            public String promptSecret(String label) {
                return promptLine(label);
            }

            @Override
            public String promptLine(String label) {
                return awaitLine(label);
            }
        }).install(dispatcher);
    }

    public void run() {
        ClientAppFactory.attachEvents(app, new ObservatoryEvents());
        terminal.enterRawMode();
        java.io.InputStream input = terminal.input();
        terminal.handle(org.jline.terminal.Terminal.Signal.WINCH, signal -> {
            width = Math.max(20, terminal.getWidth());
            height = Math.max(6, terminal.getHeight());
            dirty = true;
        });
        width = Math.max(20, terminal.getWidth());
        height = Math.max(6, terminal.getHeight());
        addInfo("Observatory mode. Type ${help} for commands, ${quit} to exit.");

        while (!app.exitRequested()) {
            pump(input, 100);
            if (dirty) {
                render();
            }
        }
        try {
            terminal.close();
        } catch (IOException ignored) {
        }
        app.close();
    }

    /** Reads/processes input for up to timeoutMs; inner loops reuse this safely. */
    private void pump(java.io.InputStream input, long timeoutMs) {
        long deadline = System.currentTimeMillis() + timeoutMs;
        while (System.currentTimeMillis() < deadline) {
            int b = -1;
            try {
                if (input.available() > 0) {
                    b = input.read();
                }
            } catch (IOException e) {
                return;
            }
            if (b < 0) {
                try {
                    Thread.sleep(15);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    return;
                }
                continue;
            }
            handleByte(b);
            if (dirty) {
                render();
            }
        }
    }

    private void handleByte(int b) {
        if (b == 27) {
            escapeSeq = new StringBuilder();
            return;
        }
        if (escapeSeq != null) {
            if (escapeSeq.length() == 0 && (b == '[' || b == 'O')) {
                escapeSeq.append((char) b);
                return;
            }
            escapeSeq.append((char) b);
            if (escapeSeq.length() >= 2) {
                editor.escape(escapeSeq.substring(1));
                escapeSeq = null;
            }
            return;
        }
        String line = editor.feed(b);
        if (line == null) {
            return;
        }
        if (activePrompt != null) {
            promptResult = line;
            editor.reset();
            activePrompt = null;
            return;
        }
        if (pendingExitAnswer != null) {
            answerExit(line);
            return;
        }
        editor.reset();
        handleLine(line);
    }

    private void handleLine(String line) {
        ParsedInput parsed = org.ourcamellia.core.cmd.CommandParser.parse(line, false);
        if (parsed instanceof ParsedInput.Command cmd) {
            notifyMode = (cmd.name().equals("info") || cmd.name().equals("notify"))
                    && cmd.args().isEmpty();
            CommandResult result = dispatcher.dispatch(cmd, context());
            for (String out : result.lines()) {
                if (!out.isBlank()) {
                    addInfo(out);
                }
            }
            if (result.exitRequested()) {
                beginExit();
            }
            return;
        }
        if (parsed instanceof ParsedInput.Malformed mal) {
            notifyMode = false;
            addInfo("error: malformed command — " + mal.reason() + " (nothing was sent or executed)");
            return;
        }
        if (parsed instanceof ParsedInput.Blank) {
            return;
        }
        ParsedInput.Message message = (ParsedInput.Message) parsed;
        if (notifyMode && message.text().matches("^\\d+\\s+(pass|reject|over)$")) {
            String[] parts = message.text().split("\\s+");
            addInfo(app.notifyAction(Integer.parseInt(parts[0]), parts[1]));
            return;
        }
        notifyMode = false;
        try {
            app.say(message.text());
            addChat(app.local() != null
                    ? app.local().myName() : String.valueOf(app.server() == null ? "me" : app.server().loggedInUser())
                    , message.text());
        } catch (Errors.OcException e) {
            addInfo("error: " + e.getMessage());
        }
    }

    private void beginExit() {
        String key = currentKeyOrNull();
        boolean buffered = key != null && app.hasBuffered(key);
        ExitPolicy.Decision decision = ExitPolicy.decide(buffered, true);
        if (!decision.promptNeeded()) {
            app.requestExit();
            return;
        }
        addInfo(decision.message());
        pendingExitAnswer = "pending";
    }

    private void answerExit(String line) {
        pendingExitAnswer = null;
        switch (line.trim().toLowerCase()) {
            case "y" -> {
                String key = currentKeyOrNull();
                if (key != null) {
                    int n = app.persist(key);
                    addInfo("persisted " + n + " message(s)");
                }
                app.requestExit();
            }
            case "n" -> {
                addInfo("buffered messages discarded");
                app.requestExit();
            }
            default -> addInfo("exit cancelled");
        }
    }

    /** Blocks until a line is submitted (called during command dispatch). */
    private String awaitLine(String label) {
        addInfo(label);
        activePrompt = label;
        promptResult = null;
        java.io.InputStream input = terminal.input();
        while (promptResult == null && !app.exitRequested()) {
            pump(input, 80);
        }
        return promptResult == null ? "" : promptResult;
    }

    private CommandDef.Context context() {
        if (app.mode() == SessionMode.NONE) {
            return CommandDef.Context.L1;
        }
        return app.currentConversation() == null ? CommandDef.Context.L2 : CommandDef.Context.L3;
    }

    private void addInfo(String text) {
        infoLines.add(Text.renderable(text));
        dirty = true;
    }

    private void addChat(String sender, String text) {
        chatLines.add(Text.renderable(sender) + "> " + Text.renderable(text));
        dirty = true;
    }

    // ---------------- rendering ----------------

    private void render() {
        // Drain queued event lines into the bounded transcript.
        String line;
        while ((line = infoLines.poll()) != null) {
            transcript.addAll(wrap(line, width - 2));
        }
        while ((line = chatLines.poll()) != null) {
            transcript.addAll(wrap(line, width - 2));
        }
        while (transcript.size() > MAX_TRANSCRIPT_LINES) {
            transcript.remove(0);
        }
        if (height < 8 || width < 30) {
            renderCompact();
            return;
        }
        writer.print("\u001b[2J\u001b[H"); // clear + home
        int convLines = height - STATUS_LINES - 2;

        // Status region.
        writer.println(Text.renderable(statusLine1()));
        writer.println(Text.renderable(statusLine2()));
        writer.println(Text.renderable(statusLine3()));

        // Conversation region.
        List<String> view = conversationView(convLines);
        for (String l : view) {
            writer.println(l);
        }
        for (int i = view.size(); i < convLines; i++) {
            writer.println();
        }

        // Input region: prompt line, then the editor.
        writer.print(promptPrefix() + " ");
        editor.render(writer, "", width - promptPrefix().length() - 1);
        dirty = false;
    }

    private void renderCompact() {
        writer.print("\u001b[2J\u001b[H");
        writer.println("[terminal too small — compact mode] " + Text.renderable(statusLine1()));
        for (int i = 0; i < height - 3; i++) {
            writer.println();
        }
        writer.print(promptPrefix() + " ");
        editor.render(writer, "", Math.max(8, width - promptPrefix().length() - 1));
        dirty = false;
    }

    private List<String> conversationView(int maxLines) {
        List<String> out = new ArrayList<>();
        if (app.currentConversation() != null) {
            int from = Math.max(0, transcript.size() - maxLines);
            out.addAll(transcript.subList(from, transcript.size()));
            return out;
        }
        // Level 2: conversation list.
        List<ConversationRef> conversations = app.conversations();
        if (conversations.isEmpty()) {
            out.add(app.mode() == SessionMode.NONE
                    ? "menu — enter a mode: ${mode(\"local\", name)} or ${mode(\"server\", \"host:port\")}"
                    : "no conversations yet — use ${friend-request(...)} to reach out");
        } else {
            out.add("conversations:");
            for (ConversationRef ref : conversations) {
                String status = switch (app.peerStatus(ref.id())) {
                    case CONNECTED -> "(connected)";
                    case DISCOVERED -> "(seen)";
                    case UNREACHABLE -> "(unreachable)";
                    case UNCONFIRMED -> "";
                };
                out.add("  " + (ref.pinned() ? "◆ " : "  ") + ref.title() + " " + status);
            }
        }
        int from = Math.max(0, out.size() - maxLines);
        return out.subList(from, out.size());
    }

    private String statusLine1() {
        return switch (app.mode()) {
            case NONE -> "Ourcamellia — main menu";
            case LOCAL -> "Local  ·  you: " + app.local().myName();
            case SERVER -> "Server ·  " + (app.server().serverName() == null ? app.server().serverAddress()
                    : app.server().serverName()) + "  ·  "
                    + (app.server().loggedInUser() == null ? "(not logged in)" : app.server().loggedInUser());
        };
    }

    private String statusLine2() {
        if (app.mode() == SessionMode.LOCAL && app.local() != null) {
            ConversationRef cur = app.currentConversation();
            if (cur == null) {
                return "discoverable " + onOff(app.discoverable()) + " · connectable "
                        + onOff(app.connectable()) + " · " + app.local().friends().size() + " friend(s)";
            }
            return "peer: " + cur.title() + " · " + app.peerStatus(cur.id()).name().toLowerCase()
                    + " · " + app.friendState(cur.id()).name().toLowerCase();
        }
        if (app.mode() == SessionMode.SERVER && app.server() != null) {
            ConversationRef cur = app.currentConversation();
            if (cur == null) {
                return app.server().friends().size() + " friend(s) · "
                        + app.server().groups().size() + " group(s)";
            }
            return "conversation: " + cur.title()
                    + (cur.privacy() != null ? " · " + cur.privacy().name().toLowerCase() : "");
        }
        return "";
    }

    private String statusLine3() {
        ConversationRef cur = app.currentConversation();
        StringBuilder sb = new StringBuilder();
        if (cur != null) {
            String key = currentKeyOrNull();
            if (key != null) {
                sb.append("recording ").append(app.recording(key) ? "on" : "off")
                        .append(app.hasBuffered(key) ? " · " + bufferedCount(key) + " buffered" : "")
                        .append("   ");
            }
        }
        int n = app.notifications().size();
        sb.append("INFO").append(n > 0 ? "[" + n + "]" : "").append("  ");
        if (app.mode() == SessionMode.LOCAL && app.local() != null) {
            sb.append("identity ").append(shortFp(app.local().myFingerprint()));
        }
        return sb.toString();
    }

    private int bufferedCount(String key) {
        // buffered entries are in-memory only; the count is kept by the history store
        var c = app.history().conversation(key);
        return c == null ? 0 : c.buffered.size();
    }

    private String promptPrefix() {
        return switch (context()) {
            case L1 -> "(menu)";
            case L2 -> "(list)";
            case L3 -> "(" + app.currentConversation().title() + ")";
            case ANY -> ">";
        };
    }

    private String shortFp(String fp) {
        return fp == null || fp.length() < 12 ? "?" : fp.substring(0, 12) + "…";
    }

    private static String onOff(boolean b) {
        return b ? "on" : "off";
    }

    private static List<String> wrap(String text, int width) {
        if (text.length() <= width) {
            return List.of(text);
        }
        List<String> out = new ArrayList<>();
        while (text.length() > width) {
            out.add(text.substring(0, width));
            text = text.substring(width);
        }
        out.add(text);
        return out;
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

    private final class ObservatoryEvents implements AppEvents {
        @Override
        public void onMessage(ConversationRef conversation, Message message) {
            addChat(message.sender(), message.text());
        }

        @Override
        public void onStatusChanged() {
            dirty = true;
        }

        @Override
        public void onNotificationsChanged() {
            dirty = true;
        }

        @Override
        public void onInfo(String text) {
            addInfo(text);
        }

        @Override
        public void onPeerStatus(String peerName, PeerStatus status) {
            dirty = true;
        }

        @Override
        public void onShutdown() {
            dirty = true;
        }
    }
}
