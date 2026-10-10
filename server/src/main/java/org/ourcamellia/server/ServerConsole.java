package org.ourcamellia.server;

import org.ourcamellia.common.Errors;
import org.ourcamellia.common.Text;
import org.ourcamellia.common.config.ServerConfig;
import org.ourcamellia.core.cmd.Arg;
import org.ourcamellia.core.cmd.CommandDispatcher;
import org.ourcamellia.core.cmd.CommandResult;
import org.ourcamellia.core.cmd.CommandDef;
import org.ourcamellia.core.cmd.ParsedInput;
import org.ourcamellia.core.server.ServerCore;
import org.ourcamellia.core.server.ServerStateStore;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.EnumSet;
import java.util.List;

import static org.ourcamellia.core.cmd.CommandDef.Context.*;
import static org.ourcamellia.core.cmd.CommandDef.ParamType.*;

/**
 * The operator console: a local-only, line-oriented interface for server
 * administration (REQUIREMENTS §9). It runs on the server host over stdin — it is
 * never exposed over the network; host access is the operator authentication
 * boundary (documented). Commands use the same formal grammar as the client.
 */
public final class ServerConsole {

    private final ServerCore server;
    private final BufferedReader in;
    private final PrintStream out;
    private final CommandDispatcher dispatcher = new CommandDispatcher();
    private volatile boolean quit = false;

    public ServerConsole(ServerCore server, InputStream stdin, PrintStream stdout) {
        this.server = server;
        this.in = new BufferedReader(new InputStreamReader(stdin, StandardCharsets.UTF_8));
        this.out = stdout;
        install();
    }

    private void install() {
        dispatcher.register(def("admin", "add or remove an operator", "${admin(\"add\"|\"remove\", @name)}",
                        List.of(p("action", CHOICE, false, "add | remove"), p("name", STRING, false, "@name")), ANY),
                (args, ctx) -> {
                    String action = args.get(0).asString();
                    String name = Text.requireServerName(args.get(1).asString());
                    if (action.equals("add")) {
                        server.promote(name);
                    } else if (action.equals("remove")) {
                        server.demote(name);
                    } else {
                        throw new Errors.Usage("action must be add or remove");
                    }
                    return CommandResult.ok("done");
                });
        dispatcher.register(def("announce", "post to the announcement channel (all accounts)", "${announce(\"text\")}",
                        List.of(p("text", STRING, false, "announcement text")), ANY),
                (args, ctx) -> {
                    server.announce(args.get(0).asString());
                    return CommandResult.ok("announcement posted");
                });
        dispatcher.register(def("registration", "approve or reject a pending registration",
                        "${registration(\"approve\"|\"reject\", ticketId)}",
                        List.of(p("action", CHOICE, false, "approve | reject"), p("ticket", STRING, false, "ticket id")), ANY),
                (args, ctx) -> {
                    String action = args.get(0).asString();
                    if (action.equals("approve")) {
                        server.approveRegistration(args.get(1).asString());
                    } else if (action.equals("reject")) {
                        server.rejectRegistration(args.get(1).asString());
                    } else {
                        throw new Errors.Usage("action must be approve or reject");
                    }
                    return CommandResult.ok("done");
                });
        dispatcher.register(def("groups", "list groups with ids and privacy modes", "${groups}", List.of(), ANY),
                (args, ctx) -> {
                    List<String> lines = new java.util.ArrayList<>();
                    lines.add("groups (id · name · privacy · owner):");
                    for (var g : server.store().state().groups.values()) {
                        lines.add("  " + g.id + " · " + g.name + " · " + g.privacy + " · owner " + g.owner);
                    }
                    return CommandResult.ok(lines);
                });
        dispatcher.register(def("review", "show the operator review log of an operator-visible group",
                        "${review(groupId [, N])}",
                        List.of(p("groupId", STRING, false, "group id"), p("limit", NUMBER, true, "entries (default 20)")), ANY),
                (args, ctx) -> {
                    int limit = args.size() >= 2 ? ((Arg.Num) args.get(1)).asInt() : 20;
                    List<String> lines = new java.util.ArrayList<>();
                    for (var e : server.review(args.get(0).asString(), limit)) {
                        lines.add(e.ts() + " " + e.sender() + "> " + e.text());
                    }
                    if (lines.isEmpty()) {
                        lines.add("(no messages in the review log)");
                    }
                    return CommandResult.ok(lines);
                });
        dispatcher.register(def("mod-delete", "remove one operator-visible group message everywhere",
                        "${mod-delete(groupId, msgId)}",
                        List.of(p("groupId", STRING, false, "group id"), p("msgId", STRING, false, "message id")), ANY),
                (args, ctx) -> {
                    server.modDelete(args.get(0).asString(), args.get(1).asString());
                    return CommandResult.ok("moderation notice relayed");
                });
        dispatcher.register(def("bot-create", "create a BOT account (token shown once)",
                        "${bot-create(@name)}", List.of(p("name", STRING, false, "@name")), ANY),
                (args, ctx) -> {
                    String name = Text.requireServerName(args.get(0).asString());
                    var cred = server.createBot("operator", name);
                    return CommandResult.ok("BOT " + name + " created — store these credentials safely; they are shown once:",
                            "  token: " + cred.token(),
                            "  x25519 private key (base64): " + cred.x25519PrivateKeyBase64());
                });
        dispatcher.register(def("bot-revoke", "revoke all tokens of a BOT account",
                        "${bot-revoke(@name)}", List.of(p("name", STRING, false, "@name")), ANY),
                (args, ctx) -> {
                    server.revokeBotTokens("operator", Text.requireServerName(args.get(0).asString()));
                    return CommandResult.ok("tokens revoked");
                });
        dispatcher.register(def("policy", "show the server policy summary", "${policy}", List.of(), ANY),
                (args, ctx) -> CommandResult.ok(server.policySummary().split("\n")));
        dispatcher.register(def("stats", "show connection and account statistics", "${stats}", List.of(), ANY),
                (args, ctx) -> CommandResult.ok(server.stats()));
        dispatcher.register(def("help", "list console commands", "${help}", List.of(), ANY),
                (args, ctx) -> CommandResult.ok(dispatcher.helpText(ANY)));
        dispatcher.register(def("quit", "graceful shutdown", "${quit}", List.of(), ANY),
                (args, ctx) -> {
                    quit = true;
                    return CommandResult.exit("shutting down");
                });
    }

    public void run() {
        out.println("Ourcamellia server console. Type ${help} for commands, ${quit} to shut down.");
        while (!quit) {
            out.print("server> ");
            out.flush();
            String line;
            try {
                line = in.readLine();
            } catch (IOException e) {
                out.println("console input failed: " + e.getMessage());
                break;
            }
            if (line == null) {
                break; // EOF: keep serving; the console just stops reading
            }
            ParsedInput parsed = org.ourcamellia.core.cmd.CommandParser.parse(line, false);
            if (parsed instanceof ParsedInput.Command cmd) {
                CommandResult result = dispatcher.dispatch(cmd, ANY);
                for (String l : result.lines()) {
                    if (!l.isBlank()) {
                        out.println(l);
                    }
                }
            } else if (parsed instanceof ParsedInput.Malformed mal) {
                out.println("error: malformed command — " + mal.reason());
            } else if (parsed instanceof ParsedInput.Message m) {
                out.println("error: unknown input — type ${help} for console commands");
            }
        }
    }

    public boolean quitRequested() {
        return quit;
    }

    private static CommandDef def(String name, String summary, String usage,
                                  List<CommandDef.Param> params, CommandDef.Context... contexts) {
        EnumSet<CommandDef.Context> set = EnumSet.noneOf(CommandDef.Context.class);
        set.addAll(List.of(contexts));
        return new CommandDef(name, summary, usage, params, set);
    }

    private static CommandDef.Param p(String name, CommandDef.ParamType type, boolean optional, String desc) {
        return new CommandDef.Param(name, type, optional, desc);
    }
}
