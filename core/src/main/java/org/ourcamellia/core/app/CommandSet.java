package org.ourcamellia.core.app;

import org.ourcamellia.common.Errors;
import org.ourcamellia.common.Text;
import org.ourcamellia.common.domain.ConversationRef;
import org.ourcamellia.common.domain.FriendState;
import org.ourcamellia.common.domain.Notification;
import org.ourcamellia.common.domain.NotificationKind;
import org.ourcamellia.common.domain.SessionMode;
import org.ourcamellia.core.cmd.Arg;
import org.ourcamellia.core.cmd.CommandDef;
import org.ourcamellia.core.cmd.CommandDispatcher;
import org.ourcamellia.core.cmd.CommandResult;

import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;

import static org.ourcamellia.core.cmd.CommandDef.Context.*;
import static org.ourcamellia.core.cmd.CommandDef.ParamType.*;

/**
 * The canonical command set (docs/COMMAND_GRAMMAR.md §3), wired to the application
 * layer. Both CLI modes use exactly this set — business rules live in ClientApp, not
 * here. Password prompts go through the injected Prompts hook so each UI can secure
 * input its own way.
 */
public final class CommandSet {

    /** Secure input hooks provided by the UI. */
    public interface Prompts {
        String promptSecret(String label);

        String promptLine(String label);
    }

    private final ClientApp app;
    private final Prompts prompts;
    private CommandDispatcher dispatcher;

    public CommandSet(ClientApp app, Prompts prompts) {
        this.app = app;
        this.prompts = prompts;
    }

    public void install(CommandDispatcher d) {
        this.dispatcher = d;
        d.register(def("help", "list commands or describe one", "${help [name]}",
                        List.of(param("name", ATOM, true, "command name")), ANY),
                this::help);
        d.register(def("status", "show current status (connection, peers, recording)", "${status}",
                        List.of(), ANY),
                (args, ctx) -> CommandResult.ok(statusLines()));
        d.register(def("info", "list active notifications", "${info}", List.of(), ANY),
                (args, ctx) -> CommandResult.ok(notificationLines()));
        d.register(def("notify", "open (N) or act on a notification: ${notify(N, \"pass|reject|over\")}",
                        "${notify [N [action]]}",
                        List.of(param("index", NUMBER, true, "notification number"),
                                param("action", CHOICE, true, "pass | reject | over")), ANY),
                this::notify);
        d.register(def("mode", "choose mode: ${mode(\"local\", name)} or ${mode(\"server\", \"host:port\")}",
                        "${mode(local|server, value)}",
                        List.of(param("which", CHOICE, false, "local | server"),
                                param("value", STRING, false, "local name or server address")), L1),
                this::mode);
        d.register(def("server-alias", "set your private local note for this server",
                        "${server-alias(\"note\")}",
                        List.of(param("note", STRING, false, "free-text note")), ANY),
                this::serverAlias);
        d.register(def("server-info", "server official name, policy, and your alias", "${server-info}",
                        List.of(), ANY),
                (args, ctx) -> CommandResult.ok(serverInfoLines()));
        d.register(def("register", "register an account (password prompted when omitted)",
                        "${register(@name [, \"password\", @email])}",
                        List.of(param("name", STRING, false, "@name"),
                                param("password", STRING, true, "password (prompted when omitted)"),
                                param("email", STRING, true, "@Email")), ANY),
                this::register);
        d.register(def("login", "log in (password prompted when omitted)",
                        "${login(@name [, \"password\"])}",
                        List.of(param("name", STRING, false, "@name"),
                                param("password", STRING, true, "password (prompted when omitted)")), ANY),
                this::login);
        d.register(def("logout", "disconnect from the server", "${logout}", List.of(), ANY),
                (args, ctx) -> {
                    if (app.server() == null) {
                        throw new Errors.Usage("not connected to a server");
                    }
                    app.server().logout();
                    return CommandResult.ok("logged out");
                });
        d.register(def("open", "open a conversation", "${open(name)}",
                        List.of(param("name", ATOM, false, "peer or group name")), L2),
                this::open);
        d.register(def("close", "close the current conversation", "${close}", List.of(), L3),
                (args, ctx) -> {
                    app.closeConversation();
                    return CommandResult.ok("conversation closed");
                });
        d.register(def("friends", "list friends and their observer-relative status", "${friends}",
                        List.of(), L2),
                (args, ctx) -> CommandResult.ok(friendLines()));
        d.register(def("friend-request", "send a friend request", "${friend-request(name)}",
                        List.of(param("name", ATOM, false, "peer or @user")), L2),
                this::friendRequest);
        d.register(def("discoverable", "toggle discovery visibility (Local mode)",
                        "${discoverable(\"on\"|\"off\")}",
                        List.of(param("value", CHOICE, false, "on | off")), L2),
                (args, ctx) -> {
                    boolean on = requireOnOff(args.get(0));
                    app.setDiscoverable(on);
                    return CommandResult.ok("discoverable: " + (on ? "on" : "off"));
                });
        d.register(def("connectable", "toggle inbound connection acceptance (Local mode)",
                        "${connectable(\"on\"|\"off\")}",
                        List.of(param("value", CHOICE, false, "on | off")), L2),
                (args, ctx) -> {
                    boolean on = requireOnOff(args.get(0));
                    app.setConnectable(on);
                    return CommandResult.ok("connectable: " + (on ? "on" : "off"));
                });
        d.register(def("connect", "address-targeted connection attempt (Local mode)",
                        "${connect(\"host:port\")}",
                        List.of(param("address", STRING, false, "host:port")), L2),
                this::connect);
        d.register(def("discover", "run a discovery query now (Local mode)", "${discover}",
                        List.of(), L2),
                (args, ctx) -> {
                    if (app.local() == null) {
                        throw new Errors.Usage("Local mode is not active");
                    }
                    app.local().runDiscovery();
                    return CommandResult.ok("discovery query sent" + (app.local().discoveryAvailable()
                            ? "" : " (discovery unavailable on this network)"));
                });
        d.register(def("create-group", "create an operator-visible group (disclosed to members)",
                        "${create-group(\"name\", member...)}",
                        List.of(param("name", STRING, false, "group name"),
                                param("members", STRING, true, "member names (repeatable)")), L2),
                (args, ctx) -> createGroup(args, false));
        d.register(def("create-encrypted-group", "create an encrypted group (operators cannot read it)",
                        "${create-encrypted-group(\"name\", member...)}",
                        List.of(param("name", STRING, false, "group name"),
                                param("members", STRING, true, "member names (repeatable)")), L2),
                (args, ctx) -> createGroup(args, true));
        d.register(def("group-invite", "invite a member (owner)", "${group-invite(name)}",
                        List.of(param("member", ATOM, false, "member name")), L3),
                (args, ctx) -> {
                    String groupId = currentGroupId();
                    app.server().inviteMember(groupId, args.get(0).asString());
                    return CommandResult.ok("invitation sent to " + args.get(0).asString());
                });
        d.register(def("group-remove", "remove a member (owner); encrypted groups require rotation",
                        "${group-remove(name)}",
                        List.of(param("member", ATOM, false, "member name")), L3),
                (args, ctx) -> {
                    String groupId = currentGroupId();
                    app.server().removeMember(groupId, args.get(0).asString());
                    return CommandResult.ok("member removed — for encrypted groups, rotate the key now: ${group-send-keys}");
                });
        d.register(def("group-leave", "leave the current group", "${group-leave}", List.of(), L3),
                (args, ctx) -> {
                    app.server().leaveGroup(currentGroupId());
                    app.closeConversation();
                    return CommandResult.ok("left the group");
                });
        d.register(def("group-transfer", "transfer ownership (owner)", "${group-transfer(name)}",
                        List.of(param("member", ATOM, false, "new owner")), L3),
                (args, ctx) -> {
                    app.server().transferGroup(currentGroupId(), args.get(0).asString());
                    return CommandResult.ok("ownership transferred to " + args.get(0).asString());
                });
        d.register(def("group-members", "list group members and privacy mode", "${group-members}",
                        List.of(), L3),
                (args, ctx) -> CommandResult.ok(groupMemberLines()));
        d.register(def("group-send-keys", "owner: distribute/rotate the encrypted-group key",
                        "${group-send-keys}", List.of(), L3),
                (args, ctx) -> {
                    app.server().rotateGroupKeys(currentGroupId());
                    return CommandResult.ok("new group key distributed");
                });
        d.register(def("record", "show or set automatic recording: ${record(\"on\"|\"off\")}",
                        "${record [on|off]}",
                        List.of(param("value", CHOICE, true, "on | off")), ANY),
                this::record);
        d.register(def("persist", "persist buffered unpersisted messages of the current conversation",
                        "${persist}", List.of(), ANY),
                (args, ctx) -> {
                    String key = currentKeyOrError();
                    int n = app.persist(key);
                    return CommandResult.ok(n == 0
                            ? "nothing buffered to persist" : "persisted " + n + " message(s)");
                });
        d.register(def("history-delete", "delete saved history: ${history-delete(\"current\"|\"peer\"|\"all\" [, name])}",
                        "${history-delete(scope [, name])}",
                        List.of(param("scope", CHOICE, false, "current | peer | all"),
                                param("name", STRING, true, "peer name (for scope=peer)")), ANY),
                this::historyDelete);
        d.register(def("say", "send text explicitly (payload is literal, never parsed)",
                        "${say(text)}",
                        List.of(param("text", STRING, false, "payload")), ANY),
                this::say);
        d.register(def("quit", "exit the application (exit-prompt policy applies)", "${quit}",
                        List.of(), ANY),
                (args, ctx) -> CommandResult.exit("bye"));
        d.register(def("exit", "exit the application (alias of quit)", "${exit}", List.of(), ANY),
                (args, ctx) -> CommandResult.exit("bye"));
    }

    // ---------------- handlers ----------------

    private CommandResult help(List<Arg> args, CommandDef.Context ctx) {
        if (args.isEmpty()) {
            return CommandResult.ok(dispatcher.helpText(ctx));
        }
        return CommandResult.ok(dispatcher.helpOne(args.get(0).asString()));
    }

    private CommandResult notify(List<Arg> args, CommandDef.Context ctx) {
        if (args.isEmpty()) {
            return CommandResult.ok(notificationLines());
        }
        int index = ((Arg.Num) args.get(0)).asInt();
        if (args.size() == 1) {
            List<Notification> list = app.notifications();
            if (index < 1 || index > list.size()) {
                throw new Errors.Validation("notification " + index + " does not exist");
            }
            Notification n = list.get(index - 1);
            return CommandResult.ok("notification " + index + ": [" + n.kind() + "] from " + n.from()
                    + " — " + n.text(), "actions: ${notify(" + index + ", \"pass\")}, "
                    + "${notify(" + index + ", \"reject\")}, ${notify(" + index + ", \"over\")}");
        }
        String action = args.get(1).asString();
        return CommandResult.ok(app.notifyAction(index, action));
    }

    private CommandResult mode(List<Arg> args, CommandDef.Context ctx) {
        String which = args.get(0).asString();
        String value = args.get(1).asString();
        if (which.equals("local")) {
            app.enterLocal(value);
            return CommandResult.ok("Local mode: you are '" + value + "'");
        }
        if (which.equals("server")) {
            app.connectServer(value);
            return CommandResult.ok("connecting to " + value + " — wait for the server welcome");
        }
        throw new Errors.Usage("mode must be local or server");
    }

    private CommandResult serverAlias(List<Arg> args, CommandDef.Context ctx) {
        if (app.mode() != SessionMode.SERVER || app.server() == null) {
            throw new Errors.Usage("not connected to a server");
        }
        String note = args.get(0).asString();
        app.store().putAlias(app.server().serverAddress(), note);
        return CommandResult.ok("alias saved for " + app.server().serverAddress());
    }

    private String[] serverInfoLines() {
        if (app.mode() != SessionMode.SERVER || app.server() == null) {
            return new String[]{"not connected to a server"};
        }
        var s = app.server();
        String alias = app.store().alias(s.serverAddress());
        return new String[]{
                "server name : " + (s.serverName() == null ? "(unknown yet)" : s.serverName()),
                "address     : " + s.serverAddress(),
                "your alias  : " + (alias == null ? "(none — set with ${server-alias(...)})" : alias),
                "logged in   : " + (s.loggedInUser() == null ? "no — use ${login(...)}" : s.loggedInUser()),
        };
    }

    private CommandResult register(List<Arg> args, CommandDef.Context ctx) {
        if (app.mode() != SessionMode.SERVER || app.server() == null) {
            throw new Errors.Usage("not connected to a server");
        }
        String name = args.get(0).asString();
        Text.requireServerName(name);
        String password = args.size() >= 2 ? args.get(1).asString() : prompts.promptSecret("password for " + name);
        String email = args.size() >= 3 ? args.get(2).asString()
                : prompts.promptLine("@Email (optional, enter to skip)");
        Map<String, String> fields = new java.util.LinkedHashMap<>();
        if (email != null && !email.isBlank()) {
            fields.put("@Email", email);
        }
        app.server().register(name, password, fields);
        return CommandResult.ok("registration request sent");
    }

    private CommandResult login(List<Arg> args, CommandDef.Context ctx) {
        if (app.mode() != SessionMode.SERVER || app.server() == null) {
            throw new Errors.Usage("not connected to a server");
        }
        String name = args.get(0).asString();
        Text.requireServerName(name);
        String password = args.size() >= 2 ? args.get(1).asString() : prompts.promptSecret("password for " + name);
        app.server().login(name, password);
        return CommandResult.ok("login request sent");
    }

    private CommandResult open(List<Arg> args, CommandDef.Context ctx) {
        String name = args.get(0).asString();
        for (ConversationRef ref : app.conversations()) {
            if (ref.title().equals(name) || ref.id().equals(name)) {
                app.openConversation(ref);
                return CommandResult.ok("opened " + ref.title());
            }
        }
        throw new Errors.NotFound("no conversation named '" + name + "'");
    }

    private String[] friendLines() {
        List<String> out = new ArrayList<>();
        for (String friend : app.friends()) {
            FriendState state = app.friendState(friend);
            out.add(friend + " — " + state.name().toLowerCase() + " — "
                    + app.peerStatus(friend).name().toLowerCase());
        }
        if (out.isEmpty()) {
            out.add("(no friends yet — use ${friend-request(name)} to reach out)");
        }
        return out.toArray(String[]::new);
    }

    private CommandResult friendRequest(List<Arg> args, CommandDef.Context ctx) {
        String name = args.get(0).asString();
        boolean delivered = app.sendFriendRequest(name);
        return delivered
                ? CommandResult.ok("friend request sent to " + name + " (sent is not delivered — watch notifications)")
                : CommandResult.ok("friend request to " + name + " is undeliverable (peer unreachable)");
    }

    private CommandResult connect(List<Arg> args, CommandDef.Context ctx) {
        if (app.local() == null) {
            throw new Errors.Usage("Local mode is not active");
        }
        String address = args.get(0).asString();
        int colon = address.lastIndexOf(':');
        if (colon <= 0 || colon == address.length() - 1) {
            throw new Errors.Validation("address must be host:port");
        }
        String host = address.substring(0, colon);
        int port;
        try {
            port = Integer.parseInt(address.substring(colon + 1));
        } catch (NumberFormatException e) {
            throw new Errors.Validation("address must be host:port");
        }
        app.local().connect(host, port);
        return CommandResult.ok("connection attempt sent to " + address);
    }

    private CommandResult createGroup(List<Arg> args, boolean encrypted) {
        if (app.mode() != SessionMode.SERVER || app.server() == null) {
            throw new Errors.Usage("groups are created in Server mode");
        }
        String name = args.get(0).asString();
        List<String> members = new ArrayList<>();
        for (int i = 1; i < args.size(); i++) {
            members.add(args.get(i).asString());
        }
        String groupId = app.server().createGroup(name, members, encrypted);
        String disclosure = encrypted
                ? "encrypted group: server operators cannot read its content; the operator is not "
                + "responsible for content it cannot decrypt"
                : "operator-visible group: server operators can read content and moderate";
        return CommandResult.ok("group '" + name + "' created (" + groupId + ")", disclosure);
    }

    private CommandResult record(List<Arg> args, CommandDef.Context ctx) {
        String key = currentKeyOrError();
        if (args.isEmpty()) {
            return CommandResult.ok(app.recording(key)
                    ? "automatic recording is ON for this conversation"
                    : "automatic recording is OFF — new messages stay in memory until ${persist}");
        }
        boolean on = requireOnOff(args.get(0));
        app.setRecording(key, currentTitle(), on);
        return CommandResult.ok(on
                ? "recording enabled — new messages are persisted automatically"
                : "recording disabled — new messages stay buffered in memory (saved history is NOT deleted)");
    }

    private CommandResult historyDelete(List<Arg> args, CommandDef.Context ctx) {
        String scope = args.get(0).asString();
        if (!scope.equals("current") && !scope.equals("peer") && !scope.equals("all")) {
            throw new Errors.Usage("scope must be current, peer, or all");
        }
        String arg = args.size() >= 2 ? args.get(1).asString() : null;
        String confirm = prompts.promptLine("delete " + scope + " history? This cannot be undone. Type YES to confirm:");
        if (!"YES".equals(confirm)) {
            return CommandResult.ok("deletion cancelled — nothing was deleted");
        }
        if (scope.equals("all")) {
            // Broad destructive scope requires a second explicit confirmation (P2).
            String again = prompts.promptLine("delete ALL local history? Type YES again to confirm:");
            if (!"YES".equals(again)) {
                return CommandResult.ok("deletion cancelled — nothing was deleted");
            }
        }
        int removed = app.deleteHistory(scope, arg);
        return CommandResult.ok("deleted " + removed + " history file(s)");
    }

    private CommandResult say(List<Arg> args, CommandDef.Context ctx) {
        String text = args.get(0).asString();
        app.say(text);
        return CommandResult.ok("sent");
    }

    // ---------------- helpers ----------------

    private String[] statusLines() {
        List<String> out = new ArrayList<>();
        SessionMode mode = app.mode();
        out.add("mode: " + (mode == SessionMode.NONE ? "menu" : mode.name().toLowerCase()));
        if (mode == SessionMode.LOCAL && app.local() != null) {
            out.add("local name: " + app.local().myName());
            out.add("discoverable: " + (app.discoverable() ? "on" : "off")
                    + ", connectable: " + (app.connectable() ? "on" : "off"));
            ConversationRef cur = app.currentConversation();
            if (cur != null) {
                out.add("conversation: " + cur.title() + " (recording "
                        + (app.recording(app.local().convKey(cur.id())) ? "on" : "off") + ")");
            }
        }
        if (mode == SessionMode.SERVER && app.server() != null) {
            out.add("server: " + app.server().serverName() + " @ " + app.server().serverAddress());
            out.add("user: " + (app.server().loggedInUser() == null ? "(not logged in)" : app.server().loggedInUser()));
            ConversationRef cur = app.currentConversation();
            if (cur != null) {
                out.add("conversation: " + cur.title());
            }
        }
        out.add("notifications: " + app.notifications().size());
        return out.toArray(String[]::new);
    }

    private String[] notificationLines() {
        List<Notification> list = app.notifications();
        if (list.isEmpty()) {
            return new String[]{"no active notifications"};
        }
        List<String> out = new ArrayList<>();
        for (int i = 0; i < list.size(); i++) {
            Notification n = list.get(i);
            out.add((i + 1) + ". [" + n.kind().name().toLowerCase() + "] " + n.from() + ": " + n.text()
                    + (n.kind() == NotificationKind.FRIEND_REQUEST
                    ? "  → ${notify(" + (i + 1) + ", \"pass\")} or ${notify(" + (i + 1) + ", \"reject\")}"
                    : "  → ${notify(" + (i + 1) + ", \"over\")}"));
        }
        return out.toArray(String[]::new);
    }

    private String[] groupMemberLines() {
        ConversationRef cur = app.currentConversation();
        if (cur == null || cur.kind() != ConversationRef.Kind.GROUP || app.server() == null) {
            throw new Errors.Usage("not in a group conversation");
        }
        var g = app.server().group(cur.id());
        if (g == null) {
            throw new Errors.NotFound("group no longer exists");
        }
        List<String> out = new ArrayList<>();
        out.add("group: " + g.name + " — " + g.privacy + " (owner: " + g.owner + ")");
        for (String m : g.members) {
            out.add("  " + m);
        }
        return out.toArray(String[]::new);
    }

    private String currentGroupId() {
        ConversationRef cur = app.currentConversation();
        if (cur == null || cur.kind() != ConversationRef.Kind.GROUP) {
            throw new Errors.Usage("open a group conversation first");
        }
        return cur.id();
    }

    private String currentKeyOrError() {
        ConversationRef cur = app.currentConversation();
        if (cur == null) {
            throw new Errors.Usage("no conversation selected");
        }
        if (app.mode() == SessionMode.LOCAL && app.local() != null) {
            return app.local().convKey(cur.id());
        }
        if (app.mode() == SessionMode.SERVER && app.server() != null) {
            return app.server().convKey(cur);
        }
        throw new Errors.Usage("no conversation selected");
    }

    private String currentTitle() {
        ConversationRef cur = app.currentConversation();
        return cur == null ? "" : cur.title();
    }

    private static boolean requireOnOff(Arg arg) {
        String v = arg.asString();
        if (v.equals("on")) {
            return true;
        }
        if (v.equals("off")) {
            return false;
        }
        throw new Errors.Usage("value must be on or off");
    }

    private static CommandDef def(String name, String summary, String usage,
                                  List<CommandDef.Param> params, CommandDef.Context... contexts) {
        EnumSet<CommandDef.Context> set = EnumSet.noneOf(CommandDef.Context.class);
        set.addAll(List.of(contexts));
        return new CommandDef(name, summary, usage, params, set);
    }

    private static CommandDef.Param param(String name, CommandDef.ParamType type, boolean optional,
                                          String description) {
        return new CommandDef.Param(name, type, optional, description);
    }
}
