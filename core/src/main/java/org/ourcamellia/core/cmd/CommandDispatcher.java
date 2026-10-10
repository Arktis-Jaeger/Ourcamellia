package org.ourcamellia.core.cmd;

import org.ourcamellia.common.Errors;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Command dispatch: parser → registry validation (arity, types, context) → handler.
 * Business logic lives in handlers wired to the application layer; the dispatcher
 * performs no business rules of its own (ARCHITECTURE.md §4).
 */
public final class CommandDispatcher {

    /** A command implementation. Throwing any OcException yields an error result. */
    public interface Handler {
        CommandResult handle(List<Arg> args, CommandDef.Context context) throws Errors.OcException;
    }

    private record Entry(CommandDef def, Handler handler) {}

    private final Map<String, Entry> commands = new LinkedHashMap<>();

    public void register(CommandDef def, Handler handler) {
        commands.put(def.name(), new Entry(def, handler));
    }

    public List<CommandDef> definitions() {
        List<CommandDef> out = new ArrayList<>();
        commands.values().forEach(e -> out.add(e.def()));
        return out;
    }

    public CommandDef definition(String name) {
        Entry e = commands.get(name);
        return e == null ? null : e.def();
    }

    /** Parses the line and, when it is a command, dispatches it. */
    public CommandResult execute(String line, CommandDef.Context context, boolean oldModeNewlineEscape) {
        ParsedInput in = CommandParser.parse(line, oldModeNewlineEscape);
        if (in instanceof ParsedInput.Command cmd) {
            return dispatch(cmd, context);
        }
        if (in instanceof ParsedInput.Malformed mal) {
            return CommandResult.error("malformed command — " + mal.reason()
                    + " (nothing was sent or executed)");
        }
        // Message/Blank are handled by the caller (default say / no-op).
        return CommandResult.ok();
    }

    public CommandResult dispatch(ParsedInput.Command cmd, CommandDef.Context context) {
        Entry e = commands.get(cmd.name());
        if (e == null) {
            return CommandResult.error("unknown command '" + cmd.name()
                    + "' — try ${help} for the command list");
        }
        CommandDef def = e.def();
        if (!def.validIn(context)) {
            return CommandResult.error("command '" + cmd.name() + "' is not available in this context");
        }
        if (cmd.args().size() < def.minArgs() || cmd.args().size() > def.maxArgs()) {
            return CommandResult.error("usage: " + def.usage());
        }
        for (int i = 0; i < cmd.args().size(); i++) {
            String typeError = typeCheck(def.paramAt(i).type(), cmd.args().get(i));
            if (typeError != null) {
                return CommandResult.error("argument " + (i + 1) + ": " + typeError + " — usage: " + def.usage());
            }
        }
        try {
            CommandResult r = e.handler().handle(cmd.args(), context);
            return r == null ? CommandResult.ok() : r;
        } catch (Errors.OcException ex) {
            return CommandResult.error(ex.getMessage());
        } catch (RuntimeException ex) {
            return CommandResult.error("internal error: " + ex.getClass().getSimpleName());
        }
    }

    private static String typeCheck(CommandDef.ParamType type, Arg arg) {
        return switch (type) {
            case STRING -> null; // any arg renders as its literal text
            case NUMBER -> arg instanceof Arg.Num ? null : "expected a number";
            case BOOL -> arg instanceof Arg.Bool ? null : "expected true or false";
            case ATOM, CHOICE -> arg instanceof Arg.Atom || arg instanceof Arg.Str
                    ? null : "expected a name or quoted text";
        };
    }

    /** Help text for all commands available in the context. */
    public String helpText(CommandDef.Context context) {
        StringBuilder sb = new StringBuilder("commands (this context):\n");
        commands.values().stream()
                .map(Entry::def)
                .filter(d -> d.validIn(context))
                .forEach(d -> sb.append("  ${").append(d.name())
                        .append("}  —  ").append(d.summary()).append('\n'));
        return sb.toString().stripTrailing();
    }

    public String helpOne(String name) {
        Entry e = commands.get(name);
        if (e == null) {
            return "unknown command '" + name + "'";
        }
        CommandDef d = e.def();
        StringBuilder sb = new StringBuilder(d.name()).append(" — ").append(d.summary()).append('\n')
                .append("usage: ").append(d.usage()).append('\n');
        for (CommandDef.Param p : d.params()) {
            sb.append("  ").append(p.name()).append(" (").append(p.type())
                    .append(p.optional() ? ", optional" : "").append("): ")
                    .append(p.description()).append('\n');
        }
        return sb.toString().stripTrailing();
    }
}
