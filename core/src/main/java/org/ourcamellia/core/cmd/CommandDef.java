package org.ourcamellia.core.cmd;

import java.util.EnumSet;
import java.util.List;

/** Metadata for one command: name, summary, parameter schema, valid contexts. */
public record CommandDef(
        String name,
        String summary,
        String usage,
        List<Param> params,
        EnumSet<Context> contexts) {

    public enum ParamType { STRING, NUMBER, BOOL, ATOM, CHOICE }

    public record Param(String name, ParamType type, boolean optional, String description) {}

    /** Contexts: ANY (everywhere), L1 (mode menu), L2 (conversation list), L3 (conversation). */
    public enum Context { ANY, L1, L2, L3 }

    public boolean validIn(Context c) {
        return contexts.contains(Context.ANY) || contexts.contains(c);
    }

    public int minArgs() {
        return (int) params.stream().filter(p -> !p.optional()).count();
    }

    public int maxArgs() {
        return params.size();
    }

    public Param paramAt(int i) {
        return params.get(i);
    }
}
