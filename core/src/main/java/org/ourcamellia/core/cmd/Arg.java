package org.ourcamellia.core.cmd;

/** A parsed argument value. */
public sealed interface Arg permits Arg.Str, Arg.Num, Arg.Bool, Arg.Atom {

    record Str(String value) implements Arg {}

    record Num(double value, String raw) implements Arg {
        public int asInt() {
            if (value != Math.floor(value) || value < Integer.MIN_VALUE || value > Integer.MAX_VALUE) {
                throw new org.ourcamellia.common.Errors.Usage("expected an integer, got: " + raw);
            }
            return (int) value;
        }
    }

    record Bool(boolean value) implements Arg {}

    /** Bare unquoted token; may look like ${...} — that is data, never a command. */
    record Atom(String value) implements Arg {}

    default String asString() {
        return switch (this) {
            case Str s -> s.value();
            case Num n -> n.raw();
            case Bool b -> Boolean.toString(b.value());
            case Atom a -> a.value();
        };
    }
}
