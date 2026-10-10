package org.ourcamellia.core.cmd;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.ourcamellia.common.Errors;

import java.util.EnumSet;

import static org.junit.jupiter.api.Assertions.*;

class CommandDispatcherTest {

    private CommandDispatcher dispatcher;

    @BeforeEach
    void setUp() {
        dispatcher = new CommandDispatcher();
        dispatcher.register(new CommandDef("say", "send text", "${say(text)}",
                        java.util.List.of(new CommandDef.Param("text", CommandDef.ParamType.STRING, false, "payload")),
                        EnumSet.of(CommandDef.Context.L2, CommandDef.Context.L3)),
                (args, ctx) -> CommandResult.ok("sent: " + args.get(0).asString()));
        dispatcher.register(new CommandDef("help", "list commands", "${help [name]}",
                        java.util.List.of(new CommandDef.Param("name", CommandDef.ParamType.ATOM, true, "command name")),
                        EnumSet.of(CommandDef.Context.ANY)),
                (args, ctx) -> args.isEmpty()
                        ? CommandResult.ok(dispatcher.helpText(ctx))
                        : CommandResult.ok(dispatcher.helpOne(args.get(0).asString())));
        dispatcher.register(new CommandDef("open", "open conversation", "${open(name)}",
                        java.util.List.of(new CommandDef.Param("name", CommandDef.ParamType.ATOM, false, "peer or group")),
                        EnumSet.of(CommandDef.Context.L2)),
                (args, ctx) -> CommandResult.ok("opened " + args.get(0).asString()));
        dispatcher.register(new CommandDef("record", "toggle recording", "${record(on/off)}",
                        java.util.List.of(new CommandDef.Param("value", CommandDef.ParamType.CHOICE, false, "on or off")),
                        EnumSet.of(CommandDef.Context.L3)),
                (args, ctx) -> {
                    String v = args.get(0).asString();
                    if (!v.equals("on") && !v.equals("off")) {
                        throw new Errors.Usage("value must be on or off");
                    }
                    return CommandResult.ok("recording " + v);
                });
    }

    @Test
    void sayDispatchesStringArg() {
        var r = dispatcher.dispatch(new ParsedInput.Command("say", java.util.List.of(new Arg.Str("hi"))),
                CommandDef.Context.L3);
        assertEquals(CommandResult.Status.OK, r.status());
        assertEquals("sent: hi", r.lines().get(0));
    }

    @Test
    void sayCoercesNumberAndBoolToText() {
        var r1 = dispatcher.dispatch(new ParsedInput.Command("say", java.util.List.of(new Arg.Num(123, "123"))),
                CommandDef.Context.L3);
        assertEquals("sent: 123", r1.lines().get(0));
        var r2 = dispatcher.dispatch(new ParsedInput.Command("say", java.util.List.of(new Arg.Bool(true))),
                CommandDef.Context.L3);
        assertEquals("sent: true", r2.lines().get(0));
    }

    @Test
    void sayArityErrors() {
        var noArg = dispatcher.dispatch(new ParsedInput.Command("say", java.util.List.of()), CommandDef.Context.L3);
        assertEquals(CommandResult.Status.ERROR, noArg.status());

        var twoArgs = dispatcher.dispatch(new ParsedInput.Command("say",
                java.util.List.of(new Arg.Str("x"), new Arg.Str("y"))), CommandDef.Context.L3);
        assertEquals(CommandResult.Status.ERROR, twoArgs.status());
    }

    @Test
    void unknownCommandIsError() {
        var r = dispatcher.dispatch(new ParsedInput.Command("nope", java.util.List.of()), CommandDef.Context.ANY);
        assertEquals(CommandResult.Status.ERROR, r.status());
        assertTrue(r.lines().get(0).contains("unknown command"));
    }

    @Test
    void contextEnforcement() {
        var r = dispatcher.dispatch(new ParsedInput.Command("open", java.util.List.of(new Arg.Atom("@a"))),
                CommandDef.Context.L1);
        assertEquals(CommandResult.Status.ERROR, r.status());
        assertTrue(r.lines().get(0).contains("not available"));
    }

    @Test
    void choiceValidation() {
        var ok = dispatcher.dispatch(new ParsedInput.Command("record", java.util.List.of(new Arg.Str("off"))),
                CommandDef.Context.L3);
        assertEquals(CommandResult.Status.OK, ok.status());
        var bad = dispatcher.dispatch(new ParsedInput.Command("record", java.util.List.of(new Arg.Str("maybe"))),
                CommandDef.Context.L3);
        assertEquals(CommandResult.Status.ERROR, bad.status());
    }

    @Test
    void handlerExceptionsBecomeErrorResults() {
        // register a command that throws a business error
        dispatcher.register(new CommandDef("boom", "boom", "${boom}", java.util.List.of(), EnumSet.of(CommandDef.Context.ANY)),
                (args, ctx) -> {
                    throw new Errors.Denied("not allowed");
                });
        var r = dispatcher.dispatch(new ParsedInput.Command("boom", java.util.List.of()), CommandDef.Context.ANY);
        assertEquals(CommandResult.Status.ERROR, r.status());
        assertEquals("error: not allowed", r.lines().get(0));
    }

    @Test
    void helpListsCommands() {
        var r = dispatcher.dispatch(new ParsedInput.Command("help", java.util.List.of()), CommandDef.Context.L2);
        assertEquals(CommandResult.Status.OK, r.status());
        String text = String.join("\n", r.lines());
        assertTrue(text.contains("say"));
        assertTrue(text.contains("help"));
    }

    @Test
    void executeParsesMalformedIntoError() {
        var r = dispatcher.execute("${inf", CommandDef.Context.L2, false);
        assertEquals(CommandResult.Status.ERROR, r.status());
        assertTrue(r.lines().get(0).contains("malformed command"));
    }

    @Test
    void executeReturnsEmptyForMessages() {
        var r = dispatcher.execute("hello there", CommandDef.Context.L3, false);
        assertEquals(CommandResult.Status.OK, r.status());
        assertTrue(r.isEmpty());
    }
}
