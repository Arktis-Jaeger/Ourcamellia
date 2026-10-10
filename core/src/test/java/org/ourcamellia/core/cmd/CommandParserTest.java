package org.ourcamellia.core.cmd;

import org.junit.jupiter.api.Test;

import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

/** The parser test matrix P01–P30 from docs/COMMAND_GRAMMAR.md. */
class CommandParserTest {

    private static ParsedInput p(String line) {
        return CommandParser.parse(line);
    }

    private static ParsedInput pOld(String line) {
        return CommandParser.parse(line, true);
    }

    @Test
    void p01Help() {
        var r = p("${help}");
        assertEquals(new ParsedInput.Command("help", java.util.List.of()), r);
    }

    @Test
    void p02TrailingSpaces() {
        var r = p("${help}   ");
        assertEquals(new ParsedInput.Command("help", java.util.List.of()), r);
    }

    @Test
    void p03PlainTextIsMessage() {
        assertEquals(new ParsedInput.Message(" hello "), p(" hello "));
        assertEquals(new ParsedInput.Message("hello"), p("hello"));
    }

    @Test
    void p04QuotedCommandLookingPayload() {
        var r = (ParsedInput.Command) p("${say(\"${info}\")}");
        assertEquals("say", r.name());
        assertEquals("${info}", r.args().get(0).asString());
    }

    @Test
    void p05AtomCommandLookingPayload() {
        var r = (ParsedInput.Command) p("${say(${info})}");
        assertEquals("say", r.name());
        assertEquals("${info}", r.args().get(0).asString());
    }

    @Test
    void p06InfoIsCommand() {
        var r = p("${info}");
        assertEquals(new ParsedInput.Command("info", java.util.List.of()), r);
    }

    @Test
    void p07CommandSubstringNotExecuted() {
        assertEquals(new ParsedInput.Message("x ${info}"), p("x ${info}"));
    }

    @Test
    void p08UnterminatedIsMalformed() {
        assertTrue(p("${inf") instanceof ParsedInput.Malformed);
        assertTrue(p("${info") instanceof ParsedInput.Malformed);
    }

    @Test
    void p09TwoAtomsParseAsTwoArgs() {
        var r = (ParsedInput.Command) p("${say(hello world)}");
        assertEquals(2, r.args().size());
        assertEquals("hello", r.args().get(0).asString());
        assertEquals("world", r.args().get(1).asString());
    }

    @Test
    void p10EscapedNewlineInString() {
        var r = (ParsedInput.Command) p("${say(\"hello\\nworld\")}");
        assertEquals("hello\nworld", r.args().get(0).asString());
    }

    @Test
    void p11EscapedLiteralDollarBrace() {
        assertEquals(new ParsedInput.Message("${not a command}"), p("\\${not a command}"));
    }

    @Test
    void p12StringEscapes() {
        var r = (ParsedInput.Command) p("${say(\"esc \\\\ \\\" \\n \\t\")}");
        assertEquals("esc \\ \" \n \t", r.args().get(0).asString());
    }

    @Test
    void p13UnicodeAndAtoms() {
        var r = (ParsedInput.Command) p("${create-group(\"组 A\", @alice, @bob)}");
        assertEquals("create-group", r.name());
        assertEquals("组 A", r.args().get(0).asString());
        assertEquals("@alice", r.args().get(1).asString());
        assertEquals("@bob", r.args().get(2).asString());
    }

    @Test
    void p14UnknownCommandParsesThenFailsAtDispatch() {
        var r = (ParsedInput.Command) p("${nope(1,2)}");
        assertEquals("nope", r.name());
        assertEquals(2, r.args().size());
        assertInstanceOf(Arg.Num.class, r.args().get(0));
    }

    @Test
    void p15NumberArg() {
        var r = (ParsedInput.Command) p("${say(123)}");
        assertEquals("123", r.args().get(0).asString());
        var neg = (ParsedInput.Command) p("${say(-1.5)}");
        assertEquals("-1.5", neg.args().get(0).asString());
    }

    @Test
    void p16BooleanArg() {
        var r = (ParsedInput.Command) p("${say(true)}");
        assertEquals("true", r.args().get(0).asString());
        assertEquals("false", ((ParsedInput.Command) p("${say(false)}")).args().get(0).asString());
        // "truex" is an atom, not a boolean
        assertEquals("truex", ((ParsedInput.Command) p("${say(truex)}")).args().get(0).asString());
    }

    @Test
    void p17CanonicalNotify() {
        var r = (ParsedInput.Command) p("${notify(2, \"pass\")}");
        assertEquals(2, ((Arg.Num) r.args().get(0)).asInt());
        assertEquals("pass", r.args().get(1).asString());
    }

    @Test
    void p18NotifyShortcutIsPlainText() {
        assertEquals(new ParsedInput.Message("1 pass"), p("1 pass"));
        assertEquals(new ParsedInput.Message("2 over"), p("2 over"));
    }

    @Test
    void p19NestedLookingTextIsData() {
        var r = (ParsedInput.Command) p("${say(\"a${b}c\")}");
        assertEquals("a${b}c", r.args().get(0).asString());
    }

    @Test
    void p20SayWithoutPayloadParses() {
        assertEquals(new ParsedInput.Command("say", java.util.List.of()), p("${say}"));
    }

    @Test
    void p21GarbageCommandsAreMalformed() {
        assertTrue(p("${}") instanceof ParsedInput.Malformed);
        assertTrue(p("${(x)}") instanceof ParsedInput.Malformed);
        assertTrue(p("${say(}") instanceof ParsedInput.Malformed);
        assertTrue(p("${say)") instanceof ParsedInput.Malformed);
    }

    @Test
    void p22UnterminatedStringIsMalformed() {
        assertTrue(p("${say(\"unterminated)}") instanceof ParsedInput.Malformed);
    }

    @Test
    void p23TooManyArgsParseThenFailAtDispatch() {
        var r = (ParsedInput.Command) p("${say(\"x\", \"y\")}");
        assertEquals(2, r.args().size());
    }

    @Test
    void p24SpaceSeparatedArgsParseAsTwo() {
        var r = (ParsedInput.Command) p("${say(@alice @bob)}");
        assertEquals(2, r.args().size());
    }

    @Test
    void p25BlankIsBlank() {
        assertTrue(p("") instanceof ParsedInput.Blank);
        assertTrue(p("   ") instanceof ParsedInput.Blank);
    }

    @Test
    void p26LongMessageAccepted() {
        String longText = "x".repeat(1000);
        assertEquals(new ParsedInput.Message(longText), p(longText));
        assertTrue(p("y".repeat(100_000)) instanceof ParsedInput.Malformed);
    }

    @Test
    void p27ControlCharsSurviveParserButRejectedByAppLayer() {
        // The parser preserves text verbatim; rejection happens in Text.requireCleanText
        // at the application boundary (tested in common.TextTest / ClientAppTest).
        var r = p("evil\u001b[2J");
        assertEquals(new ParsedInput.Message("evil\u001b[2J"), r);
    }

    @Test
    void p28ArgumentsNeedParentheses() {
        assertTrue(p("${help ${info}}") instanceof ParsedInput.Malformed);
    }

    @Test
    void p29ChoiceValidatedAtDispatch() {
        var r = (ParsedInput.Command) p("${record(\"off\")}");
        assertEquals("off", r.args().get(0).asString());
    }

    @Test
    void p30OldModeNewlineEscape() {
        assertEquals(new ParsedInput.Message("\n"), pOld("\\n"));
        assertEquals(new ParsedInput.Message("a\nb"), pOld("a\\nb"));
        // Observatory mode does not process \n escapes
        assertEquals(new ParsedInput.Message("a\\nb"), p("a\\nb"));
    }

    @Test
    void oldModeStillExecutesCommands() {
        assertEquals(new ParsedInput.Command("info", java.util.List.of()), pOld("${info}"));
    }

    @Test
    void emptyParensIsZeroArgs() {
        var r = (ParsedInput.Command) p("${foo()}");
        assertTrue(r.args().isEmpty());
    }

    @Test
    void commasWithSpaces() {
        var r = (ParsedInput.Command) p("${foo( 1 , 2 , \"three\" )}");
        assertEquals(3, r.args().size());
        assertEquals("three", r.args().get(2).asString());
    }

    @Test
    void trailingCommaIsMalformed() {
        assertTrue(p("${foo(1,)}") instanceof ParsedInput.Malformed);
    }

    @Test
    void unknownStringEscapeKeepsBackslash() {
        assertEquals(new ParsedInput.Message("a\\xb"), p("a\\xb"));
    }

    @Test
    void fuzzNoExceptions() {
        Random rnd = new Random(42);
        char[] alphabet = "${}()\\\", \t\nabc123-_@.\u00e9\u001b".toCharArray();
        for (int iter = 0; iter < 50_000; iter++) {
            int len = rnd.nextInt(64);
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < len; i++) {
                sb.append(alphabet[rnd.nextInt(alphabet.length)]);
            }
            ParsedInput r = CommandParser.parse(sb.toString(), rnd.nextBoolean());
            assertNotNull(r);
        }
    }
}
