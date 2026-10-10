# Ourcamellia — Formal Command Grammar

This document resolves REQUIREMENTS.md §6.2 (the grammar was explicitly an open
implementation decision). The illustrative snippets in the requirements
(`${say(${info})`, `create-group{(group name): ...}`, `1 pass`) are conceptual; this
document defines the canonical grammar, documents the deviation from the snippets, and lists
the parser test matrix. The parser is implemented once in `core` and shared by Observatory
and Old modes; it parses the whole logical input line and never recurses into payloads.

## 1. Grammar (EBNF-ish)

```
input          := command | message
command        := '${' name [ '(' args ')' ] '}' SPACES?          -- strict whole-line match
name           := LETTER ( LETTER | DIGIT | '-' | '_' )*
args           := arg ( ( ',' SPACES? | SPACES ) arg )*  SPACES?   -- ',' canonical; plain spaces also separate args
arg            := STRING | NUMBER | BOOL | ATOM
STRING         := '"' ( SCHAR | ESCAPE )* '"'
SCHAR          := any char except '"' '\' and control chars
ESCAPE         := '\' ( '\\' | '"' | 'n' | 't' | '$' | '{' )
NUMBER         := '-'? DIGIT+ [ '.' DIGIT+ ]
BOOL           := 'true' | 'false'
ATOM           := ACHAR+                 -- no SPACE, '"', ',', '(', ')', '\'
ACHAR          := any char except SPACE '"' ',' '(' ')' '\' and control chars
message        := MCHAR*                 -- free text, may contain spaces, ${...}, anything
SPACES         := ' ' | '\t'
```

Notes:

- `'${'` is the only command trigger; the input must match exactly one complete command
  expression, with trailing spaces/tabs permitted and nothing else outside it.
- Arguments are always inside parentheses; the canonical separator is ',' (spaces
  allowed around it), but plain whitespace also separates arguments — so
  `${say(hello world)}` parses as two arguments and fails `say`'s arity check with a
  usage message that says text containing spaces must be quoted. Canonical examples:
  `${say("hi")}`, `${notify(2, "pass")}`, `${create-group("Group", @alice, @bob)}`.
- Input that does **not** start with `'${'` is always an ordinary message (the default `say`
  operation). A command-looking substring inside a message is never executed.
- Input that starts with `'${'` but fails to parse completely is **rejected with a clear
  error** ("malformed command: ...") and nothing is sent or executed — we never silently
  convert a half-written command into a chat message, and never execute an ambiguous one.
- In argument position, `${say(${info})}` is a valid `say` invocation whose single atom
  argument is the literal text `${info}`; the argument is data and is never recursively
  parsed. The quoted form `${say("${info}")}` is equivalent.
- Atoms cannot contain spaces; `say(hello world)` parses as two arguments and fails arity
  validation with a helpful message ("unquoted text containing spaces must be quoted").
- Escapes: in STRING, `\\` `\"` `\n` `\t`; in a message (Old mode), `\n` produces a newline
  inside the message and `\${` produces a literal `${`; unknown escapes keep the backslash
  literally (documented, deterministic).
- Unicode is preserved as-is (no NFC normalization; messages and names are stored/sent
  verbatim after validation of control characters and length limits).
- Grammar deviation from the illustrative snippets (documented per REQUIREMENTS §6.2):
  - the user's `say{(...)}` / `create-group{(...)}` braces-with-colons form is replaced by
    `${name(args...)}`;
  - the conceptual `create-group{(group name): "Member A", "Member B"}` becomes
    `${create-group("Group Name", @alice, @bob)}` (privacy mode selected explicitly via
    `${create-encrypted-group(...)}`, see §4);
  - notification shortcuts `1 pass` / `2 over` are context-sensitive menu inputs (accepted
    only while the notification list is open); their canonical command forms are
    `${notify(1, "pass")}` / `${notify(2, "over")}` (see §3).

## 2. Argument schema and validation

Each command declares an ordered argument schema (name, type, required/optional) in the
command registry. Types: `string` (STRING or ATOM), `number`, `boolean`, `username`
(ATOM that must match the identity rules: Server mode `@name`, Local mode bare name —
validated against the configured charset rules), `choice` (ATOM from an enumerated set).
Arguments are validated (length ≤ 512 chars, no control characters, identity charset
`[A-Za-z0-9._-]{1,64}`, email shape) before any business operation. Malformed values
produce typed usage errors; nothing is executed.

## 3. Canonical command reference (v1)

Context = the menu level in which the command is valid (L1 = mode choice, L2 = conversation
list, L3 = conversation, ANY = anywhere). The same set is shared by both CLI modes.

| Command | Context | Meaning |
|---|---|---|
| `${help}` `[atom]` | ANY | list commands / describe one |
| `${status}` | ANY | status query: local connection state, peer statuses (observer-relative), recording state |
| `${info}` / `${notify}` | ANY | list active notifications (numbered, most recent first) |
| `${notify(N)}` | ANY | open notification item N |
| `${notify(N, "pass")}` | ANY | accept the friend request in item N |
| `${notify(N, "reject")}` | ANY | reject the friend request in item N |
| `${notify(N, "over")}` | ANY | mark item N reviewed and remove from active list |
| `${mode("local", "user")}` | L1 | enter Local mode as `user` (bare name) |
| `${mode("server", "addr")}` | L1 | connect to a server at `addr` (`host:port`) |
| `${server-alias("name")}` | L2(Server) | set private local alias/note for current server |
| `${server-info}` | L2(Server) | server official name, policy summary, alias |
| `${register("@name")}` | L1(Server) | register account (password + email prompted) |
| `${register("@name", "pass", "@email")}` | L1(Server) | scripted registration (warns: password visible in shell history) |
| `${login("@name")}` | L1(Server) | login (password prompted, never echoed) |
| `${login("@name", "pass")}` | L1(Server) | scripted login (same warning) |
| `${logout}` | L2(Server) | disconnect and return to L1 |
| `${open(name)}` | L2 | open conversation with a peer/group |
| `${friends}` | L2 | list friends and their observer-relative status |
| `${friend-request(name)}` | L2 | send friend request |
| `${discoverable("on"/"off")}` | L2(Local) | discovery visibility |
| `${connectable("on"/"off")}` | L2(Local) | inbound connection acceptance |
| `${connect("addr")}` | L2(Local) | address-targeted connection attempt (`host:port`) |
| `${discover}` | L2(Local) | run a discovery query now |
| `${create-group("name", m1, m2...)}` | L2 | operator-visible group (privacy disclosed at creation) |
| `${create-encrypted-group("name", m1...)}` | L2 | encrypted group, server cannot read content (disclosed) |
| `${group-invite(name)}` | L3(group) | invite member (owner) |
| `${group-remove(name)}` | L3(group) | remove member (owner) — encrypted groups rotate the key |
| `${group-leave}` | L3(group) | leave group |
| `${group-transfer(name)}` | L3(group) | transfer ownership (owner) |
| `${group-members}` | L3(group) | list members + privacy mode |
| `${record}` | L3 | show recording state |
| `${record("on"/"off")}` | L3 | enable/disable automatic recording (never deletes history) |
| `${persist}` | L3 | manually persist buffered unpersisted messages |
| `${history-delete("current")}` | ANY | delete saved history of the current conversation (confirm) |
| `${history-delete("peer", name)}` | ANY | delete all saved history with one identity (confirm) |
| `${history-delete("all")}` | ANY | delete entire local history (double confirmation) |
| `${say(text)}` | L2/L3 | explicit say (payload is literal, never parsed) |
| `${quit}` / `${exit}` | ANY | exit (honors the exit-prompt policy) |

Server console (operator, line-oriented, local only) additionally provides:
`${admin add|remove @name}`, `${announce("text")}`, `${registration approve|reject id}`,
`${policy show}`, `${review #group [N]}`, `${mod-delete #group msgId}`, `${stats}`.

Username rule: Server mode identities are written `@name`; Local mode identities are bare
names. The two namespaces are distinct and never compared across modes.

## 4. Parser test matrix

| # | Input | Expected |
|---|---|---|
| P01 | `${help}` | help executed |
| P02 | `${help}   ` | help executed (trailing spaces) |
| P03 | ` hello ` | message " hello " (leading/trailing preserved? → trimmed per Old-mode rule, see note) |
| P04 | `${say("${info}")}` | message payload literally `${info}`, no recursion |
| P05 | `${say(${info})}` | message payload literally `${info}` (atom form) |
| P06 | `${info}` | notification list command, not message |
| P07 | `x ${info}` | ordinary message, no command executed |
| P08 | `${inf` | malformed-command error, nothing sent |
| P09 | `${say(hello world)}` | arity error (two atoms), nothing sent |
| P10 | `${say("hello\nworld")}` | payload with LF |
| P11 | `\${not a command}` | message literal `${not a command}` |
| P12 | `${say("esc \\\" \\n \\t")}` | escapes decoded correctly |
| P13 | `${create-group("组 A", @alice, @bob)}` | Unicode name, two members |
| P14 | `${nope(1,2)}` | unknown-command error |
| P15 | `${say(123)}` | payload "123" (number arg → string for say) |
| P16 | `${say(true)}` | payload "true" |
| P17 | `${notify(2, "pass")}` | notification action (canonical form) |
| P18 | `1 pass` | notification shortcut in notification-list context only; elsewhere it is sent as a message |
| P19 | `${say("a${b}c")}` | literal `a${b}c`, no nesting |
| P20 | `${say}` | say with no payload → usage error (payload required), nothing sent |
| P21 | `${}` / `${(x)}` / `${say(}` | malformed-command errors |
| P22 | `${say("unterminated)}` | malformed-command error |
| P23 | `${say("x", "y")}` | arity error (say takes ≤1 arg) |
| P24 | `${say(@alice @bob)}` | arity error; suggests quoting |
| P25 | empty line | no-op |
| P26 | 1000-char message | accepted (length limit enforced only beyond max) |
| P27 | message with control chars (ESC) | rejected with sanitization error (terminal-injection defense) |
| P28 | `${help ${info}}` | malformed-command error (args require parentheses), nothing executed |
| P29 | `${record("off")}` | choice arg validated (`off`); `${record("maybe")}` → usage error |
| P30 | `\n` alone (Old mode) | message containing one newline |

Note P03: in Old mode the whole trimmed line is the message (trailing spaces trimmed; this
is documented). In Observatory mode the submitted text is sent verbatim.

Fuzz/property tests: random byte strings up to 4 KB are fed to the parser; the invariant is
"no exception, no out-of-memory, and either a valid command object or a message/error
result" (ARCHITECTURE.md §4).
