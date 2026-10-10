# Ourcamellia — First-Version Requirements

This document describes the agreed first-version product scope. Requirements marked **Confirmed** are product decisions. Items marked **Implementation decision** should be resolved by engineering and documented. Items marked **Decision required** must not be silently treated as a confirmed product decision.

## 1. Delivery and quality

- Deliver a complete non-GUI client-and-server product, not a temporary prototype.
- The command-line interface is a real user interface.
- The application must build and run on a standard supported JVM environment. Prefer cross-platform behavior and graceful fallback for terminal or network-interface differences.
- Provide automated unit, integration, protocol, persistence, and security-boundary tests as applicable.
- Include build/run instructions, configuration examples, operator instructions, and a summary of limitations.
- Work in dependency-aware stages, testing each stage, but continue through all agreed first-version requirements in the same delivery.
- Do not preserve the old project's code merely for convenience; begin from a clean implementation. Preserve the product ideas, not the old implementation.

## 2. Runtime and terminal presentation

### 2.1 Two presentation modes — Confirmed

**Observatory mode (default):**
- Fixed-layout terminal interface with a fixed-height status region, a conversation display region that adapts to terminal dimensions, and an input region.
- Status values refresh without continually appending duplicate status lines.
- The status content changes with menu/conversation context.
- Support terminal resize, narrow windows, asynchronous incoming messages, and input-cursor safety.
- Resizing changes the visible viewport, not the underlying message history.
- The intended tone is quiet, restrained, and readable. Do not over-engineer visual effects.

**Old mode:**
- Traditional line-oriented input/output.
- Does not depend on screen clearing, cursor positioning, or fixed-layout terminal capabilities.
- Suitable for scripts, logs, pipes, embedding, and limited terminals.
- Input uses the literal escape sequence `\n` to represent a newline inside a message; output displays the resulting newline normally.
- It shares the same business core, command semantics, and event model as Observatory mode. It must not become a separate implementation of business logic.

### 2.2 Status region

The status region is context-sensitive and has a stable, predictable layout. Relevant fields include:
- current peer/group name;
- peer address where permitted by the mode;
- peer's status as known from the local observer's perspective;
- local username;
- local connection/availability status;
- whether the current conversation is automatically recording;
- INFO/notification indicator.

The exact presentation and placeholders for screens without a selected conversation are implementation decisions. Do not display peer IP addresses to ordinary Server-mode users. Local mode may display the peer's local IPv4 address.

### 2.3 Menus

**Level 1:** choose Local or Server mode.
- Local mode requires a local username; it may be temporary.
- Server mode allows server address entry, account login, and registration.
- Local and Server identities are distinct and do not share identity namespaces.
- Server mode has no guest-account mechanism.

**Level 2:** conversation list.
- Sort entries alphabetically A–Z, then digits 1–0, unless a documented deterministic rule is required for ties.
- The server's default/top-level group entry is pinned at the top of the Server-mode list; the exact nature of this built-in group is a **Decision required** item and must be clarified before implementation or proposed explicitly for approval.
- Local entries show peer username, peer IPv4 address, and observer-relative status.
- Server entries show server name, the local user's server-scoped username, and status. The client must not expose other Server-mode users' IP addresses.

**Level 3:** private or group conversation window.

The server address is manually entered in the first CLI version. A future GUI may provide a server list. After connecting, the client can retrieve the server's chosen display name. The client can also keep a local user-defined note/alias for that server. Server name and local alias are distinct fields.

## 3. Local mode

### 3.1 Identity and networking

- Local mode uses a temporary/local username and does not require a server account.
- No separate identity verification code is required in the agreed design.
- Local users can establish direct communication with peers by address and port.
- A discovery mechanism and direct-connection mechanism are separate concerns.
- Do not equate a discovery response with confirmed online status.
- Specify and test the discovery transport, ports, message format, expiry, timeout, interface selection, and behavior on networks where broadcast/multicast is unavailable.
- IPv4 peer addresses may be shown in Local mode.

### 3.2 Discoverability and connectability — Confirmed

These are independent settings:
1. Discoverable ON, connectable ON: the peer may be discovered and can accept inbound connections.
2. Discoverable OFF, connectable ON: the peer is not found through discovery, but someone who already knows its address may attempt a connection.
3. Discoverable OFF, connectable OFF: the peer cannot be discovered or accept inbound connections; it can only initiate outbound connections.

The implementation must not assume discoverability ON means that arbitrary strangers can send ordinary chat messages. Discovery, connection acceptance, friendship, and chat authorization are separate gates.

### 3.3 Friendship and first contact

- Local mode has friend requests and friendship acceptance.
- A friend request is an address-targeted network operation. Sending it does not prove delivery; the target may be unreachable, unavailable, or configured not to accept the relevant traffic.
- When the target is not discoverable, a stranger cannot send a message without first becoming a friend under the agreed direction of the design.
- When discoverability is enabled, first-contact behavior must be explicit and tested. The recommended policy is to allow a stranger to establish the limited connection/request path needed to send a friend request, but not to send ordinary chat content until friendship is accepted.
- If the discovery and request transport makes this distinction impossible, document the transport limitation and implement a separate narrowly scoped request path; do not open unrestricted chat as a workaround.

### 3.4 Observer-relative status — Confirmed

A peer's status is interpreted from the current observer's perspective:
- If B is not discoverable but can accept inbound connections, and B actively connects to A, A can consider B reachable/connected in that relationship.
- If A has no connection to B and cannot confirm B's state, A must not infer that B is online merely because B may be online elsewhere.
- “Offline” means no active/known connection from the current observer's perspective; where the implementation cannot distinguish offline from unknown, use an explicit UNKNOWN/UNCONFIRMED state rather than making a false claim.
- Distinguish transport connection state from discoverability and friendship.
- State changes may be communicated to the relevant peer when a valid channel exists.
- Status queries should be available through commands. A future GUI may show the last known status rather than constantly polling.

## 4. Server mode

### 4.1 Server independence and identity

- Each server is independent and has no server-to-server connection/federation.
- A server has a server-chosen display name.
- Each server has its own username namespace. `@name` on Server A and `@name` on Server B are unrelated accounts.
- The server stores account data, friend relationships, group membership/metadata, and notifications for its own community.
- The server may know the source IP address of a connecting client for transport/security purposes, but ordinary users must not be shown other users' IP addresses.
- The server operator assigns administrator status; users cannot grant it to themselves.

### 4.2 Registration and authentication

Default registration fields:
- `@UserName`
- `Passwd`
- `@Email`

The server operator can configure which fields are required and the registration policy. The default policy is automatic approval, but servers may configure manual or external verification.

- No guest-account mechanism in Server mode.
- Login credentials must be handled securely; never store plaintext passwords.
- Registration policy is server-controlled.
- External verification is not a built-in verification product. Ourcamellia supplies documented URL interfaces for different supported integration protocols and a receipt/acknowledgement contract. The deployer chooses and operates the external verifier.
- Document supported request and receipt formats, authentication/signature expectations, timeout/retry behavior, failure states, and safe configuration. Do not silently accept an invalid or unverified callback.
- External verifier endpoints are operator-configured, not arbitrary user-submitted destinations. Protect server-side URL calls against SSRF and unintended access to internal network resources.
- Server-side registration and recovery policy determines the available response when a user forgets the secondary password.

### 4.3 Server name and local alias

- The server controls its public server name.
- Each client may assign a private local note/alias to a server.
- Do not confuse the server's official name with the client's local alias.

## 5. Friends, conversations, groups, and BOTs

### 5.1 Friendship

- Both Local and Server modes support friend requests and acceptance.
- A request can be pending, accepted, rejected, expired, or undeliverable as appropriate to the transport.
- Do not represent a sent request as accepted or delivered without evidence.
- Connection permission and discoverability do not automatically imply friendship.

### 5.2 Private messages

- Support ongoing text-message exchange after a valid conversation is established.
- A message is sent as a message, not recursively parsed as a command.
- Preserve message text as text; never interpret message payloads as commands on the receiving side.
- Private-message history is stored locally by each client according to that client's history settings.
- One user's decision to record their own local history does not require the other participant's consent. Do not claim that this prevents the other participant from recording or copying messages.

### 5.3 Groups

- Creating a group is a command with a group name and an initial member list. The user's conceptual example is `create-group{(group name): "Member A", "Member B"}`; the exact concrete grammar must be formally defined and documented.
- Group membership and group metadata are server-side in Server mode.
- Group owners have the second-highest group-relevant authority; server operators retain their applicable higher administrative authority.
- Group permissions should include, at minimum, group creation, member invitation/removal, leaving, ownership/management rules, and message sending.
- The product must support both ordinary groups where server operators can review content and explicitly encrypted groups where the server operator cannot monitor message content.
- The group privacy/encryption mode must be explicit to participants before they rely on it. Do not imply server monitoring is possible for an encrypted group.
- The definition of the built-in “server group” shown at the top of the conversation list remains a **Decision required** item.

### 5.4 BOTs and programmatic access — Confirmed

- BOTs are participants/accounts visibly marked `BOT`.
- A BOT can appear in a friend list and in group conversations.
- First version includes both ordinary/manual BOT participation and a formal programmatic API suitable for external programs/agents.
- Programmatic access must use explicit authentication and authorization. Do not grant a BOT administrator rights merely because it uses the API.
- Define BOT identity, token/credential lifecycle, revocation, rate limits, available actions, and whether a BOT acts as a user or on behalf of a user.
- The API is an application/programming interface, not automatically a network protocol. Document which interfaces are in-process/local and which, if any, are network-accessible.
- Do not expose an unauthenticated remote management API.

## 6. Commands and message parsing

### 6.1 Confirmed parsing principle

- A command is executed only when the complete logical input line/string strictly matches exactly one complete command expression.
- Trailing spaces at the end of the line do not prevent recognition.
- If any additional non-whitespace content exists outside the command expression, treat the entire input as an ordinary message. Do not execute a command substring found inside it.
- Ordinary text messaging is semantically the default `say` operation.
- A `say` command can explicitly send text that resembles a command. The user's illustrative example is `${say(${info})`, intended to send the literal text `${info}` rather than execute `info`.
- A literal `${}` can be represented using the documented escape `\${}`.
- A line can contain at most one command. Command parsing must not recursively parse the text argument of a command or any received message.
- In Old mode, `\n` in input represents a newline within the message; output displays that newline normally. Observatory mode may use its multiline input mechanism, but both modes must produce equivalent message content.

### 6.2 Formal grammar is an implementation decision requiring explicit documentation

The user has described parameterized commands conceptually as a structure similar to:
`say{("content"): "string parameter", boolean parameter, numeric parameter}`
The exact delimiters and grammar are not yet finalized. The Agent must:
1. propose one consistent formal grammar supporting command names, optional arguments, strings, booleans, numbers, nested/literal command-looking text, escaping, and Unicode;
2. include examples and a parser test matrix;
3. document malformed-input behavior;
4. keep the parser deterministic and non-recursive;
5. avoid executing a command when parsing is ambiguous or malformed;
6. make the grammar usable by a future GUI/API without requiring GUI input to be parsed as terminal text;
7. implement the chosen grammar consistently across both CLI modes.

Do not treat the illustrative snippets as a license to invent incompatible syntax without documenting the decision.

### 6.3 Notifications commands

- `${info}` is an example of a command to inspect notifications.
- Notification lists may use a numeric selection. A command/input such as `1 pass` can accept a friend request associated with item 1.
- A pure informational/server notification can be opened by its number; `2 over` marks it reviewed and removes it from the active notification list.
- The exact canonical syntax for these examples follows the formal command grammar and must be documented consistently.
- Commands must validate indices, operation availability, permissions, and stale notification identifiers safely.

## 7. Notifications

- INFO appears in relevant second- and third-level menu status regions.
- Friend requests can appear in notifications.
- Server announcements can be delivered to users who were offline; after login, the server informs them of pending notifications.
- The server operator configures the retention/expiry duration and distribution policy for server notifications.
- Persist notification state so restart/offline behavior is reliable.
- Distinguish unread, read/reviewed, acted-on, expired, and dismissed states as appropriate.
- A notification's disappearance from the active list must not accidentally delete unrelated conversation history.
- Avoid duplicate notifications on reconnect/retry. Define stable IDs and idempotent handling.

## 8. Conversation history and persistence

### 8.1 Confirmed behavior

- Each client keeps its own local history.
- History is stored in JSON.
- Default configuration enables automatic recording, but the operator/user configuration can set the default to disabled.
- When recording is enabled, new messages are automatically persisted.
- When recording is disabled, new messages remain in process memory and are not written to JSON automatically.
- Re-enabling recording resumes automatic persistence for new messages. It does not by itself erase earlier saved history.
- A separate command can persist the currently buffered, not-yet-persisted messages from the current conversation into its history file.
- A separate deletion command removes saved history. Turning recording off never deletes previously saved JSON history.
- A user may manually persist the current conversation even if automatic recording is disabled.
- Buffered, unpersisted messages are lost when the process ends unless the user persists them first.
- The system must not silently write buffered content to disk when recording is disabled.

### 8.2 Exit behavior — implement with a configurable policy

The user has specified that, when automatic recording is not enabled, the default exit behavior should ask whether to persist the current conversation content. Interpret this narrowly:
- prompt only when the current session contains buffered messages that have not been persisted;
- offer a clear yes/no choice (and a safe cancel/return option if appropriate);
- on “yes”, persist only the intended unpersisted messages and confirm success;
- on “no”, exit without writing those buffered messages;
- if there is no unpersisted content, do not ask;
- make the policy configurable, and document how non-interactive/Old mode handles the prompt (e.g. no prompt when stdin is not interactive; report that buffered messages will be lost unless an explicit policy says otherwise).
If the user intended a broader prompt policy, record it as a decision to confirm rather than expanding it silently.

### 8.3 Deletion and data integrity

- History deletion is a separate explicit command and must have a clearly scoped target and confirmation strategy.
- The target scope (one conversation/session versus all history with a peer versus all local history) is a **Decision required** item. Propose a safe default and document it before implementing destructive behavior.
- Use robust writes (temporary file + atomic replacement where supported), validate JSON on load, and recover gracefully from corrupted or partially written files without silently discarding recoverable data.
- Avoid duplicate messages on retry/restart; define stable message IDs or an equivalent strategy.
- Distinguish message receipt/delivery status from history persistence status.

## 9. Configuration, observability, and operation

- Provide documented configuration files with safe defaults.
- Configuration should cover at minimum: default recording state, terminal mode, Local discoverability/connectability, server bind/listen settings, server display name, registration fields/policy, notification retention, and group encryption/privacy policy.
- Secrets must not be checked into source control or printed in logs.
- Logs should support diagnosis without dumping message bodies, passwords, secondary passwords, tokens, private keys, or unnecessary personal data.
- Provide helpful error messages and deterministic exit behavior.
- Include graceful shutdown and resource cleanup.
- Document ports, firewall requirements, and how to run a local test server/client.

## 10. Acceptance criteria

The first version is not complete until:
- clean build succeeds from the documented instructions;
- client and server can be started independently;
- Local and Server flows have integration tests;
- both CLI modes exercise the same application core;
- command parsing passes positive, negative, escaping, multiline, trailing-space, and nested-looking-text tests;
- friendship, discoverability, connectability, and observer-relative status are tested independently;
- ordinary and encrypted group behavior are distinct and accurately disclosed;
- BOT API authentication/authorization is tested;
- recording, buffering, manual persistence, exit prompting, deletion scope, JSON recovery, and restart behavior are tested;
- notification offline delivery, deduplication, expiry, and actions are tested;
- registration policy and external verifier receipts are tested;
- no known critical security defect or unresolved product decision is hidden in the final report;
- documentation matches actual behavior.
