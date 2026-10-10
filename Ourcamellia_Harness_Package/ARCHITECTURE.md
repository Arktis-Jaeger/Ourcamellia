# Ourcamellia — Architecture Requirements

This document constrains the architecture without prematurely forcing a specific framework or library.

## 1. Required separation of concerns

The implementation must separate at least these responsibilities:

1. **Domain model:** identities, friends, conversations, groups, notifications, messages, recording state, permissions, and status values.
2. **Application/use-case layer:** operations such as login, registration, friend request/acceptance, create group, send message, inspect notification, persist history, and delete history.
3. **Transport/protocol layer:** connection framing, serialization, authentication, timeouts, retries, and network error mapping.
4. **Persistence layer:** accounts, server policy, group metadata, notifications, local JSON conversation history, and configuration.
5. **CLI presentation:** Observatory and Old modes, input handling, rendering, command parsing, and user prompts.
6. **Programmatic API:** stable, documented operations for BOTs and future GUI clients.
7. **Security/authorization:** a consistent place to enforce permissions and data-access boundaries.

A CLI command must call the application layer; it must not implement its own duplicate business rules. A future GUI should be able to invoke the same use cases without pretending its controls are terminal command strings.

## 2. Repository and build

- Start from a clean implementation; do not reuse old project source code unless explicitly approved.
- Prefer one repository and a small number of modules. A candidate structure is `common`, `client`, `server`, and test modules, but the Agent may choose a better structure with a concise rationale.
- Choose a build tool based on maintainability and standard-JVM portability. Avoid adding dependencies without a clear reason.
- Pin dependency versions and document the supported JDK/runtime.
- Separate executable entry points for the client and server.
- Provide reproducible build and test commands.
- Do not introduce a database server, cloud service, central registry, or deployment platform unless required and explicitly justified.

## 3. Application API and BOT API

- Define application operations independently of the CLI syntax.
- Provide a documented programmatic interface for external BOTs and future GUI integration.
- Define whether the first version exposes the API in-process, over localhost, over a network, or through more than one adapter. This must be an explicit design decision, not an accidental consequence of binding a server socket to all interfaces.
- Authentication and authorization must be required for protected API operations.
- Separate normal user/BOT actions from server-administrator operations.
- Scope BOT credentials and allow revocation.
- Do not grant management powers to a BOT by default.
- If network-accessible API endpoints exist, document bind address, authentication, TLS/identity, permissions, rate limits, and safe defaults.

## 4. Command parser

- Implement a deterministic parser for the formal grammar defined in `REQUIREMENTS.md`.
- Parse only the complete input expression. Do not search arbitrary message text for command substrings.
- Parse once. A string supplied as a `say` payload is data and must not be recursively evaluated.
- Keep command dispatch separate from use-case implementation.
- Provide command metadata for help/usage where practical: name, argument schema, permission requirements, and result/error format.
- Use structured argument types rather than passing raw unvalidated strings into business operations.
- Include parser fuzz/property tests if practical.

## 5. Network protocol

- Define explicit message framing and versioning.
- Bound frame sizes and validate all decoded fields.
- Define connection lifecycle, keepalive/timeout behavior, heartbeat/status behavior if needed, and graceful close.
- Define message IDs and idempotency for retry-sensitive operations such as friend requests, notifications, and message delivery.
- Separate Local discovery traffic from ordinary chat traffic.
- Define what status the protocol can actually prove. Do not turn lack of response into a false certainty.
- Use a transport abstraction only where it reduces real duplication; do not create unnecessary layers.
- Document protocol compatibility expectations and version rejection behavior.

## 6. Persistence

- Local client conversation history uses JSON as required.
- Server-side persistence must cover accounts, authentication data, friendships, groups, registration/verification state, notification state, and server configuration/policy.
- Choose the lightest reliable server persistence solution that supports transactional consistency and safe restart. If using flat files, define locking, atomicity, recovery, and corruption handling; if using an embedded database, justify the dependency and migration strategy.
- Use schema/version fields for persistent formats.
- Use atomic replacement or transactional writes where applicable.
- Never write unpersisted messages to history while recording is OFF except through explicit manual persistence or the confirmed exit prompt.
- Separate configuration from generated data, secrets, logs, and user history.
- Provide a documented backup/restore approach and state what encrypted data cannot be restored without its keys.

## 7. Terminal UI

### Observatory
- Use a terminal abstraction/library if it materially improves portable cursor control, resize handling, and input; otherwise document why a custom implementation is safe.
- Maintain one rendering owner/event loop or another concurrency-safe strategy so asynchronous network events do not corrupt the input cursor.
- Keep a bounded visible viewport while preserving the underlying conversation model/history in memory.
- Handle terminals too small for the ideal layout by falling back to a compact layout or clear warning.

### Old
- Do not rely on ANSI cursor positioning or screen clearing.
- Ensure deterministic line-oriented behavior for redirection and automation.
- Input escape processing must be documented and tested.
- Avoid interactive prompts when input/output is non-interactive unless a configuration explicitly requires them.

## 8. Errors, logs, and diagnostics

- Use typed/internal error categories and user-readable messages.
- Do not crash on routine disconnects, invalid user input, unavailable interfaces, or malformed remote packets.
- Logs must not expose passwords, secondary passwords, tokens, keys, or full message content by default.
- Include enough diagnostic context to troubleshoot connection and persistence errors without leaking sensitive data.
- Make shutdown close network resources and flush only data that policy permits to be persisted.

## 9. Engineering workflow

Before major implementation:
1. inspect the workspace and runtime;
2. record JDK/build/dependency constraints;
3. produce a concise architecture decision record for major choices;
4. list unresolved product decisions and proposed defaults;
5. implement vertical slices with tests;
6. run the complete test suite after cross-cutting changes;
7. perform a final security and requirements audit.

Do not spend tokens narrating every trivial action. Report meaningful decisions, test failures, blockers, and deviations.
