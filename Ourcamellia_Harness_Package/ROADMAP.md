# Ourcamellia — Implementation Roadmap and Acceptance Gates

The roadmap defines internal work stages for one complete first-version delivery. Passing one stage is not permission to stop the overall task.

## Stage 0 — Workspace reconnaissance and decisions

- Inspect existing files and repository state, but do not reuse old source implementation.
- Identify JDK, build tools, OS/runtime constraints, and available network/test capabilities.
- Select the build system, module layout, terminal approach, server persistence, network transports, and cryptographic libraries based on requirements.
- Create a concise decision log with rationale and alternatives considered for high-impact decisions.
- Resolve formal command grammar by documenting a proposal and test matrix. Clearly flag any remaining product decision, especially the meaning of the built-in server group and history deletion scope.
- Do not ask the user to decide ordinary implementation details that can be responsibly decided by engineering.

**Gate:** requirements map and architecture plan exist; no high-impact assumption is hidden.

## Stage 1 — Project skeleton and shared core

- Set up reproducible build, modules, style/check commands, test framework, and executable entry points.
- Implement shared domain models, configuration parsing, error types, IDs, serialization/versioning primitives, and application service boundaries.
- Establish tests and CI-like local verification commands.
- Verify the application core can be invoked without the CLI.

**Gate:** clean build/test succeeds; core is independent of terminal UI.

## Stage 2 — Command grammar and CLI foundation

- Implement the formal command grammar and parser.
- Implement the command registry/dispatcher and help/usage output.
- Implement Old mode and Observatory mode using the same application layer.
- Test strict whole-line command recognition, trailing spaces, ordinary text, escaped `${}`, nested command-looking text in `say`, malformed commands, multiline input, and non-interactive behavior.
- Ensure received messages are never recursively interpreted as commands.

**Gate:** parser test matrix passes in both modes; UI resize/input handling does not corrupt message state.

## Stage 3 — Local mode

- Implement direct peer transport and discovery as separate capabilities.
- Implement discoverability/connectability settings.
- Implement Local identity, connection lifecycle, friend request/accept/reject behavior, and ordinary text messaging.
- Implement observer-relative status semantics.
- Test all permission combinations, unreachable peers, timeout, interface unavailability, malformed packets, and first-contact restrictions.

**Gate:** two local clients can complete the supported flow; permission/status tests pass.

## Stage 4 — Server foundation and accounts

- Implement an independently runnable server with server name, configuration, persistence, and secure password authentication.
- Implement account registration/login, server-scoped usernames, custom required fields, and registration policy.
- Implement default automatic approval, plus supported manual/external verification integration contracts.
- Implement external receipt validation, idempotency, timeout/failure behavior, and URL safety protections.
- Implement client connection and ensure peer IP addresses are not exposed to ordinary Server-mode clients.

**Gate:** server/client integration tests pass; registration and authentication tests pass.

## Stage 5 — Server friends, notifications, and messaging

- Implement server-mode friend requests and relationships.
- Implement private messaging and notification persistence.
- Implement offline notification retrieval on next login, stable IDs, deduplication, expiry, read/reviewed state, and supported notification actions.
- Implement observer-relative/known status where applicable.
- Ensure permissions are checked server-side.

**Gate:** online/offline/restart and notification-action tests pass.

## Stage 6 — Groups and BOTs

- Implement group creation, membership, roles, group-owner permissions, and server-operator authority.
- Implement ordinary operator-visible groups and a genuinely operator-unreadable encrypted group mode, or clearly report a security blocker if a correct implementation cannot be delivered. Do not fake end-to-end encryption.
- Document group privacy at creation/join time and enforce the chosen mode.
- Implement BOT identities and visible BOT markers.
- Implement programmatic API authentication, permission scoping, token/credential revocation, rate limiting, and user-versus-admin separation.
- Test unauthorized operations and encrypted-group access boundaries.

**Gate:** group permission matrix, encryption boundary tests, and BOT API security tests pass.

## Stage 7 — History, configuration, and recovery

- Implement local JSON history, default recording configuration, recording toggle, in-memory buffering, explicit persistence command, deletion command, and exit prompt behavior.
- Implement safe writes, schema versioning, duplicate avoidance, corrupted-file handling, and restart tests.
- Implement configuration documentation and safe defaults.
- Implement clear behavior for non-interactive Old mode.

**Gate:** all recording/persistence/deletion cases in the requirements are tested; no silent persistence while recording is OFF.

## Stage 8 — Integration, hardening, and release readiness

- Run all tests from a clean state.
- Run formatting/static analysis available in the chosen stack.
- Audit every requirement in `REQUIREMENTS.md` and every threat item in `SECURITY.md`.
- Check resource cleanup, network timeouts, malformed inputs, permission boundaries, and logs for secret leakage.
- Test fresh installation/run instructions and independent client/server launch.
- Fix issues found; do not merely list them if they are within scope and fixable.
- Update architecture decisions and documentation to match actual behavior.

**Gate:** all acceptance criteria pass, or every remaining blocker is clearly identified with evidence and a concrete recommendation.

## Final delivery report

The final response to the user must include:
- what was implemented;
- exact build/test commands run and their results;
- any tests not run and why;
- launch instructions for client and server;
- configuration/data locations and backup notes;
- important security/privacy limitations;
- a requirement checklist mapping the scope to implementation/tests;
- unresolved decisions or blockers, without claiming completion for unimplemented items.

Do not say “complete” merely because compilation succeeds.
