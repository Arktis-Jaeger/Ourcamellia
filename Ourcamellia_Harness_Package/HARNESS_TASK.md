# Harness Task — Build the Complete Ourcamellia First Version

## Mission

Implement the complete first-version Ourcamellia product described in `PROJECT.md`, `REQUIREMENTS.md`, `ARCHITECTURE.md`, `SECURITY.md`, and `ROADMAP.md`.

This is a full delivery task, not a prototype task. You may work in internal stages and test after each stage, but you must continue through the entire agreed scope. Do not stop after scaffolding, a parser demo, or a minimal chat implementation.

## Authority and constraints

- You may make ordinary technical decisions within the project workspace.
- Do not access or modify files outside the authorized workspace.
- Start from a clean implementation. Do not copy old project source code merely to save time.
- Preserve the product's confirmed requirements and security boundaries.
- Do not introduce a central server, server federation, guest accounts in Server mode, or an unauthenticated remote management API.
- Keep dependencies and architecture as small as reasonably possible.
- Never invent cryptography. Use vetted libraries and document actual guarantees.
- Do not silently omit requirements. If a requirement is impossible or materially ambiguous, record it, propose a recommendation, and continue with independent work that does not depend on it.
- Do not ask the user to decide routine engineering details. Make and document sound choices.
- If an unresolved product choice materially changes security, user-visible behavior, or stored-data compatibility, do not bury it in an assumption. Produce a concise decision request with the recommended option and explain why it blocks that part of implementation.
- Avoid token-wasting narration of trivial actions. Keep a decision log and report meaningful progress, test results, blockers, and deviations.

## Required workflow

1. Read all project Markdown files completely before changing source code.
2. Inspect the workspace, JDK, build tools, existing files, and runtime constraints. Do not assume the workspace is empty.
3. Create or update a requirements traceability checklist linking each requirement to code areas and tests.
4. Record high-impact architecture decisions and unresolved product decisions before committing to choices.
5. Select the build system, module layout, terminal library/strategy, server persistence, network protocols, and cryptographic libraries with concise rationale.
6. Implement in the stages in `ROADMAP.md`, with tests at each stage.
7. After each cross-cutting change, run the relevant tests; periodically run the complete suite.
8. If tests fail, investigate and fix them rather than masking or deleting tests. Do not weaken a test solely to make the build pass.
9. Perform a final security/privacy review and requirement-by-requirement acceptance audit.
10. Update all documentation so it describes the actual implementation, not the original plan if the implementation differs.
11. Deliver the final report specified in `ROADMAP.md`.

## Command grammar requirement

The command syntax examples in the specification are conceptual and include an unresolved exact formal grammar. Resolve this deliberately:
- document a single formal grammar;
- make whole-input matching strict;
- permit trailing spaces;
- treat extra non-whitespace content outside a command as ordinary message text;
- ensure normal text is semantically `say`;
- support explicit `say` of command-looking literal text;
- never recursively execute command-looking text in arguments or received messages;
- support escaped literal `${}` and the Old-mode `\\n` input convention;
- test nested-looking content, malformed commands, Unicode, multiline text, and ambiguous inputs.

Do not let terminal parsing define the application's business API.

## Security gates

Before completion, verify at minimum:
- password hashes rather than plaintext passwords;
- separate login and secondary-password semantics;
- authenticated encryption for data protected by secondary password;
- server operator visibility for ordinary groups and genuine operator-unreadability for encrypted groups;
- accurate user disclosure of each group's privacy mode;
- secure external-verifier receipt validation and SSRF defenses;
- no unauthorized server-mode IP disclosure;
- server-side authorization for every privileged operation;
- BOT credentials are scoped/revocable and do not imply administrator access;
- history recording OFF never silently persists new buffered messages;
- logs do not leak secrets;
- malformed network input is bounded and safely rejected.

## Completion standard

Do not finish merely because the application compiles or one happy-path demo works. The delivery is complete only when the full first-version scope has been implemented, tests have been run, documentation matches behavior, and the final report clearly distinguishes passed checks from unresolved limitations.

If a secure encrypted-group implementation cannot be completed correctly within this task, do not substitute transport encryption or disk encryption and call it end-to-end encryption. Report the exact blocker and a safe recommendation, while completing independent requirements.
