# Ourcamellia

Lightweight, decentralized-by-independence chat platform — first version.
Each server is an independent community with its own identity namespace, accounts,
relationships, groups, policies, and data. There is no federation, no central
directory, and no central account system.

Components:

- `ourcamellia-client` — command-line client with two presentation modes:
  **Observatory** (fixed-layout terminal UI, default on real terminals) and
  **Old** (line-oriented, scriptable).
- `ourcamellia-server` — independently runnable community server with an
  operator console.
- Local mode — direct peer communication with UDP discovery, TLS transport,
  friendship gates, and observer-relative status.
- Server mode — accounts (configurable registration fields and policies),
  friends, groups (operator-visible and encrypted), notifications with offline
  delivery, the announcement channel, and a BOT API.

## Requirements

- JDK 21 (any OpenJDK-compatible distribution; developed on Zulu 21.0.2).
- Maven 3.9+ (`mvn`) — or use the Maven Wrapper: `./mvnw`.
- POSIX shell for the wrapper scripts (macOS/Linux). On Windows use the shaded jars
  directly (`java -jar ...`).

## Build

```bash
mvn -q package          # compiles, runs the full test suite, builds shaded jars
```

Artifacts:

- `server/target/ourcamellia-server.jar`
- `client/target/ourcamellia-client.jar`

Test counts and what each suite covers are described in
[docs/REQUIREMENTS_TRACE.md](docs/REQUIREMENTS_TRACE.md).

## Run — client

```bash
java -jar client/target/ourcamellia-client.jar --data-dir ~/.ourcamellia
java -jar client/target/ourcamellia-client.jar --mode old          # scripts/pipes
java -jar client/target/ourcamellia-client.jar --help
```

- Observatory mode is selected automatically on a real terminal; on a dumb
  terminal it refuses with a clear error — use `--mode old`.
- Old mode is fully scriptable: input `\n` is a newline inside a message,
  `\${` is a literal `${`. Commands never depend on terminal capabilities.
- The configuration file lives at `<data-dir>/config.json`
  (see `docs/config-examples/client.json` for all options and defaults).

Client walkthrough:

```
${mode("local", "alice")}            # Local mode, temporary local identity
${connect("192.168.1.20:54536")}     # address-targeted connection
${friend-request("bob")}             # first contact is limited to the request path
${info}                              # list notifications
1 pass                               # accept the friend request (shortcut)
hello there                          # plain text is a message (default say)
${create-group("Study", "@bob")}     # Server mode: operator-visible group
${create-encrypted-group("Secret", "@bob")}   # encrypted: operators cannot read it
${record("off")}                     # stop automatic recording (never deletes history)
${persist}                           # persist buffered messages on demand
${history-delete("current")}         # confirmed deletion (all needs double confirmation)
${quit}                              # exit (prompts only when buffered content exists)
```

## Run — server

```bash
mkdir -p ./ourcamellia-server && cd ./ourcamellia-server
java -jar ../server/target/ourcamellia-server.jar run            # console + daemon
java -jar ../server/target/ourcamellia-server.jar genkey         # custom TLS identity
```

- The operator console runs on the server host over stdin (never over the network):
  `${admin add @name}`, `${announce("text")}`, `${registration approve <ticketId>}`,
  `${review <groupId>}`, `${mod-delete <groupId> <msgId>}`, `${bot-create @name}`,
  `${policy}`, `${stats}`, `${quit}`.
- Configuration: `<data-dir>/server.json` (see `docs/config-examples/server.json`).
- Default port **54530/TCP** (TLS). Local-mode clients additionally use
  **54536/TCP** (peer listener) and **54535/UDP** (discovery). Open these on the
  firewall as needed; UDP broadcast must be permitted on the LAN for discovery
  (discovery is optional — manual addresses always work).
- The first server start generates a self-signed TLS certificate; clients pin its
  fingerprint on first connect (TOFU) and refuse changed certificates.

## Data locations and backup

| Component | Location |
|---|---|
| Client data (default) | `~/.ourcamellia/` |
| Client history | `~/.ourcamellia/history/*.json` (one JSON file per conversation; optionally sealed with the secondary password) |
| Client state (friends, pins, notifications, aliases, X25519 key) | `~/.ourcamellia/state.json` |
| Server data (default) | `./data/` |
| Server structural state | `data/server-state.json` (atomic writes; single source of truth) |
| Operator review log | `data/group-review.json` (operator-visible group content, bounded) |
| TLS identity | `data/tls/keystore.p12` + `data/tls/keystore.password` |
| Logs | `<data-dir>/logs/ourcamellia.log` (secret-redacted, message bodies excluded) |

Backup: copy the data directory while the process is stopped (the server refuses
two processes on one directory via a file lock). **Backups of encrypted-group
content are ciphertext only** — the group keys live on member devices; a server
backup can never recover encrypted-group plaintext. Client history protected by a
lost secondary password is unrecoverable by design (see THREAT_MODEL).

## Documentation

- [docs/DECISIONS.md](docs/DECISIONS.md) — architecture decisions and approved product decisions
- [docs/COMMAND_GRAMMAR.md](docs/COMMAND_GRAMMAR.md) — formal command grammar + test matrix
- [docs/REQUIREMENTS_TRACE.md](docs/REQUIREMENTS_TRACE.md) — requirements → code/tests mapping
- [docs/PROTOCOL.md](docs/PROTOCOL.md) — wire protocol, framing, discovery, verifier contract
- [docs/OPERATOR.md](docs/OPERATOR.md) — server operator guide (policies, ports, backup, moderation)
- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) — guarantees, mitigations, and residual risks
- [docs/config-examples/](docs/config-examples/) — full configuration examples

## Known limitations (first version)

- Local discovery needs UDP broadcast; on networks where broadcast is blocked,
  discovery returns nothing and manual address entry remains fully functional.
- Private messages are not queued by the server: an offline recipient means an
  honest "not delivered" report. Server announcements ARE queued (notifications).
- Encrypted groups: no post-compromise security — a removed member who captured
  old ciphertext can decrypt old messages; after removal the owner must rotate the
  key (the UI reminds them). Operators cannot moderate encrypted-group content and
  are not responsible for it.
- Observatory input is single-line (Old mode supports `\n` inside messages).
- The BOT HTTP adapter is plaintext HTTP by design — keep it bound to loopback.
- Terminal widths for CJK text are approximated in Observatory rendering.

## Privacy summary (honest statement)

- Local history is private to the local installation (optionally sealed with your
  secondary password; the server never sees it).
- Server operators can read and moderate operator-visible group content; they
  CANNOT read encrypted-group content, which the server relays as ciphertext only.
- Passwords are stored as PBKDF2-HMAC-SHA256 hashes; BOT tokens as SHA-256 digests.
- The product never shows other users' IP addresses to ordinary server-mode users.
- "Sent" is not "delivered": delivery reports reflect transport hand-off only.
- We cannot prevent a recipient from copying or screenshotting content — no claim
  of that kind is made.

## License

Copyright (C) 2026 Arktis-Jaeger

This program is free software: you can redistribute it and/or modify it under the
terms of the **GNU General Public License, version 3** as published by the Free
Software Foundation. See [LICENSE](LICENSE) for the full text.

This program is distributed in the hope that it will be useful, but **WITHOUT ANY
WARRANTY**; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE.

Because the program is distributed under GPL-3.0, anyone who conveys it or a
modified version must pass on the same freedoms and make the corresponding source
available. Running an unmodified copy on your own server does not by itself
trigger that obligation.

### Third-party components

Runtime dependencies are separately licensed and remain under their own terms;
GPL-3.0 is compatible with all of them:

| Component | License |
|---|---|
| Jackson (`com.fasterxml.jackson.core`) | Apache License 2.0 |
| JLine (`org.jline`) | BSD 3-Clause |
| JUnit Jupiter (test scope only) | Eclipse Public License 2.0 |
