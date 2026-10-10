# Ourcamellia — Architecture Decision Log (ADR)

Stage 0 record of high-impact decisions, with rationale and alternatives considered.
Product decisions explicitly marked "Decision required" in REQUIREMENTS.md were put to
the user and approved (recorded in §0). Everything else below is an engineering
decision made by the implementing agent, documented per ARCHITECTURE.md §9.

## 0. Approved product decisions (user-confirmed)

| # | Topic | Approved choice |
|---|-------|-----------------|
| P1 | Built-in "server group" pinned at top of Server-mode conversation list | Official **announcement channel** named after the server: every account is auto-joined and cannot leave; only server operators may post; posts are delivered both as server notifications (incl. offline delivery) and appear in the channel window. |
| P2 | History deletion scope | Three explicit scopes: `current` (current conversation), `peer <name>` (all local history with one identity), `all` (entire local history). Every scope requires confirmation; `all` requires a second explicit confirmation. Recording-off never deletes anything. |
| P3 | Exit prompt policy | Narrow interpretation of REQUIREMENTS §8.2: prompt only when the current conversation has buffered, unpersisted messages; yes/no/cancel; no prompt when nothing is buffered; no prompt when stdin is non-interactive (a message reports that buffered content will be lost). |
| P4 | Secondary password scope | Client-side only: protects **local conversation history files** with AEAD (key derived via PBKDF2 from the secondary password). The server never sees the secondary password; loss of it makes protected local history unrecoverable, and the server honestly discloses "no recovery" in its policy. |

## 1. Language, runtime, build

- **Decision:** Java 21 (LTS), Maven multi-module build, Maven Wrapper committed to the repo.
- **Rationale:** JDK 21 (Zulu 21.0.2) is the runtime present in the environment; LTS maximizes
  portability. Java + JCA means cryptography comes from a vetted standard library. Maven modules
  (`common`, `core`, `server`, `client`, `it`) keep the required separation of concerns
  (ARCHITECTURE.md §1) while staying a single repository (ARCHITECTURE.md §2).
- **Alternatives:** Kotlin (adds toolchain friction, no gain here); Gradle (not installed;
  Maven's declarative model is enough); plain `javac` scripts (non-reproducible dependency
  handling).
- **Dependencies (pinned):** jackson-databind 2.17.2 (JSON), jline-terminal/jline-reader 3.27.1
  (Observatory raw-mode terminal + Old-mode line editing), JUnit Jupiter 5.10.2 (tests).
  Nothing else. No database server, no web framework, no cloud service.
- **Supported runtime:** JDK 21+ (any OpenJDK-compatible distribution). Documented in README.

## 2. Terminal UI strategy

- **Decision:** Observatory mode uses the JLine 3 `Terminal` API directly (raw mode, cursor
  positioning, WINCH resize events) with one render loop that is the single owner of the
  display; async network events post to thread-safe state which the loop renders. Old mode is
  plain `System.in`/`System.out` line I/O (JLine reader when interactive for line editing, raw
  stream otherwise), never using ANSI positioning, suitable for pipes/scripts.
- **Rationale:** JLine provides portable terminal detection and graceful fallbacks (dumb
  terminals), avoiding hand-rolled ANSI/raw-mode code. Observatory needs full-screen control,
  which JLine's Terminal supports without adopting a heavyweight TUI framework (Lanterna).
- **Non-interactive behavior:** Old mode detects non-interactive stdin/stdout and disables all
  prompts (documented); Observatory refuses to start on a dumb terminal with a clear error.

## 3. Network protocol and transport

- **Decision:** TLS 1.2+ (JSSE) for all TCP connections — server↔client and Local peer↔peer —
  with length-prefixed UTF-8 JSON frames, a `v` version field, bounded frame size (default
  1 MiB), and stable message/request IDs (UUIDv4). Self-signed certificates generated at first
  run via `sun.security.x509.CertAndKeyGen` (wrapped behind an interface), pinned by
  fingerprint (TOFU) on the client side; server operators may supply their own keystore.
  App-level keepalive: ping/pong every 30 s, 90 s read timeout.
- **Rationale:** JSSE is a vetted TLS implementation; TOFU pinning gives an honest
  "identity = address + key fingerprint" model (SECURITY.md §2: Local-mode friendship is
  associated with an address/key, and this is documented, not claimed as strong identity).
  JSON frames keep the codebase small and debuggable; length prefix + max size bounds hostile
  input. Password is only ever sent inside the TLS channel, never plaintext on the wire.
- **Discovery:** separate UDP capability (default port 54535): a JSON query is broadcast;
  only peers that are *both* discoverable and connectable answer by unicast with
  `{username, tcpPort, certFingerprint, expiry}`; responses cached with TTL and never
  interpreted as "online now" (observer-relative status only). On networks where broadcast is
  unavailable, discovery simply returns nothing and manual address entry still works
  (documented limitation).
- **Alternatives:** SRP password-authenticated key exchange over plaintext TCP (more custom
  crypto to get right, no benefit over TLS here); WebSocket (needless web dependency);
  Netty (heavy; standard NIO + virtual threads sufficient). Java 21 virtual threads
  (one thread per connection) keep the networking code simple and safe.

## 4. Server persistence

- **Decision:** Authoritative in-memory state + JSON snapshot files with atomic writes.
  One structural snapshot `server-state.json` (accounts incl. password hashes, friendships,
  groups, notifications, registrations, bot tokens, admin set) written atomically
  (temp file + fsync + rename), plus a separate bounded operator review log
  `group-review.json` for operator-visible group content. A `data.lock` file (FileLock)
  prevents two server processes sharing a data dir.
- **Rationale:** A single structural snapshot gives all-or-nothing transactional consistency
  across accounts/friends/groups/notifications without an embedded database dependency
  (ARCHITECTURE.md §6: flat files need locking/atomicity/recovery documented — done here).
  Volumes are a small community's worth of data; the snapshot is rewritten on mutation
  batches. The review log is append-oriented and independently recoverable.
- **Alternatives:** H2/SQLite embedded DB (dependency + migration strategy beyond need);
  per-entity JSON files (torn writes across relationships possible). Schema version field
  in every persistent format; corrupted files are quarantined (`*.corrupt-<ts>`) and the
  server refuses to start on a corrupted structural snapshot rather than silently dropping
  data.
- **Message content:** the server does NOT store private-message content and does NOT store
  encrypted-group content (it relays only); operator-visible group messages are appended to
  the bounded review log for moderation, with retention config. Documented in THREAT_MODEL.md.

## 5. Cryptography

All cryptography uses JCA primitives only; no custom constructions.

- **Login passwords:** PBKDF2-HMAC-SHA256, 16-byte random salt, configurable iterations
  (default 210 000; operators can raise toward OWASP's 600 000), constant-time verify.
  Hashes stored server-side; plaintext never logged or persisted.
- **Secondary password (P4):** PBKDF2-HMAC-SHA256 → 256-bit key → AES-256-GCM sealed
  container with version byte, salt, per-file random nonce and AAD = filename+conversation id.
  Protects local history files only; the server is never involved.
- **Encrypted groups:** X25519 key agreement (JCA XDH) + HKDF-SHA256 (RFC 5869, implemented
  over JCA `Mac`, validated against RFC test vectors) + AES-256-GCM. Group key is a random
  256-bit key; the creator wraps it to each member's X25519 public key; member-add wraps the
  current key for the new member; member-removal rotates the group key (wrapped to remaining
  members). The server stores/relays only wrapped key blobs and ciphertext — it cannot read
  content through ordinary operation. Honest limitations (no post-compromise security; a
  removed member who captured old ciphertext can decrypt old messages; the server can
  exclude members or block the group) are disclosed in THREAT_MODEL.md and in the UI.
- **External verifier:** HMAC-SHA256 request/receipt signing with an operator-configured
  shared secret; request idempotency via stable request IDs; bounded timeout and retry.
- **BOT API tokens:** 256-bit random tokens, stored only as SHA-256 digests, shown once at
  creation, revocable per token, rate-limited.

## 6. Command grammar

Formal grammar defined in `COMMAND_GRAMMAR.md`: commands are written
`${name(args...)}`; strict whole-line matching; trailing spaces allowed; anything else is an
ordinary `say` message; `say` payloads are never recursively parsed; escape `\${}` for a
literal `${}`; Old-mode `\n` for newline. The parser is a non-recursive state machine in
`core` (usable by a future GUI through structured argument objects, not terminal strings).

## 7. BOT API surface

- **In-process Java API** (`org.ourcamellia.core.botapi.BotSession`): BOT programs embedded
  in the server JVM authenticate with a bot token and receive send/receive operations. This
  is the primary stable programmatic interface.
- **Optional localhost HTTP adapter** (`ourcamellia-server` config `botapi.enabled`, default
  bind `127.0.0.1:54700`): minimal JSON API (`/v1/auth`, `/v1/send`, `/v1/events`,
  `/v1/conversations`) with bearer-token auth, per-token rate limits, and no administrative
  operations. Binding to non-loopback is possible but documented as an explicit operator
  risk decision. There is no unauthenticated remote management API.
- BOT is a *participant type* (visible `BOT` marker), not a privilege level; BOTs never get
  administrator rights via the API (SECURITY.md §2).

## 8. Local-mode groups

- **Decision:** Local mode supports groups as owner-coordinated peer-to-peer groups:
  the owner invites members over direct connections; membership metadata is stored locally
  by each participant; messages are unicast to each member. Ordinary groups are plaintext to
  participants; encrypted groups reuse the same X25519/AES-GCM design (owner distributes the
  group key).
- **Rationale:** REQUIREMENTS §5.3 scopes server-side membership explicitly "in Server mode",
  and the first-version boundary includes group conversations; keeping one crypto design for
  both modes avoids divergent code. Limitation (no central membership authority; a removed
  member must be rotated out by the owner) is documented.

## 9. Server-mode account flow

- Registration fields default `@UserName`, `Passwd`, `@Email`, configurable required set and
  policy: `auto` (default), `manual` (operator approves in server console), `external`
  (HMAC-signed HTTP callback contract, see PROTOCOL.md; SSRF-guarded). No guest accounts.
- Initial admin bootstrap: the operator lists initial admin usernames in server config; the
  first account registered with such a name becomes operator. Operators promote/demote via
  the server console. Server console is a line-oriented operator interface (never exposed
  over the network).
- Server display name vs. client alias are distinct fields; ordinary users never receive
  other users' IP addresses (server strips transport addresses before broadcast).

## 10. Findings recorded during implementation (post-decision notes)

- **JSSE TLS 1.3 client-auth quirk:** a server context created with `null` trust
  managers sends a CertificateRequest no client can satisfy ("Empty client
  certificate chain"). Local-mode mutual TLS therefore uses a trust-all server
  context (`SelfSignedCerts.serverContextWithTrustAll`) — safe because peer identity
  is enforced above TLS by fingerprint pinning and the name/fingerprint binding in
  the HELLO handshake. Covered by `TlsClientAuthIT`.
- **Self-signed certificates** are generated with a minimal pure-JCA X.509 builder
  (`X509SelfSigned`, DER-encoded, KeyUsage+BasicConstraints) — `sun.security.x509`
  is not exported from `java.base` on JDK 21. End-to-end validated by TLS handshake
  tests on both sides.
- **Rate limiter semantics:** buckets start full (a fresh client gets its whole
  per-minute budget), never with a single token.
- **Data-dir authority:** the config file's `dataDir` is authoritative for both
  executables; `--data-dir` overrides it. (A bug where the flag-only path ignored
  the config value was found by ProcessIT and fixed.)
- **Process-level async races:** piped Old-mode scripts can outrun async server
  responses; the cross-process acceptance test drives the client interactively
  (write → await expected output → next command). This is a test-harness property,
  not a product limitation.

## 11. Key technical constraints found in environment

- macOS 15 (arm64), JDK 21.0.2 Zulu, no system Maven — Maven 3.9.9 downloaded into the
  workspace `.tools/` and Maven Wrapper generated into the repo for reproducibility.
- Maven Central reachable. No GUI available/needed. UDP broadcast behavior is
  network-dependent; tests use loopback unicast for the discovery codec plus a real
  two-process loopback integration test.
