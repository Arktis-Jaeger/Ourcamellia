# Ourcamellia — Threat Model and Residual Risks (v1)

This is the honest description of what the product protects and what it does not.
"No claim" lines are intentional: we do not promise properties the design cannot
deliver.

## Trust boundaries

| Boundary | Who can read/do what |
|---|---|
| Local history (client disk) | the local installation/user; optionally sealed with the secondary password (AES-256-GCM via PBKDF2). The server never sees it. |
| Private messages in transit | encrypted by TLS; the Server-mode server sees plaintext while relaying (it must, to route) — this is disclosed. Local-mode peers see plaintext (they are the recipient). |
| Operator-visible group content | members + server operators (review log); plaintext in server memory while relaying — disclosed at creation. |
| Encrypted group content | members only. Server stores/relays wrapped keys + ciphertext; operator cannot read content, cannot moderate. |
| Server structural state | the operator (host access). Passwords as PBKDF2 hashes; BOT tokens as SHA-256 digests. |
| Client source IPs | transport layer only (rate limiting/diagnostics); never stored in state, never sent to users. |

## Threat-by-threat review (SECURITY.md §9)

1. **Malicious peers / malformed packets** — bounded frames (1 MiB), strict field
   validation, JSON nesting/string limits, connection closed on violation, UDP
   garbage dropped. Tested: FrameCodecTest, WireTest, DiscoveryIT, fuzz parser test.
2. **Impersonation / spoofed discovery** — TLS + certificate fingerprint pinning
   (TOFU) for peers and servers; friend fingerprints checked on inbound connections;
   changed fingerprints refused. Discovery replies carry fingerprints and are never
   treated as identity proof. Tests: LocalModeIT.certificateChangeIsRefused.
   *Residual:* first-contact TOFU trusts the first-seen certificate; a network
   attacker present at that moment can pin their own key (standard TOFU risk,
   documented). Discovery UDP replies can be spoofed on the LAN — they only feed the
   directory, and the TLS fingerprint check applies when connecting.
3. **Brute-force login / BOT credentials** — PBKDF2-HMAC-SHA256 with per-account
   salt (configurable work factor), login rate limits per IP and per user, BOT tokens
   are 256-bit random, stored as digests, rate-limited per token, revocable. Tests:
   ServerModeIT.loginRateLimit, BotApiIT.
4. **Privilege escalation / unauthorized group/notification actions** — every
   protected operation is authorized server-side (group membership, ownership,
   friendship, notification ownership); BOT API surface has no administrative
   operations. Tests: GroupModeIT, BotApiIT.
5. **Leaked server backups / local history files** — backups contain hashes
   (passwords/BOT tokens) and ciphertext (encrypted groups). Local history is
   optional sealed with the secondary password; loss of that password makes the
   history unrecoverable (no backdoor). *Residual:* a stolen client state file
   (`state.json`) contains the local X25519 private key; whoever can read it AND
   captured encrypted-group ciphertext can decrypt it. Documented.
6. **Malicious/misconfigured verifier URLs; replayed/forged receipts** — SSRF guard
   (scheme allowlist, private/loopback/link-local blocking, redirect re-validation,
   DNS checked per hop); HMAC-signed requests and receipts with nonce echo and
   constant-time comparison; unauthenticated callbacks rejected; idempotent tickets.
   Tests: ExternalVerifierIT. *Residual:* DNS rebinding between check and connect is
   a documented race window; deploy the verifier on trusted infrastructure.
7. **Terminal escape injection / hostile usernames** — control characters are
   rejected at validation (`Text.requireCleanText`) and stripped at render time;
   username charset is restricted to `[A-Za-z0-9._-]`. Tests: TextTest, WireTest.
8. **Corrupted JSON/history files** — atomic writes (temp+fsync+rename); corrupted
   history files are quarantined and recovered empty; corrupted server state
   quarantines and refuses to start (never silently drops accounts). Tests:
   LocalHistoryStoreTest.
9. **Lost secondary password / group keys** — secondary password protects local
   history only; loss = unrecoverable, and the server honestly discloses "no
   recovery". Encrypted-group key loss (owner's device) = that client can no longer
   read the group until re-wrapped by the owner. No false promises anywhere.
10. **Operator access per group mode** — ordinary groups are operator-readable and
    moderated; encrypted groups exclude the operator by construction (ciphertext
    only). Disclosure text is shown at group creation. Tests: GroupModeIT.
11. **Resource exhaustion / spam / repeated connections** — rate limits (login,
    register, friend requests, messages, group ops, BOT tokens), bounded frame sizes,
    bounded notification/friend/group lists, review log retention, connection
    timeouts + heartbeat, single-session-per-account replacement. Tests: rate-limit
    suites.

## Honest limitations (by design)

- Private messages are not queued: offline recipient → "delivery failed" (announcements
  are queued as notifications). "Delivered" means handed to the recipient's
  connection, not read.
- Encrypted groups have no post-compromise security: a removed member who captured
  old ciphertext can decrypt it; the server can drop messages or exclude members
  (availability attacks) but cannot read or forge content; key rotation is owner-
  triggered and the UI reminds after removal.
- Local-mode identity is "name + pinned key fingerprint", not real-world identity.
- Observatory rendering approximates CJK character widths.
- The BOT HTTP adapter is plaintext HTTP on loopback by default.
- UDP discovery requires a broadcast-capable network; without it, manual addresses
  still work.
- This is a threat model, not a certification: "no known critical defect in the
  implemented scope" is the completion standard, not "secure against all attackers".
