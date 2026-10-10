# Ourcamellia — Operator Guide

Running one independent community server. Each server is fully independent: its own
accounts, friendships, groups, notifications, and policies. There is no federation
and no central directory.

## 1. Start

```bash
java -jar ourcamellia-server.jar run --data-dir ./mydata
```

- Config file: `<data-dir>/server.json` (created from defaults; see
  docs/config-examples/server.json). Unknown keys are ignored with a warning;
  invalid values fail with a clear message.
- First start generates a self-signed TLS certificate
  (`<data-dir>/tls/keystore.p12`, password in `tls/keystore.password`, 0600).
  Clients pin the fingerprint on first connect (TOFU) and refuse changes — publish
  the fingerprint to your users out-of-band. For a CA-signed identity, drop your own
  PKCS12 keystore at the configured path and set `tlsKeystorePassword`, or use
  `ourcamellia-server genkey`.
- Default port: **54530/TCP** (TLS). Open it in the firewall.

## 2. Console (operator terminal, local only)

The console runs on the server host over stdin — never over the network. Host access
is the operator authentication boundary.

```
${admin add @name} / ${admin remove @name}
${announce("text")}                    → announcement channel + notification (offline delivery)
${registration approve <ticketId>} / ${registration reject <ticketId>}
${groups}                              → group ids, privacy modes
${review <groupId> [N]}                → operator review log (operator-visible groups only)
${mod-delete <groupId> <msgId>}        → remove a message everywhere (operator-visible groups only)
${bot-create @name}                    → prints the BOT token + X25519 key ONCE
${bot-revoke @name}                    → revoke all tokens of a BOT
${policy} / ${stats} / ${quit}         → policy summary / stats / graceful shutdown
```

## 3. Registration policies

- `auto` — approved immediately (default).
- `manual` — pending until an operator approves via the console. Pending tickets
  expire after `pendingTtlMinutes`.
- `external` — the server POSTs each ticket to your verifier (see the receipt
  contract in PROTOCOL.md). You must run the verifier yourself; Ourcamellia only
  provides the URL interfaces. Configure `verifier.url`, `verifier.sharedSecret`
  (HMAC), timeout/retries, and SSRF settings. Keep the URL on a network segment you
  control; private targets are refused by default (`allowPrivateTargets` must be
  explicitly true to reach them).

Required fields: `@UserName` and `Passwd` are always required; add/remove fields in
`requiredRegistrationFields` (default `["@Email"]`, with `requireEmail` on).

## 4. Groups and moderation

- Operator-visible groups: you can read content (`${review}`) and moderate
  (`${mod-delete}`). Content is kept in `data/group-review.json` up to
  `reviewLogRetention` entries. Members are told this at creation.
- Encrypted groups: content is end-to-end encrypted between members (X25519 +
  AES-256-GCM). You cannot read it, cannot moderate it, and are not responsible for
  it — the product states this explicitly. The server stores only wrapped keys and
  ciphertext. `encryptedGroupsAllowed` turns this mode on/off.
- The announcement channel (pinned in every member's list) is operator-post only.

## 5. Data, backup, recovery

| File | Contents |
|---|---|
| `data/server-state.json` | accounts (PBKDF2 password hashes), friendships, groups, notifications, registrations, BOT tokens (SHA-256 digests), admin set |
| `data/group-review.json` | operator-visible group content (bounded) |
| `data/data.lock` | prevents two servers on one directory |
| `data/tls/*` | TLS identity |
| `data/logs/ourcamellia.log*` | redacted logs (no passwords/tokens/bodies) |

- Backup: stop the server and copy the data directory. Atomic writes (temp+fsync+
  rename) mean the snapshot is never half-written.
- A corrupt `server-state.json` is quarantined (`*.corrupt-<ts>`) and the server
  refuses to start rather than discard accounts — inspect the quarantined file and
  repair manually.
- Encrypted-group content in any backup is ciphertext; you cannot restore plaintext
  without member keys, and the product does not claim otherwise.
- If a user loses their secondary password (which protects only their local history,
  client-side), nothing on your server can help — say so honestly. Your server never
  sees that password.

## 6. BOT API

- In-process API: `ServerCore.openBotSession(token, x25519PrivateKey)` — BOTs act as
  their own marked accounts; the API surface contains no administrative operations.
- Optional HTTP adapter: `botApi.enabled`, default bind `127.0.0.1:54700` (plaintext
  HTTP by design — keep it on loopback; binding it elsewhere is an explicit,
  documented risk decision). Endpoints: `/v1/auth`, `/v1/send`, `/v1/group-send`,
  `/v1/friend-request`, `/v1/events` — bearer-token auth, per-token rate limits, no
  admin endpoints, 401 without a valid token.
- Tokens are shown once, stored as SHA-256 digests, revocable per BOT.

## 7. Security-relevant configuration

- `passwordHashIterations` (PBKDF2-HMAC-SHA256; default 210000 — raise toward
  600000 on capable hardware).
- `rateLimits` — login/register/connections/friend-requests/messages/group-ops per
  minute, per key.
- `notificationRetentionDays` — notification + friend-request expiry.
- `adminUsernames` — bootstrap names: the account registering such a name becomes an
  operator at (auto-)approval. Keep at least one; operators promote/demote via the
  console.
- `logLevel` — logs never contain passwords, tokens, secondary passwords, or message
  bodies by default (redaction is enforced in the formatter).
