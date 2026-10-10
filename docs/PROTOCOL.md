# Ourcamellia — Wire Protocol (v1)

Transport: TLS 1.2+ (JSSE). Framing: 4-byte big-endian length + UTF-8 JSON frame,
bounded by `maxFrameBytes` (default 1 MiB). Every frame is an envelope:

```json
{"v":1, "id":"<uuid4>", "type":"<name>", "ts":<epoch ms>, "ref":"<uuid4?>", "body":{...}}
```

- `v` must be 1; anything else is rejected (version mismatch → error + close).
- `id` is a UUIDv4 used for idempotency and reply correlation; `ref` links replies.
- `ts` must be within ±1 day of server clock.
- All fields are length/type validated on parse; hostile frames close the connection.

## Identities and authentication

- **Local mode:** both peers present self-signed certificates (mutual TLS). Identity
  = local name + certificate SHA-256 fingerprint (TOFU pinning via `PinGuard`); a
  friend appearing with a different fingerprint is refused. The first frame after a
  connection is `hello {client:<name>, version:"1"}` from each side; messages from a
  connection whose sender does not match the connection's peer name are rejected.
- **Server mode:** the server presents its certificate; clients pin the fingerprint
  on first connect and refuse changes. Login sends `{username, password}` inside the
  TLS channel; passwords are stored server-side as PBKDF2-HMAC-SHA256 hashes.
- **BOTs:** bearer token (stored as SHA-256 digest) + X25519 private key, used by the
  in-process API and the optional loopback HTTP adapter.

## Frame types

| type | direction | body |
|---|---|---|
| `hello` | c→s, p→p | `{client, version}` |
| `welcome` | s→c | `{serverName, channelId, unreadNotifications, registrationPolicy, groupPolicyNote, serverTime}` |
| `login` | c→s | `{username, password}` |
| `register` | c→s | `{username, password, ticketId, x25519PublicKey?, fields{...}}` |
| `register-result` | s→c | `{status: approved\|pending\|rejected, ticketId, message}` |
| `auth-ok` | s→c | `{username, bot, unread, displayName}` |
| `friend-request` | c→s, p→p | `{requestId, from, to}` |
| `friend-reply` | p→p | `{requestId, from, to, accept}` |
| `friend-state` | s→c, p→p | `{requestId, from, to, state: accepted\|rejected\|pending\|expired\|undeliverable}` |
| `message` | c→s, s→c, p→p | `{msgId, sender, to, text, ts}` (private; server relays, never stores) |
| `delivery` | s→c, p→p | `{msgId, to, status: delivered\|failed}` (honest: hand-off only) |
| `group-create` | c→s | `{groupId, name, privacy: operator-visible\|encrypted, members[]}` |
| `group-invite` / `group-remove` / `group-transfer` | c→s | `{groupId, member}` |
| `group-leave` / `group-members` | c→s | `{groupId}` |
| `group-update` | s→c | `{group: {id, name, privacy, owner, members[], pubKeys{}, createdAt}}` |
| `group-message` | c→s, s→c | `{msgId, groupId, sender, ts, text \| box}` — exactly one payload; `box` is base64 AES-256-GCM ciphertext (encrypted groups only) |
| `group-key-wrap` | c→s, s→c | `{groupId, forUser, box, generation, from, fromPub}` — owner distributes wrapped group keys; server stores+relays, cannot forge (sender key must match the owner's registered key) |
| `channel-message` | s→c | `{msgId, channelId, text, ts}` (announcements; operators only) |
| `mod-delete` | s→c | `{groupId, msgId, operator}` (operator-visible groups only) |
| `notify-list` | s→c | `{items: [notification]}` |
| `notify-push` | s→c | `{item: notification}` |
| `notify-action` | c→s | `{notifId, action: pass\|reject\|over}` |
| `notify-state` | s→c | `{notifId, state}` |
| `friends-list` | s→c | `{friends: [{name, status, bot}]}` — never contains IP addresses |
| `peer-state` | s→c | `{user, status: connected\|disconnected}` |
| `profile` | s→c | `{username, bot, status}` |
| `ping` / `pong` | both | `{}` — keepalive every `pingIntervalMs`, read timeout `readTimeoutMs` |
| `bye` | both | `{}` — graceful close |
| `error` | both | `{category, message}` — stable categories: usage, validation, auth, denied, not_found, conflict, network, malformed, persistence, rate_limited, internal |
| `ack` | s→c | `{status}` |

notification: `{id, kind: friend-request\|announcement\|info, state: unread\|read\|acted\|dismissed\|expired, from, text, createdAt, expiresAt, refId}`.
Notifications are persisted server-side with stable ids (deduplicated), delivered
on login (offline delivery) and pushed when online; expiry follows the configured
retention.

## Local discovery (UDP)

Separate capability from chat transport. Default port 54535/UDP.

- Query (broadcast): `{"v":1, "id":"<uuid>", "type":"discover-query"}`
- Reply (unicast, only when discoverable AND connectable):
  `{"v":1, "id":"<uuid>", "type":"discover-reply", "username", "tcpPort",
  "fp":"<cert sha256 hex>", "expiresAt"}`
- Replies feed the peer directory with a TTL; they never imply "online now"
  (observer-relative status only). Broadcast-unavailable networks simply yield no
  results; manual addresses always work.

## External registration verifier contract

When the server policy is `external`, the server POSTs JSON to the operator-configured
URL for each registration ticket:

```
POST <url>
Content-Type: application/json
X-Ourcamellia-Ticket: <ticketId>
X-Ourcamellia-Signature: hex(HMAC-SHA256(sharedSecret, body))

{"v":1, "ticketId": "<uuid>", "username": "@name", "nonce": "<hex16>", "fields": {...}}
```

The verifier replies with an authenticated receipt; an unauthenticated callback is
never accepted:

```json
{"ticketId":"<uuid>","status":"approved|rejected|pending",
 "nonce":"<echoed>","signature":"hex(HMAC-SHA256(secret, nonce + \"|\" + ticketId + \"|\" + status))",
 "message":"optional"}
```

- Idempotent per ticket; bounded timeout; up to `maxRetries`; redirects re-validated
  per hop against the SSRF policy (http/https only, non-public addresses blocked
  unless the operator explicitly allows private targets).
- Passwords and secondary passwords are never sent to the verifier — only the
  configured registration fields.

## Encrypted-group key scheme

Group key: random 256-bit. Distribution: owner wraps the key per member with
ECDH(X25519) → HKDF-SHA256(info = "ourcamellia/group/v1/<groupId>/<generation>") →
AES-256-GCM (AAD binds groupId+generation). Messages: AES-256-GCM under the group key
(AAD binds groupId). Member removal bumps the generation and requires owner rotation;
new members cannot read pre-join content; removed members can decrypt old captured
ciphertext (no post-compromise security — documented, not hidden). The server stores
and relays only wrapped keys and ciphertext.
