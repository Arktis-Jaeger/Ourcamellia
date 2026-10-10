# Ourcamellia — Security, Privacy, and Trust Boundaries

## 1. Purpose

This document prevents implementation choices from accidentally contradicting the product's privacy and administration model. It is not a claim that every threat can be eliminated. The implementation must describe what it protects, what it does not protect, and who can access each category of data.

## 2. Roles and trust boundaries

### Local mode
- Each peer controls its own client and local history.
- Discoverability, inbound connectability, friendship, and active connection are independent states.
- A peer address is network metadata; a discovery response is not proof of identity.
- The implementation must document whether Local-mode friendship is cryptographically authenticated or only associated with an address/key. Do not claim strong identity assurance without a concrete mechanism.

### Server mode
- The server operator has high administrative authority.
- The server can know client source IP addresses at the transport layer, but ordinary clients must not receive other users' IP addresses.
- The server controls account creation, registration policy, server-scoped identities, groups, and notifications.
- Server operators assign administrator status.
- Each server is independent; there is no central trust authority.

### BOTs / external programs
- BOT is a visible participant type, not a privilege level.
- API credentials must be scoped, revocable, and not equivalent to server-administrator credentials.
- Do not provide an unauthenticated remote management endpoint.

## 3. Passwords and secondary password

- Login passwords must never be stored in plaintext or reversible form. Use a vetted password-hashing algorithm with per-password salt and appropriate work parameters.
- A secondary password protects designated user personal data. Do not conflate it with the login password.
- Use a vetted password-based key derivation function to derive a cryptographic key; use authenticated encryption (AEAD) for protected data.
- Use unique nonces as required by the selected AEAD construction, versioned formats, and explicit key/version metadata.
- Never log either password or derived key material.
- Forgotten-secondary-password handling follows the server's configured account/verification/recovery policy. There is no universal administrator recovery promise. The server's actual policy must be disclosed at account creation and implemented consistently.
- The Agent must document which fields are protected by the secondary password, which are available to the server at runtime, and what becomes unrecoverable if the password is lost.

## 4. Group privacy modes

Ourcamellia supports at least two explicitly different group modes.

### Operator-visible / moderated group
- The server operator may read group content and perform necessary moderation.
- The interface, group creation/join flow, and documentation must make this visible to participants.
- Persisted data should still be protected against casual disk exposure using appropriate storage protection, but storage encryption must not be misrepresented as end-to-end encryption.
- State clearly whether server-side processing sees plaintext in memory.

### Encrypted group not monitorable by the operator
- The group uses a design in which the server operator cannot read message content through ordinary server operation.
- The product must not promise moderation of content the server cannot decrypt.
- The interface and documentation must state that the operator cannot monitor the content and is not responsible for the content of such a group under the product's stated policy.
- Define key distribution, membership changes, removal, device/client changes, backup/recovery, and whether historical content is available to newly added members.
- Do not label a group “encrypted” merely because transport uses TLS or stored files are encrypted.
- The Agent must select and document a realistic cryptographic design. If a secure end-to-end group design cannot be implemented correctly in the first version using a vetted library, identify the blocker and recommend a safe alternative rather than inventing cryptography.

The two modes must be selected explicitly and their trust properties must not be conflated.

## 5. Transport and authentication

- Use authenticated transport where applicable, with clear peer/server identity validation.
- Define server identity verification and certificate/key lifecycle for Server mode.
- Avoid transmitting passwords in plaintext.
- Validate message lengths, framing, encoding, and all client-provided fields.
- Apply timeouts, resource limits, rate limits, and safe handling for malformed or hostile packets.
- Do not trust user-supplied usernames, group names, email addresses, command strings, or notification IDs.
- Define replay/retry behavior and use stable IDs or nonces where required.
- Ensure authorization is checked server-side for every protected action; client-side UI hiding is not authorization.

## 6. External verification URL interfaces

- Verification endpoints are configured by the server operator.
- Reject or constrain unsafe URL schemes, redirects, internal/private network destinations, and unexpected DNS/IP changes as appropriate to the selected HTTP client and deployment model.
- Authenticate receipts using a documented signature, shared secret, or similarly appropriate mechanism. Do not treat an unauthenticated callback as proof of approval.
- Use bounded timeouts, retry limits, idempotency, and explicit pending/approved/rejected/expired/error states.
- Do not leak passwords or secondary passwords to external verifiers. Send only configured, necessary registration fields.
- The deployer operates the external verification service; Ourcamellia provides the integration interfaces and receipt contract, not the verifier itself.

## 7. History and notifications

- Local history is private to the local installation under the limits of the user's device security.
- Automatic recording OFF means new messages are not automatically written to persistent history.
- Manual persistence must be explicit.
- History deletion must target a clearly identified scope and should require confirmation for broad/destructive scopes.
- Do not silently delete existing history when toggling recording.
- Notifications may contain sensitive information. Persist and expose only what is needed; enforce account ownership and access control.
- Avoid logging full message bodies by default.

## 8. Server operator authority and accountability

- Server operators have high authority and may moderate operator-visible groups.
- This does not mean every group is monitorable: encrypted groups explicitly exclude operator access to plaintext.
- Do not claim that an operator can recover data protected by a lost secondary password unless the configured recovery mechanism actually supports it.
- Audit security-relevant administrative actions where feasible, without recording unnecessary message content or secrets.
- Communicate the server's policies to users. A server's policy is not a global platform guarantee.

## 9. Minimum threat-model review

Before declaring the first version complete, document mitigations and residual risks for:
- malicious network peers and malformed packets;
- impersonation and spoofed discovery responses;
- brute-force login or BOT credentials;
- privilege escalation and unauthorized group/notification actions;
- leaked server backups and local history files;
- malicious or misconfigured external verifier URLs;
- replayed or forged verification receipts;
- terminal escape-sequence injection and hostile usernames/messages;
- corrupted JSON/history files;
- loss of secondary password and group encryption keys;
- server operator access in each group mode;
- resource exhaustion, spam, and repeated connection attempts.

Do not state “secure” as a substitute for describing the actual guarantees and limitations.
