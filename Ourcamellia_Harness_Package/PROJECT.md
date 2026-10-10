# Ourcamellia — Project Charter

## 1. Purpose

Ourcamellia is a lightweight, decentralized-by-independence chat platform. It is not a federated network: each server is an independent community with its own identity namespace, accounts, relationships, groups, policies, and data. Servers do not connect to one another and there is no central master server.

The name expresses the idea of people jointly protecting the same camellia flower.

The project is intended to support:
- a usable non-GUI product with both client and server components;
- a command-line interface that is the actual first-version user interface, not merely a debug console;
- direct Local-mode communication and Server-mode accounts and communities;
- structured commands, durable notifications, message-history controls, groups, and BOT participants;
- a stable application/core API that future GUI clients and external programs can use without depending on terminal parsing.

The first release must be a complete, tested, usable version of the agreed scope. “Implement in stages” means staged work within one delivery, not a reduced prototype or an excuse to stop after an intermediate milestone.

## 2. Core principles

1. **Independent servers, no federation.** There is no central identity provider, master server, or server-to-server federation in the agreed design.
2. **Identity namespaces are local to their mode and server.** A Local-mode username is not a Server-mode account. The same username on two independent servers represents unrelated identities.
3. **One server, one independent community.** Server accounts, friends, groups, notifications, policy, and names are scoped to that server.
4. **Technology is a mirror, not a moral agent.** The software should not assume that technology becomes inherently impure because a malicious person uses it. It should provide explicit capabilities, boundaries, and accountable administration.
5. **Least surprise.** A sent request is not proof of delivery; a network connection is not friendship; discoverability is not the same as permission to connect; a connection is not proof that a remote person is currently available to everyone.
6. **Privacy must be described honestly.** Do not promise that a recipient cannot copy, record, or screenshot content. Do not claim end-to-end encryption where the server can read message content.
7. **Management authority is explicit.** Server operators have high authority, but the software must accurately communicate the privacy and moderation model of each group.
8. **Keep the first version lightweight.** Avoid unnecessary frameworks, cloud services, central services, heavyweight infrastructure, or elaborate abstractions that do not serve a stated requirement.
9. **Cross-platform JVM application.** Prefer portable standard-JVM behavior. Where terminal capabilities, network interfaces, or OS behavior differ, provide graceful fallback and document limitations.
10. **Separate product semantics from presentation.** Business rules, command semantics, networking, persistence, and authorization must not live only inside the terminal UI.
11. **Test observable behavior.** Important protocol and security rules must have automated tests, not just comments or manual claims.
12. **No silent scope reduction.** If a requirement is infeasible, contradictory, unsafe, or materially ambiguous, document the exact issue and present a concrete recommendation. Do not quietly omit it.

## 3. First-version product boundary

The first version includes:
- a command-line client with two presentation modes;
- an independently runnable server;
- Local mode for direct peer communication and local discovery;
- Server mode for server accounts, friends, notifications, and groups;
- structured command processing and normal text messaging;
- private and group conversations;
- BOT identity and programmatic integration;
- JSON-based local conversation-history persistence and explicit persistence/deletion commands;
- configurable registration fields and server-controlled verification policy, with external verifier URL interfaces and a documented receipt contract;
- configuration, logging, error handling, tests, and operator documentation.

The first version does not require a GUI. A future GUI should be able to use the core/application API rather than reimplement business rules. Do not add server federation, a central directory, or a central account system.

## 4. Architecture direction

A single repository with clear modules is preferred unless a documented technical assessment finds a compelling reason otherwise. Candidate logical boundaries:
- shared protocol and domain types;
- client application/core;
- independently runnable server;
- CLI presentation layer;
- persistence and configuration;
- tests and test fixtures.

The exact build system, terminal library, transport details, persistence libraries, and package structure are implementation decisions. Select the smallest maintainable solution that meets the requirements; document the rationale before locking in choices.

## 5. Product vocabulary

- **Local mode:** direct communication using local identities and peer network addresses.
- **Server mode:** a client logged into one independent server community.
- **Discoverability:** whether a peer can be found through the discovery mechanism.
- **Connectability:** whether a peer accepts an inbound connection.
- **Friend:** an identity with an accepted friendship relationship.
- **Conversation/session:** a private or group communication context.
- **Recording:** automatically persisting newly received/sent conversation messages to local JSON history.
- **Buffered message:** a message held in process memory while automatic recording is disabled and not yet persisted.
- **BOT:** an account/participant explicitly marked as a bot; it can appear in friend lists and group conversations.
- **Server operator/administrator:** a role assigned by the server, with high administrative authority.
- **Group owner:** the owner of a group, whose group-level authority is second only to the server operator's applicable administrative authority.

## 6. How to treat this document

This charter defines the project's purpose and hard boundaries. Detailed feature requirements are in `REQUIREMENTS.md`; security and trust boundaries are in `SECURITY.md`; architecture obligations are in `ARCHITECTURE.md`; implementation and acceptance sequencing are in `ROADMAP.md`.

When documents appear inconsistent:
1. preserve explicit user-approved product decisions;
2. preserve security and data-integrity guarantees;
3. identify and document the conflict rather than silently choosing;
4. update the relevant documents consistently and record the rationale.
