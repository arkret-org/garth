# Garth capability migration

This audit records where every application-facing runtime capability lives
after the authority-commit migration. Removal is limited to client-side
consistency machinery that has no role in the current protocol.

## Capability checklist

- [x] Governance-authority submit, resolve, per-stream scan, current authority
  bundle resolution and authority handoff.
- [x] Independent Realm, Circle and Sidecar replicas with signed snapshots and
  a separately verified tail for each visible stream.
- [x] Account aggregate subscription with durable cursor checkpointing,
  projection-before-checkpoint ordering, reconnect reset/resume and explicit
  cancellation.
- [x] Producer message authoring: content-bound `AuthoredEvent`, local producer
  proof, `EventCommitSubmission`, durable queued request and authority outcome.
- [x] SecurityTransaction create/get/continue, byte-identical continuation
  replay, opaque staged-secret reference and terminal secret erasure.
- [x] PCR recovery completion binding: re-anchor and replacement-device
  authorization are distinct, consecutive `CommittedEventRef` values in the
  same PCR Realm stream.
- [x] Session-grant issue/refresh, DPoP helpers, authenticated transport
  provider and secure grant persistence.
- [x] Secure-key-store host seam and SDK key-store adapters.
- [x] Durable cursor/Event cache, bounded dedupe, generic durable inbox and
  native file-backed non-secret state with idempotent writes.
- [x] Durable producer-submission queue using queued-to-committed authority
  outcomes.
- [x] Signal structural admission, Station-delivered sender-key verification,
  host decryption, payload binding, sequence high-water enforcement and
  cursorless stream driving.
- [x] Raw WebSocket host seam, fresh-grant/fresh-proof connector boundary and
  advertised binding selection. The current SDK owns the registered close
  codes; it does not publish an additional application-frame state machine.
- [x] Direct Conversation current-resolution action mapping.
- [x] Account handoff and identity-creation orchestration using the current
  two-Event creation carrier.
- [x] Actor-profile resolution cache and Agent participation admission gates.
- [x] Durable HLC allocation for producer signing.
- [x] MLS device secrets, provider-opaque local checkpoints and accepted
  Welcome/Commit installation. Queue removal happens only after provider
  install and durable checkpoint save.
- [x] A compiling network-free `examples/minimal-client.rs` that constructs the
  HTTP transport, facade, store and Realm replica.

## Previous product path to current owner

| Previous path or surface | Current owner | Behavioral evidence |
|---|---|---|
| `examples/minimal-client.rs` | Rewritten example using `ArkretClient`, `MemoryStore` and `RealmReplica` | `cargo check --example minimal-client --all-features` |
| `src/message_authoring.rs` | Rewritten `src/message_authoring.rs` plus `src/authority.rs` and `src/submission_queue.rs` | producer proof, wrong-kind refusal and canonical-byte preservation tests |
| `src/security_transaction.rs` | Rewritten `src/security_transaction.rs` and current `arkret-models-crypto` DTOs | same-stream adjacency, gap, cross-Realm and wrong-stream refusal tests |
| `src/crypto_state_store.rs`, `src/mls/device_secret.rs`, `src/mls/local_checkpoint.rs`, `src/mls/welcome_admission.rs`, `src/mls/status.rs` | `src/mls.rs` secure device-secret store, secure local-state store and accepted-coordinate install queue | device secret round trip/removal, checkpoint round trip/removal, failed Welcome retention, saved-before-dequeue and epoch rollback tests |
| `src/mls/backup_selection.rs`, `src/mls/backup_series.rs`, `src/mls/self_preservation.rs` | Current SecurityTransaction recovery/rotation resources plus host secure stores | canonical continuation persistence and PCR completion coordinate validation |
| `src/outbound.rs`, `src/queued_record.rs` | `src/authority.rs` and `src/submission_queue.rs` | queued request state is serialized and only a validated authority outcome changes it |
| `src/store/file.rs`, `src/store/memory.rs`, `src/store/inbox.rs`, `src/store/mod.rs` | `src/store.rs`, `src/store/keystore.rs`, `src/store/seen_window.rs` | cursor round trip, file reopen, duplicate Event and repeated clear idempotency tests |
| `src/subscribe/*`, `src/sync_client/*` | `src/subscription.rs`, `src/account_sync.rs`, `src/store.rs` | cancel-before-connect, reconnect reset/resume, projection-before-checkpoint and projection-failure tests |
| `src/signal_message_stream.rs` and the previous Signal driver | `src/signal.rs` | heartbeat, drain/reconnect, unauthorized and clean-end tests; authenticated Signal admission remains in one receiver |
| `src/websocket/channels.rs`, `src/websocket/connection.rs`, `src/websocket/shared.rs`, previous WebSocket tests | `src/websocket/socket.rs`, `src/websocket/mod.rs` and SDK discovery helpers | raw inbound classification, typed close forwarding and fresh proof-input separation tests |
| `src/orchestrator.rs`, `src/event.rs`, `src/inbound.rs` | `src/facade.rs`, `src/authority.rs`, `src/replica.rs`, `src/subscription.rs` | transport validation, exact committed references, per-stream replica checks and subscription tests |
| `src/service_route.rs`, `src/service_route_material.rs` | `arkret-models-discovery` verified service bindings reexported by `src/websocket/mod.rs` | SDK discovery validation remains the sole routing authority |
| business-oriented files under `src/projection/` | SDK `RealmStateSnapshot`, typed current values and host application projectors | Garth validates signed snapshots and committed stream coordinates instead of owning a second domain projection |
| `src/session/*` | Rewritten/retained `src/session/*` | login, refresh decision, secure persistence, provider and no-op store tests |
| `src/account_handoff.rs`, `src/actor_profile_directory.rs`, `src/direct_conversation.rs`, `src/runtime_journey.rs` | Same paths, migrated to current DTOs | module-local behavior tests |
| `src/stamp/*` | Same path, with only producer signing-clock state | monotonic allocation and durable floor tests |

## Removed protocol-only machinery

- Multi-writer quorum computation and merge projections.
- Producer-side predecessor graphs and sibling reconciliation.
- A second acceptance layer based on client-computed coverage records.
- Client-computed convergence digests and reducer encryption profiles.
- Archived-event traversal, historical key exchange and historical outbox
  workflows replaced by current signed snapshot plus independent stream tails.
- Proposal acknowledgement state and local participant-set completion.
- One Realm-wide cursor that incorrectly merged all scope streams.
- Client-authored ordering members and response types tied to those members.

None of these removed items is required to author a producer Event, submit it
to the current governance Station, verify its `RealmCommit`, install MLS state,
resume account delivery, receive Signals, maintain a session, or persist local
runtime state.
