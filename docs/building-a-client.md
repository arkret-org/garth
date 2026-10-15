# Building a client on garth

Garth provides a deliberately small boundary around the Arkret SDK. A host
supplies an `AuthorityTransport` and storage, then owns application projection,
credentials, cryptographic key material, and platform lifecycle.

## 1. Construct the facade

`arkret_http_client::Client` already implements `AuthorityTransport`:

```rust
use garth::{ArkretClient, MemoryStore};

let client = ArkretClient::new(http_client, MemoryStore::new());
```

Alternative transports implement the same five operations: submit, scan,
resolve committed references, resolve the current authority bundle, and
install an authority handoff.

## 2. Submit through the current authority

Construct `QueuedSubmission` from an SDK `AuthoritySubmitRequest`. The
constructor validates the producer Event or MLS commit submission and records
its stable Event ID. Calling `client.authority().submit(...)` validates the
server outcome before changing the local state to `Committed` or `Rejected`.

Only a returned `RealmCommit` establishes finality. A producer Event carries
no ordering pointer of its own.

## 3. Build a Realm replica

Create `RealmReplica` with the Realm ID. Install a verified current-authority
bundle, then a signed `RealmStateSnapshot`. The snapshot supplies one visible
head per independent stream. For every Realm, Circle, or Sidecar stream, issue
a `StreamScanRequest` starting at that stream's head and pass the validated
result to `apply_scan`.

Do not merge positions across streams. Positions are meaningful only within
their `CommitStreamRef`.

## 4. Consume account aggregate delivery

The `account_sync` module reexports the current account-subscribe DTOs. Its
cursor checkpoints aggregate delivery; it does not confer stream finality.
Timeline items retain their own committed stream coordinates.

Implement `ClientProjector` and hand it to `AccountRunner::run`. The runner
re-acquires an authenticated transport through your `TransportProvider` on
every restart, fans each delivered frame into an ordered `ClientEvent` batch
with `account_frame_to_client_events`, awaits your projector, and only then
persists the cursor. A projector error stops the loop without advancing the
cursor, so the unit is redelivered.

`ClientEvent::Committed` carries a `CommittedDelta` with the exact
`CommitStreamRef` and `stream_position` the Station assigned. Index on that.
`RealmProjectionState` keeps one independent tail per visible stream and
refuses a gap on any one of them; it never builds a Realm-wide sequence.

`RunOptions` carries the reconnect cadence, `RunEvent` reports every lifecycle
transition, and `SyncLoopControl::cancel` stops the loop explicitly. An
`unauthorized` outcome is routed to `TransportProvider::recover_unauthorized`
before the loop gives up; an expired cursor clears the checkpoint and resumes
from catch-up.

## 4b. Queue producer submissions durably

`OutboundEngine` is the durable side of authoring. `enqueue` records a frozen
`QueuedSubmission`; `submit_next` claims the oldest due item, marks it
`Forwarding`, and records the authority outcome as `Committed` (with its
`RealmCommit`) or `Rejected` (with its reason code). A retryable transport
fault requeues the same frozen bytes behind a spec backoff delay; a protocol
violation fails the item instead of looping. An item that is already in flight
cannot be withdrawn, because its outcome is still authoritative.

## 5. Persist minimal client state

Implement `CursorStore` and `EventCacheStore`, or use `MemoryStore`. Native
hosts may use `FileStore` for non-secret cursor and committed-Event metadata.
Credentials and encryption/signing keys remain in a platform secure store and
must not be written to `FileStore`.

`CursorScope::CommitStream` keeps every authority stream checkpoint separate.
`CursorScope::Account` and `CursorScope::DeviceMessages` cover aggregate and
device-message delivery.

## 6. Author Events and coordinate recovery

For any finalized unsigned `AuthoredEvent`, use
`event_authoring::EventAuthoringSession::new(event).sign_with(host_signer)`.
The signer may attach a proof but cannot replace the finalized bytes or Event
identity. `event_authoring::event_submission` freezes the signed Event for the
existing durable outbound engine. Encryption, key access and product-specific
authorization remain host adapters.

For message-specific preparation, finalize a content-bound `AuthoredEvent`, then call `author_message` with the
host signer. Garth attaches the producer proof and returns the exact
`MessageSubmitRequestBody`; `queue_authored_message` freezes it for authority
submission and byte-identical retry.

`SecurityTransactionEngine` persists only canonical public requests and an
opaque reference to host-held secret material. A completed PCR recovery is
accepted only when the completion attestation names distinct consecutive
commits in the same PCR Realm stream. The engine clears staged material only
after observing a terminal authoritative resource.

## 7. Install and persist MLS state

`MlsInstallQueue` accepts a Welcome or Commit only with its full
`CommittedEventRef`. It invokes the host MLS provider, persists the returned
provider-opaque checkpoint, and only then removes the queue item. Use
`SecureMlsLocalStateStore` and `MlsDeviceSecretStore` with a platform secure
store for checkpoints and device material.

`mls::checkpoint` owns the encrypted v1 local envelope without linking an MLS
provider. The host obtains its checkpoint secret and restores the SDK provider.
`mls::checkpoint_port::install_checkpoint` stages a scope-keyed install through
`MlsCheckpointPort`, waits for its durability, then asks the staged guard to
publish. The guard must release store borrows before awaiting, fence session
replacement at publication, and keep pending consume intents out of delivery
until the checkpoint/consume tuple is durable. Cancellation retains the exact
tuple for recovery rather than erasing an already durable consume obligation.
The host may recover an unpublished checkpoint on restart. Realm and Circle keys are their canonical scope keys; Sidecar keys
also distinguish the group incarnation. No storage key or envelope version
changes when moving a host onto these ports.

A Welcome arrives as a producer-signed `MlsWelcomeDelivery` alongside its
accepted Commit, never as an Event. Pass it through `admit_welcome` with your
`LocalMlsEndpoint` and the accepted Commit Event ID before handing it to the
provider; anything addressed elsewhere or bound to another Commit fails closed.

`installed_mls_epoch` reports three distinct answers: installed at an epoch, an
authoritative "no accepted genesis" (so this scope is still plaintext), and
"not delivered yet". Never collapse the last two. `MlsRuntimeStatus` maps the
client-side failure taxonomy onto user-facing readiness.

`MlsKeyPackageInventoryStore` persists what this endpoint published and
`key_package_deficit` says how many fresh single-use packages to publish.
KeyPackages ride their own dedicated ledger, not a commit stream.

`verify_series_chain` walks a key-backup series back to genesis before a
restore trusts the tail, and `select_active_series_tail_for_recipient_method`
picks the envelope the local recovery path can actually open.
`should_force_epoch_advance` is the shared self-preservation commit policy.

## 8. Run transient transports

Session issue and refresh methods take a `HostClock`, normally `SystemClock`.
They sample it again after the Account Authority exchange before validating
and installing the returned credential. A timestamp captured before an async
request cannot validate the new grant's `not_before` or expiry. During Agent
rotation the outgoing observation is validated before the exchange, and the
successor is validated at response time; a successful exchange may outlive the
old grant. Exact outcome, holder, scope, successor and installation fences
still apply. Deterministic tests must advance their host clock across transport
completion and include genuinely future and expired response credentials.

`SignalReceiver` verifies the Station delivery authority and sender proof
before host decryption, validates the plaintext binding, and enforces sequence
high-water state. An accepted outcome carries the verified
`SignalSequenceDomain` alongside the plaintext, so downstream projections key
on the same sender/endpoint/scope the sequence was enforced against.
`MessageStreamProjection` consumes that to build transient `ak.message.stream`
previews; they are never durable and never touch a commit stream. `WebSocketSocket` and `WebSocketConnector` keep platform
socket I/O and fresh DPoP signing outside the runtime-neutral core; the
selected binding and close-code vocabulary come from the SDK.

## Platform notes

- Native Rust hosts normally use `NativeExecutor` and a durable store.
- Browser hosts implement storage with IndexedDB and may use `WasmExecutor`.
- Swift and Kotlin shells should expose a small Rust-owned command facade;
  async Rust traits are not a stable foreign-language ABI.

## 9. Consume current cuts and recover historical tails

`current_ingest` validates typed current rows and their cross-row subjects,
then decodes committed Event batches for the existing `ClientProjector` seam.
SDK models and reducers remain the protocol owners; the projector owns the
host's durable index, notification and UI state.

`history_recovery` drives bounded snapshot-anchored windows and live replay
through `OwnStationResultClient`. A limited preview never becomes a durable
historical prefix. A durable cursor is restored from its exact original,
while a current-head bootstrap establishes current state without inventing
historical rows. Hosts commit the returned admitted pages before moving cursors.

`historical_agent_keys` resolves only accepted Event coordinates through a
`HistoricalAgentKeyPort`. It keeps recipient AccountId, receiver Station,
actual Agent ActorId, signer method and historical target separate from current
key inventory. The host stores results only if the captured session is still
current. `mls::membership` reconciles typed roster hints with accepted host
facts; a roster hint does not authorize a membership-changing Commit.

Run `python scripts/check_layering.py --inkson-root ../inkson` in a sibling
workspace to check the dependency closure and concrete consumer wiring.
`tests/host_ports.rs` runs the same checkpoint and Event-signing inputs on
native and wasm; the browser host adapter is exercised by Inkson's
`wasm_host_ports` integration target with `spec-conformance` enabled.
