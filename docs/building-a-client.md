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
Validate each frame with `validate_account_frame`, project its contents, and
persist the cursor only after the projection succeeds. Timeline items retain
their own committed stream coordinates.

## 5. Persist minimal client state

Implement `CursorStore` and `EventCacheStore`, or use `MemoryStore`. Native
hosts may use `FileStore` for non-secret cursor and committed-Event metadata.
Credentials and encryption/signing keys remain in a platform secure store and
must not be written to `FileStore`.

`CursorScope::CommitStream` keeps every authority stream checkpoint separate.
`CursorScope::Account` and `CursorScope::DeviceMessages` cover aggregate and
device-message delivery.

## 6. Author messages and coordinate recovery

Finalize a content-bound `AuthoredEvent`, then call `author_message` with the
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

## 8. Run transient transports

`SignalReceiver` verifies the Station delivery authority and sender proof
before host decryption, validates the plaintext binding, and enforces sequence
high-water state. `WebSocketSocket` and `WebSocketConnector` keep platform
socket I/O and fresh DPoP signing outside the runtime-neutral core; the
selected binding and close-code vocabulary come from the SDK.

## Platform notes

- Native Rust hosts normally use `NativeExecutor` and a durable store.
- Browser hosts implement storage with IndexedDB and may use `WasmExecutor`.
- Swift and Kotlin shells should expose a small Rust-owned command facade;
  async Rust traits are not a stable foreign-language ABI.
