# Building a client on garth

garth is the runtime-neutral engine that Arkret clients (`inkson`, `savfox`, a
future `applet`) build on. It currently owns event polling, cursor
checkpointing, dedupe, drop/resync recovery, reconnect backoff and
cancellation, durable inbox delivery, session-backed authenticated transport,
and the generic outbound queue lifecycle.

A projection-driven client provides at least three integration pieces:

1. **Storage** — implement the store traits, or use a default.
2. **A projector** — one async hook that turns engine output into your durable
   client state.
3. **A transport provider** — supplies an authenticated SDK transport and owns
   the current session credentials.

Then call one facade method. You should not hand-roll a poll loop or
cursor/dedupe/reconnect mechanics; those are garth's job (decision 0006).
For grant-backed clients, compose `SessionEngine` with
`SessionTransportProvider`; the host factory supplies the platform HTTP client,
secure signer and a freshly minted refresh proof for each rotation.

## 1. Storage

Implement `CursorStore` + `EventCacheStore` (durable cursor + dedupe) and
`SecureKeyStore` (secrets), or use a default:

- Native: `garth::FileStore` (single JSON file, atomic writes) +
  `garth::MemorySecureKeyStore` (or a keyring-backed `SecureKeyStore`).
- Web: back the traits with IndexedDB (see your host's adapter).
- Tests: `garth::MemoryStore` implements both `CursorStore` and
  `EventCacheStore`.

The cursor advances only after your projector persists (see below), so your
`CursorStore` and projector state stay consistent even across a crash.

## 2. The projector

`ClientProjector` is the single seam between garth and your client state:

```rust
use garth::{ClientEvent, ClientProjector};

struct MyProjector { /* your Signals / db handle / state store */ }

impl ClientProjector for MyProjector {
    fn project(
        &self,
        batch: Vec<ClientEvent>,
    ) -> impl std::future::Future<Output = garth::Result<()>> + '_ {
        async move {
            for event in batch {
                match event {
                    ClientEvent::AccountUpdates(updates) => { /* device lists, ack token, ... */ }
                    ClientEvent::RealmDelta { realm_id, update } => { /* project realm timeline/state */ }
                    ClientEvent::Message(message) => { /* decoded chat message */ }
                    ClientEvent::Backfill { realm_id, outcome } => { /* catch-up after a drop */ }
                    ClientEvent::Event(event) => { /* generic / encrypted / unknown kind */ }
                    ClientEvent::Notification(_) | ClientEvent::ToDevice(_) => {}
                }
            }
            // Persist durably BEFORE returning Ok. Contract: the cursor is
            // checkpointed only after this returns Ok, so an error here leaves
            // the cursor untouched and the batch is redelivered next round.
            Ok(())
        }
    }
}
```

`project` is `async`, so it may do real work in the loop (key prefetch,
directory resolve, IndexedDB / Signal writes) — that is the whole reason it
is the only event projection seam.

## 3. Run it

```rust
use garth::{ArkretClient, RunOptions, SyncLoopControl, TransportProvider};

// A provider yields a ready-to-use SDK http-client with current credentials.
// Refreshing credentials inside `provide` makes the loop recover across
// restarts (the runner re-provides on the next start).
struct MyTransport { /* base url + session */ }
impl TransportProvider for MyTransport {
    type Transport = arkret_http_client::Client;
    fn provide(&self) -> impl std::future::Future<Output = garth::Result<Self::Transport>> + '_ {
        async move { /* build/refresh -> Client */ }
    }
}

let client = ArkretClient::new(executor, cursor_store, event_cache_store);
let control = SyncLoopControl::new();       // keep a clone; `control.cancel()` stops the loop
let projector = MyProjector { /* ... */ };
let provider = MyTransport { /* ... */ };

// Realm live sync (auto-resumes on StreamEnded/Dropped/ResyncRequired):
client.run_realm(&provider, realm_id, &projector, &control, RunOptions::default()).await?;

// Account sync:
client.run_account(actor_id, device_id, &provider, &projector, &control, RunOptions::default()).await?;
```

Both return `RunStopReason`:

- `RunStopReason::Cancelled` — `control.cancel()` was called.
- `RunStopReason::LifecycleEnded` — the provider's route/profile/channel guard
  became false.
- `RunStopReason::Unauthorized { reason }` — refresh was unavailable or the
  refreshed credential was still rejected.

The runtime facade does not store secrets. Compose it with
`SessionTransportProvider`, whose factory receives current grant state and
builds the authenticated SDK transport from host-owned signer/secure-store
handles.

## What garth does for you (don't re-implement)

- Long-poll / subscribe loop and retry/backpressure.
- Durable cursor checkpointing — **after** your projector persists.
- Event dedupe via `EventCacheStore`.
- Realm drop → `ak.self.events.read.scan` catch-up → `Backfill` projection.
- Resync (clear cursor + rebuild) and reconnect backoff.
- Cancellation via `SyncLoopControl`.
- Lifecycle invalidation via `TransportProvider::is_active`.
- Durable inbox delivery and persisted outbound queue state.

## Engine-level API

`ArkretClient::run_*` is the preferred host entry point. Lower-level
`SubscriptionEngine` and `RealmEventsDriver` methods also take
`ClientProjector`, so account and realm frames share the same
project-then-checkpoint contract at every layer.

## Durable workers, session transport and outbound

Agent/gateway consumers call `run_account_to_inbox` (or the realm inbox
driver). Cursor and delivery enter `DurableInboxStore` in one commit; the
worker calls `ack` only after business dispatch succeeds and persists `retry`
otherwise.

`SessionTransportProvider` performs due/401 refresh, shares the
`SessionEngine` single-flight gate and rebuilds its cached authenticated
transport when the grant rotates. `AuthenticatedTransportFactory::refresh_options`
must mint short-lived proofs at call time; never cache a signed refresh proof.
Secrets remain behind the host's `SecureKeyStore`/signer adapter.

For writes, `OutboundEngine` persists the SDK `SendQueue` state machine. Enqueue
the already stable transaction/prepared-event payload, then implement
`OutboundSubmitter`; accepted and duplicate outcomes both finalize the same
queue item, while retry deadlines survive restart. If acceptance must commit a
host-owned durable side effect, implement `OutboundPostAcceptHook` and call
`submit_next_with_hook`: Garth invokes it after accepted/duplicate but before
marking the item sent. Hook failure leaves the item retryable, so a duplicate
response after restart can idempotently finish the host commit. MLS encryption
and snapshot semantics remain host-owned; Garth owns only this ordering gate.

## Host wiring checklists

### Rust native host

1. Use `NativeExecutor` and one shared `FileStore` per account/client scope.
2. Implement a platform `SecureKeyStore` adapter backed by Keychain, Keystore,
   Credential Manager or another OS vault; never put grants or signing keys in
   `FileStore`.
3. Compose `SessionEngine` + `SessionTransportProvider` with a factory that
   rebuilds the authenticated SDK client from the current grant.
4. Provide a durable `ClientProjector` or `DurableInboxStore` worker, then run
   `ArkretClient::run_account` / `run_realm` under lifecycle control.
5. Queue ordinary writes through `OutboundEngine`; use
   `OutboundPostAcceptHook` for idempotent domain commits.

### Web host

1. Use `WasmExecutor`; implement cursor, dedupe, inbox and outbound store
   contracts with IndexedDB for production. Synchronous localStorage is not a
   secret store and is not a multi-tab transaction boundary.
2. Keep grants and signing material behind a non-extractable WebCrypto/
   IndexedDB-backed `SecureKeyStore`; never serialize them into cursor or queue
   JSON.
3. Supply a `ClientProjector` whose IndexedDB transaction commits before it
   returns `Ok`, and cancel runners when route/profile generation changes.
4. Coordinate multiple tabs with one writer/lease or transactional IndexedDB
   compare-and-swap so two queue workers cannot overwrite each other.

### Swift / Kotlin host

1. Keep Garth's async traits inside a Rust library boundary. Swift/Kotlin
   should call a C/UniFFI-style command facade and receive serialized/typed
   events; do not attempt to implement RPITIT Rust traits directly.
2. The Rust wrapper owns the executor, `ArkretClient`, session provider and
   queue workers. The platform supplies Keychain/Android Keystore callbacks,
   lifecycle commands, and projection/event callbacks.
3. Copy buffers at the FFI boundary, use opaque handles, provide explicit
   cancel/free operations, and never expose an SDK HTTP client, Rust future,
   trait object, grant JWT or private key across the boundary.
4. Until the object-safe companion facade in Phase 7.4/7.5 is implemented,
   mobile shells must provide a small Rust-owned wrapper; the RPITIT API is not
   itself claimed as a Swift/Kotlin ABI.
