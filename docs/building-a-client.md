# Building a client on garth

garth is the runtime-neutral engine that Cokret clients (`inkson`, `savfox`, a
future `applet`) build on. It owns the whole runtime loop — refresh, event
polling, cursor checkpointing, dedupe, drop/resync recovery, backoff,
cancellation. A client provides only two things:

1. **Storage** — implement the store traits, or use a default.
2. **A projector** — one async hook that turns engine output into your durable
   client state.

Then call one facade method. You should not hand-roll a poll loop, a
refresh↔subscribe coordinator, or cursor/dedupe/backoff mechanics; those are
garth's job (decision 0006).

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
    ) -> impl std::future::Future<Output = cokret_core::Result<()>> + '_ {
        async move {
            for event in batch {
                match event {
                    ClientEvent::AccountUpdates(updates) => { /* to-device, presence, ack token, ... */ }
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
use garth::{CokretClient, RunOptions, SyncLoopControl, TransportProvider};

// A provider yields a ready-to-use SDK http-client with current credentials.
// Refreshing credentials inside `provide` makes the loop recover across
// restarts (the runner re-provides on the next start).
struct MyTransport { /* base url + session */ }
impl TransportProvider for MyTransport {
    type Transport = cokret::Client;
    fn provide(&self) -> impl std::future::Future<Output = cokret_core::Result<Self::Transport>> + '_ {
        async move { /* build/refresh -> Client */ }
    }
}

let client = CokretClient::new(executor, cursor_store, event_cache_store);
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
- `RunStopReason::Unauthorized { reason }` — the grant is no longer accepted. Refresh
  (or require sign-in) and re-invoke; because the transport is re-acquired
  through your `TransportProvider` on each start, a provider that refreshes on
  `provide` recovers transparently. garth owns *when* to re-provide; your
  provider owns *how* to refresh SDK auth.

Session grant refresh is intentionally outside `CokretClient`: construct
`garth::SessionEngine::new(http)` beside the transport/session state that owns
credentials. Likewise, keep your `SecureKeyStore` in host state or in a crypto
store adapter; the runtime facade does not hold secrets that its loops do not
consume.

## What garth does for you (don't re-implement)

- Long-poll / subscribe loop and retry/backpressure.
- Durable cursor checkpointing — **after** your projector persists.
- Event dedupe via `EventCacheStore`.
- Realm drop → `ck.self.events.query.scan` catch-up → `Backfill` projection.
- Resync (clear cursor + rebuild) and reconnect backoff.
- Cancellation via `SyncLoopControl`.

## Engine-level API

`CokretClient::run_*` is the preferred host entry point. Lower-level
`SubscriptionEngine` and `RealmEventsDriver` methods also take
`ClientProjector`, so account and realm frames share the same
project-then-checkpoint contract at every layer.
