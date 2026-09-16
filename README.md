# garth

Runtime-neutral client primitives for the current Arkret authority-commit
protocol.

Garth sits above `arkret-http-client` and the protocol model crates. It exposes
governance-authority operations, a durable producer-submission engine, account
aggregate delivery with a resilient run loop and a typed host projection seam,
independent commit-stream replicas, producer message authoring,
SecurityTransaction recovery coordination, MLS installation and key-backup
restore policy, session/DPoP management, Signal/WebSocket host seams, and
durable local-store interfaces.

Producer Events do not carry predecessor links. A Realm, each Circle, and each
Sidecar has its own ordered `RealmCommit` stream. Clients learn the current
governance Station from a verified authority bundle, install signed state
snapshots, and then scan a tail for every visible stream independently.

The SDK is a sibling path dependency at `../arkret-rust-sdk`. See
[Building a client on garth](docs/building-a-client.md) for host integration.
The capability-by-capability migration audit is in
[CAPABILITY-MIGRATION.md](CAPABILITY-MIGRATION.md).
