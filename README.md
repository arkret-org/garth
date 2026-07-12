# garth

Runtime-neutral shared client engine for Arkret applications.

This crate is the L2 client runtime layer above `arkret-core`,
`arkret-http-client`, and the `arkret` SDK primitives. It deliberately avoids
UI frameworks and platform keystore implementations; hosts provide those
through traits.

It depends on the Arkret SDK crates by local path
(`../arkret-rust-sdk/crates/*`) and is consumed by host clients such as
`inkson` and `savfox` via a local path dependency.

The public foundation includes resilient account/realm runners, typed terminal
outcomes and observer events, durable cursor/dedupe/inbox stores,
session-backed authenticated transport with single-flight refresh, and a
durable outbound queue with a pre-`Sent` post-accept ordering hook. Product
projection, signing/encryption, platform secure storage and bridge-specific
delegated delivery remain host-owned.

See [Building a client on garth](docs/building-a-client.md) for the Rust, Web,
Swift and Kotlin integration boundaries and the minimal compiled example in
`examples/minimal-client.rs`.
