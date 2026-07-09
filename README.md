# garth

Runtime-neutral shared client engine for Arkret applications.

This crate is the L2 client runtime layer above `arkret-core`,
`arkret-http-client`, and the `arkret` SDK primitives. It deliberately avoids
UI frameworks and platform keystore implementations; hosts provide those
through traits.

It depends on the Arkret SDK crates by local path
(`../arkret-rust-sdk/crates/*`) and is consumed by host clients such as
`inkson` and `savfox` via a local path dependency.
