# garth

Runtime-neutral shared client engine for Cokret applications.

This crate is the L2 client runtime layer above `cokret-core`,
`cokret-http-client`, and the `cokret` SDK primitives. It deliberately avoids
UI frameworks and platform keystore implementations; hosts provide those
through traits.

It depends on the Cokret SDK crates by local path
(`../cokret-rust-sdk/crates/*`) and is consumed by host clients such as
`inkson` and `savfox` via a local path dependency.
