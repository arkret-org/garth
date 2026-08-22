# Secure Store Method Map

This note records the A4a comparison for the shared client runtime
keystore boundary.

## Method Comparison

| Contract | Methods | Semantics |
| --- | --- | --- |
| client `SecureKeyStore` | `store_secret_bytes`, `store_secret_bytes_durable`, `put_secret`, `get_secret_bytes`, `delete_secret`, `list_secret_keys`, `backend_info` | Runtime-neutral secure secret KV. Values are opaque bytes and are returned as zeroizing buffers. Missing values are `Ok(None)`. Delete is idempotent. Durable writes are available for secrets that must be committed before publishing dependent protocol state. |
| inkson `SecureKeyStore` | `store_secret`, `store_secret_durable`, `get_secret`, `delete_secret`, `backend_name` | String keyed/value secure KV. The wasm IndexedDB backend relies on the durable write method for MLS KeyPackage init material. |
| SDK `KeyStore` | `load`, `store`, `list`, `delete` | Raw key-byte storage for signer/HSM integrations. Missing keys are errors, `load` returns zeroizing bytes, `list` is sorted, and delete is idempotent. |
| SDK `CryptoStore` | MLS group state, KeyPackage, Welcome, Commit, epoch secret and verification methods | Typed active-MLS domain store. It enforces rollback protection and conflict checks. It is not a portable-backup surface or a plain KV store. |

## Boundary Decision

`SecureKeyStore` is the shared low-level secure secret KV for client-core
and host adapters. It intentionally keeps binary values, key listing and
durable write semantics so it can adapt to SDK `KeyStore` without losing
zeroizing key material or list/delete behavior.

`CryptoStore` remains a typed active-state facade: MLS-specific invariants stay
in its implementation instead of being flattened into ad hoc KV rows. It has no
generic serialization/export API. Portable `mls_history` backup uses the SDK's
closed history-backup pack/restore helpers, which accept only
`LocalAuthoritativeHistorySecret` on export and restore every item as an
`external_candidate`; active MLS state, Welcome and Commit records never cross
that boundary.

## Adapters

`SdkKeyStoreAdapter<S: SecureKeyStore>` implements SDK `KeyStore` on top of
the shared secure store.

`SdkKeyStoreSecureAdapter<K: KeyStore>` exposes an existing SDK `KeyStore`
as a `SecureKeyStore` for tests and for hosts that supply only an SDK
`KeyStore`.
