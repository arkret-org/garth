# Secure Store Method Map

This note records the A4a comparison for the shared client runtime
keystore boundary.

## Method Comparison

| Contract | Methods | Semantics |
| --- | --- | --- |
| client `SecureKeyStore` | `store_secret_bytes`, `store_secret_bytes_durable`, `put_secret`, `get_secret_bytes`, `delete_secret`, `list_secret_keys`, `backend_info` | Runtime-neutral secure secret KV. Values are opaque bytes and are returned as zeroizing buffers. Missing values are `Ok(None)`. Delete is idempotent. Durable writes are available for secrets that must be committed before publishing dependent protocol state. |
| yougen `SecureKeyStore` | `store_secret`, `store_secret_durable`, `get_secret`, `delete_secret`, `backend_name` | String keyed/value secure KV. The wasm IndexedDB backend relies on the durable write method for MLS KeyPackage init material. |
| SDK `KeyStore` | `load`, `store`, `list`, `delete` | Raw key-byte storage for signer/HSM integrations. Missing keys are errors, `load` returns zeroizing bytes, `list` is sorted, and delete is idempotent. |
| SDK `CryptoStore` | MLS group state, KeyPackage, Welcome, Commit, epoch secret, verification, recovery planning, backup import/export methods | Typed MLS domain store. It enforces rollback protection, conflict checks, recovery planning and backup-envelope validation. It is not a plain KV store. |

## Boundary Decision

`SecureKeyStore` is the shared low-level secure secret KV for client-core
and host adapters. It intentionally keeps binary values, key listing and
durable write semantics so it can adapt to SDK `KeyStore` without losing
zeroizing key material or list/delete behavior.

`CryptoStore` must remain a typed facade. `SecureCryptoStoreAdapter` keeps
SDK `MemoryCryptoStore` semantics in front and persists/imports its typed
backup envelope through `SecureKeyStore`; MLS-specific invariants stay in the
`CryptoStore` implementation instead of being flattened into ad hoc KV rows.

## Adapters

`SdkKeyStoreAdapter<S: SecureKeyStore>` implements SDK `KeyStore` on top of
the shared secure store.

`SdkKeyStoreSecureAdapter<K: KeyStore>` exposes an existing SDK `KeyStore`
as a `SecureKeyStore` for tests and transitional hosts.

`SecureCryptoStoreAdapter<S: SecureKeyStore>` exposes SDK `CryptoStore`
semantics while committing the typed backup JSON to the shared secure store.
