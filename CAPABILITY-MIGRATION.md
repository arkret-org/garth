# Garth capability migration

This audit records where every application-facing runtime capability lives
after the authority-commit migration, and why each removed mechanism is gone.

Every row below names the module that implements the capability and the
behavior test that proves it. A row is only marked present when the named
symbol exists in `src/` on a module path reachable from the crate root; a file
that exists on disk without a `mod` declaration reaching it is not an
implementation.

## Audit of the first migration pass

The `Migrate client runtime to authority commit streams` commit took the crate
from roughly 38,000 lines to 7,530 and the first edition of this document
claimed the removed surfaces had successors. Several of those claims named a
successor that did not exist. The corrections are:

| First-pass claim | What was actually there | Restored as |
|---|---|---|
| `src/outbound.rs`, `src/queued_record.rs` → `src/authority.rs` + `src/submission_queue.rs` | `submission_queue.rs` was a FIFO with one `submit_next`: no retry ledger, no forwarding state, no cancellation, no durable snapshot, no terminal compaction | `src/outbound.rs` — `OutboundEngine`, `SendQueue`, `SendQueueStatus`, `OutboundQueueStore` |
| `src/projection/*` → "SDK `RealmStateSnapshot` and host application projectors" | No projection seam at all: `ClientEvent`, `ClientProjector`, the full-vs-incremental Realm projection fold and the per-stream tail state had no successor | `src/projection.rs` |
| `src/orchestrator.rs`, `src/event.rs`, `src/inbound.rs` → `src/facade.rs` + `src/authority.rs` + `src/replica.rs` + `src/subscription.rs` | `facade.rs` is a 24-line holder. `TransportProvider`, `RunOptions`, `RunEvent`, `RunStopReason`, error classification, unauthorized recovery, invalid-cursor reset and `InboundDecoder` had no successor | `src/run.rs`, `src/projection.rs` |
| `src/subscribe/*`, `src/sync_client/*` → `src/subscription.rs` | `subscription.rs` runs one loop over one fixed transport and projects raw batches. There was no `SyncLoopControl`, no transport re-acquisition and no host-facing typed batch | `src/run.rs` (loop control) on top of `src/subscription.rs` (single-transport subscription) |
| `mls/backup_selection.rs`, `mls/backup_series.rs`, `mls/self_preservation.rs` → "SecurityTransaction recovery/rotation resources" | Neither backup-series chain verification nor active-series selection nor the epoch self-preservation policy existed anywhere | `src/mls/backup_series.rs`, `src/mls/backup_selection.rs`, `src/mls/self_preservation.rs` |
| `mls/welcome_admission.rs`, `mls/status.rs` → `src/mls.rs` | `src/mls.rs` had the device-secret store, the local-state store and the install queue, but no Welcome admission and no runtime status or installed-epoch read | `src/mls/welcome_admission.rs`, `src/mls/status.rs` |
| `src/signal_message_stream.rs` → `src/signal.rs` | `signal.rs` admits and decrypts Signals. The `ak.message.stream` preview projection had no successor, and `SignalPlaintext` was not even re-exported from the crate root | `src/signal_message_stream.rs`, plus the `signal_plaintext` re-exports in `src/lib.rs` |
| `src/message_authoring.rs` → "Rewritten `src/message_authoring.rs`" | The rewrite kept authoring and dropped the typed failure taxonomy that tells an interface *why* a send did not land. `MessageAuthoringFailure` had 32 call sites downstream and no successor | `src/message_authoring.rs` — `MessageAuthoringFailure`, `MessageAuthoringRecovery`, `classify_message_authoring_error`, `classify_authority_rejection` |
| `src/store/inbox.rs` → `src/store.rs` | The durable inbox came back with a free-text `last_error` but no `DeliveryErrorClass`, so a worker could no longer tell a retryable transport fault from a store failure, and the error-size ceiling was an unexported literal | `src/store.rs` — `DeliveryErrorClass`, `MAX_DELIVERY_ERROR_BYTES` |
| `src/session/engine.rs`, `src/session/provider.rs`, `src/session/store.rs` → simplified replacements | The replacement dropped refresh-successor binding checks, forced refresh, concurrent single-flight, refresh cooldown, transport caching, durable restore and invalidation. This made the types compile while removing the Session/DPoP runtime behavior Inkson depends on. | Restored the protocol-independent session runtime in the same modules and adapted it to the current SDK-owned types. |

The rows the first pass got right — `message_authoring`, `security_transaction`,
the store layer, `service_route*`, `websocket/*`, `stamp/*`,
`account_handoff`, `actor_profile_directory`, `direct_conversation`,
`runtime_journey`, and the MLS device-secret and local-checkpoint stores — are
unchanged and are listed in the capability table below.

## Capability → implementation → behavioral evidence

| Capability | Implementation | Behavioral evidence |
|---|---|---|
| Governance-authority submit, per-stream scan, committed resolve, current authority bundle and planned handoff | `src/authority.rs` — `AuthorityClient`, `AuthorityTransport` | every response is validated against its own request before it is returned; a handoff response that changed the installed handoff is refused |
| Independent Realm, Circle and Sidecar replicas over signed snapshots and separately verified tails | `src/replica.rs` — `RealmReplica`, `StreamReplica` | a tail that does not resume exactly after the installed head is refused; a snapshot without sorted independent stream heads is refused |
| Host-facing projection of committed deltas with no Realm-wide order | `src/projection.rs` — `ClientEvent`, `ClientProjector`, `CommittedDelta`, `RealmProjectionState` | `independent_streams_advance_without_a_shared_position`, `a_gap_on_one_stream_is_refused`, `a_commit_that_does_not_bind_its_event_is_refused` |
| Realm product projection fold, full replacement versus incremental overlay | `src/projection.rs` — `RealmProjectionFrame`, `reconcile_realm_projection` | `an_incremental_projection_frame_retains_omitted_state`, `a_full_projection_frame_replaces_cached_state` |
| Typed message decoding of the inbound message family | `src/projection.rs` — `InboundDecoder`, `DecodedMessage`, `DecodedInbound` | `decoder_parses_a_message_payload` |
| Aggregate frame fan-out into one ordered host batch | `src/projection.rs` — `account_frame_to_client_events`, `account_batch_to_client_events` | `an_account_frame_emits_context_then_per_stream_deltas` |
| Account aggregate subscription with durable cursor checkpointing, projection-before-checkpoint ordering, reconnect reset/resume and explicit cancellation | `src/subscription.rs` — `AccountSubscription`, `SubscriptionControl` | `cancellation_before_start_performs_no_network_call`, `reset_reconnect_clears_the_durable_cursor`, `reconnect_cursor_is_checkpointed_before_retry`, `failed_projection_never_advances_the_cursor` |
| Sync loop control: transport re-acquisition, spec backoff, lifecycle guard, observation and explicit cancellation | `src/run.rs` — `AccountRunner`, `TransportProvider`, `RunOptions`, `RunEvent`, `SyncLoopControl` | `cancellation_before_connect_performs_no_network_call`, `a_projected_batch_is_checkpointed_before_the_loop_continues`, `a_failing_projector_never_advances_the_cursor` |
| Unauthorized recovery and cursor reset inside the run loop | `src/run.rs` — `RunStopReason`, `RunErrorClass`, `classify_error` | `an_unrecoverable_authorization_failure_stops_the_loop`, `an_expired_cursor_resets_and_resumes_from_catchup` |
| Producer message authoring: content-bound `AuthoredEvent`, one local producer proof, `EventCommitSubmission` | `src/message_authoring.rs` | `authoring_attaches_one_producer_proof_and_freezes_submission`, `authoring_rejects_non_message_events_before_signing`, `queued_message_preserves_exact_canonical_event_bytes` |
| Durable producer-submission engine exposing queued / forwarding / committed / rejected | `src/outbound.rs` — `OutboundEngine`, `SendQueueStatus`, `OutboundEngineOutcome` | `an_accepted_submission_becomes_committed_with_its_commit`, `a_refused_submission_keeps_its_reason_code`, `a_transport_fault_requeues_the_same_item_with_a_delay`, `a_rejected_request_shape_fails_without_retrying` |
| Outbound withdrawal, duplicate refusal, terminal compaction and durable snapshot round trip | `src/outbound.rs` — `SendQueue`, `SendQueueSnapshot` | `an_in_flight_item_cannot_be_cancelled`, `a_queued_item_can_be_withdrawn_before_it_is_forwarded`, `the_same_event_is_never_queued_twice`, `terminal_items_are_compacted_only_after_the_cutoff`, `the_queue_snapshot_round_trips_through_serialization` |
| SecurityTransaction create/get/continue, byte-identical continuation replay, opaque staged-secret reference and terminal secret erasure | `src/security_transaction.rs` | same-stream adjacency, gap, cross-Realm and wrong-stream refusal tests |
| PCR recovery completion binding as two consecutive `CommittedEventRef` values in one PCR Realm stream | `src/security_transaction.rs` — `validate_recovery_commit_boundary` | recovery completion boundary tests |
| Session-grant issue/refresh, DPoP helpers, authenticated transport provider and secure grant persistence | `src/session/*` | 27 session tests cover login validation, refresh successor binding, DPoP continuity, single-flight refresh, cancellation recovery, cooldown, forced refresh, cache invalidation and secure persistence |
| Secure-key-store host seam and SDK key-store adapters | `src/store/keystore.rs` | key-store adapter tests, `tests/file_store_noop.rs` |
| Durable cursor and committed-Event cache, bounded dedupe, generic durable inbox, native file-backed state | `src/store.rs`, `src/store/seen_window.rs` | `memory_store_round_trips_opaque_cursor`, `memory_event_cache_is_idempotent`, `durable_inbox_retries_then_acknowledges_one_delivery`, `durable_inbox_missing_delivery_mutations_are_noops` |
| Durable submission queue seam used by the worker | `src/submission_queue.rs` | `memory_queue_preserves_fifo_submission_order`, `replacing_an_empty_queue_fails_closed` |
| Signal structural admission, delivered sender-key verification, host decryption, payload binding, sequence high-water and cursorless stream driving | `src/signal.rs` — `SignalReceiver` | heartbeat, drain/reconnect, unauthorized and clean-end tests |
| Typed authoring failure taxonomy and its recovery class | `src/message_authoring.rs` — `MessageAuthoringFailure`, `MessageAuthoringRecovery` | `a_stale_governance_binding_asks_for_re_encryption`, `a_transport_fault_leaves_the_commit_outcome_unknown`, `an_unavailable_dependency_is_retryable_but_a_refusal_is_not`, `a_plaintext_refusal_never_becomes_a_retry` |
| Transient `ak.message.stream` preview projection on the Signal rail | `src/signal_message_stream.rs` — `MessageStreamProjection` | `a_delta_before_any_keyframe_is_ignored`, `a_keyframe_then_contiguous_deltas_build_one_preview`, `a_delta_that_skips_a_sequence_is_ignored_rather_than_applied`, `a_second_stream_id_for_one_message_identity_forks_the_preview`, `an_abort_terminates_the_attempt`, `a_refused_authorization_fails_closed`, `a_stale_preview_is_marked_then_expired` |
| Raw WebSocket host seam, fresh-grant/fresh-proof connector boundary and advertised binding selection | `src/websocket/socket.rs`, `src/websocket/mod.rs` | raw inbound classification, typed close forwarding and fresh proof-input separation tests |
| Authenticated service-route resolution, DID-current-document refresh, describe binding validation and durable cache | `src/service_route.rs`, `src/service_route_material.rs` | endpoint refresh, ambiguity rejection and cache expiry tests |
| Direct Conversation current-resolution action mapping | `src/direct_conversation.rs` | module-local behavior tests |
| Account handoff and identity-creation orchestration over the current two-Event creation carrier | `src/account_handoff.rs` | module-local behavior tests |
| Actor-profile resolution cache and Agent participation admission gates | `src/actor_profile_directory.rs`, `src/runtime_journey.rs` | module-local behavior tests |
| Durable HLC allocation for producer signing | `src/stamp/mod.rs` | monotonic allocation and durable floor tests |
| MLS device secrets and provider-opaque local checkpoints | `src/mls.rs` — `MlsDeviceSecretStore`, `SecureMlsLocalStateStore` | `secure_local_checkpoint_round_trips_provider_state`, `device_secret_round_trips_and_removes` |
| Accepted Welcome/Commit installation, dequeued only after provider install and durable checkpoint save | `src/mls.rs` — `MlsInstallQueue` | `failed_welcome_install_remains_queued`, `welcome_dequeues_only_after_checkpoint_is_saved`, `older_installed_epoch_does_not_consume_queue_entry` |
| Welcome delivery admission for one local endpoint | `src/mls/welcome_admission.rs` — `admit_welcome`, `LocalMlsEndpoint` | `a_welcome_for_another_device_is_refused`, `a_welcome_that_does_not_bind_the_accepted_commit_is_refused`, `a_welcome_outside_its_realm_scope_is_refused`, `the_welcome_id_is_the_deduplication_key` |
| MLS runtime status and the installed-epoch read | `src/mls/status.rs` — `MlsRuntimeStatus`, `InstalledMlsEpoch` | `an_undelivered_answer_never_masquerades_as_no_genesis`, `a_missing_device_secret_is_reported_as_its_own_status`, `a_pending_encryption_transition_never_reads_as_ready` |
| KeyPackage inventory maintenance bound to one endpoint | `src/mls/key_package.rs` — `MlsKeyPackageInventoryStore`, `key_package_deficit` | `an_inventory_round_trips_through_the_secure_store`, `an_inventory_for_another_endpoint_is_never_stored`, `a_foreign_stored_inventory_is_refused_on_load`, `expired_and_consumed_packages_do_not_count_toward_the_low_water_mark` |
| Key-backup series chain verification back to genesis | `src/mls/backup_series.rs` — `verify_series_chain` | `a_complete_chain_verifies_back_to_genesis`, `a_withheld_intermediate_envelope_fails_closed`, `a_forged_supersedes_digest_fails_closed`, `a_mislinked_predecessor_fails_closed`, `a_duplicate_sequence_number_fails_closed` |
| Active-series backup selection and recovery-path prompting | `src/mls/backup_selection.rs` | `an_absent_active_series_pointer_selects_nothing`, `a_backup_outside_the_active_series_is_never_selected`, `the_passphrase_and_recovery_key_envelopes_are_selected_separately`, `a_recovery_prompt_needs_an_authoritative_negative_answer` |
| MLS epoch self-preservation policy | `src/mls/self_preservation.rs` — `should_force_epoch_advance` | `a_pending_commit_suppresses_a_new_self_preservation_commit`, `clock_skew_never_reads_as_overdue`, `the_message_count_trigger_is_independent_of_epoch_age`, `a_jitter_slot_opens_within_the_full_window` |
| A compiling network-free `examples/minimal-client.rs` | `examples/minimal-client.rs` | `cargo check --example minimal-client --all-features` |

## Removed machinery, with the reason for each removal

Each entry names the deleted file and why the current protocol has no place for
it. None of these has a successor, and none is needed to author a producer
Event, submit it to the current governance Station, verify its `RealmCommit`,
install MLS state, resume account delivery, receive Signals, maintain a session
or persist local runtime state.

| Deleted | Reason |
|---|---|
| `src/projection/seal_view.rs` | A Seal frontier was the client's view of a confirmation lineage. Seals are deleted; finality is the Station's `RealmCommit` chain per stream. |
| `src/projection/security_state.rs` | Read `encryption_profile`, `policy_root` and installed Cell values off a projection. Protocol-level Cells, create-locked encryption profiles and encryption floors are deleted. |
| `src/projection/mls_epoch.rs` | Read the MLS epoch out of a `sequenced_state` register Cell addressed by a composite subject. Both the state model and the Cell are deleted; the installed epoch is now a local provider read (`src/mls/status.rs`). |
| `src/projection/current_results.rs` | Planned installation of client-computed coverage records and timeline windows. A second, client-computed acceptance layer over the Station's own commits is exactly what the authority-commit model removes. |
| `src/projection/sidecar_exchange.rs` | Folded a client-computed exchange frontier and a folded-frontier digest from Events. Generic frontiers and the `AgentSidecarExchangeProjection` model are both deleted. |
| `src/projection/sidecar.rs` | The Sidecar view-state registry folded by LWW stamp and merged Sidecar timelines into one ordering. Client-authored ordering members are deleted; each Sidecar is its own commit stream. |
| `src/projection/realm_merge.rs` | The projection fold itself is a live capability and was restored into `src/projection.rs`; only its retention of the create-locked security classification was dropped, because that classification no longer exists. |
| `src/mls/commit_preconditions.rs` | Built `head_eq` preconditions against the MLS epoch Cell and the key-schedule Cell. Preconditions over protocol-level Cells are deleted. |
| `src/history_runtime.rs`, `src/history_outbox.rs`, `src/history_candidates.rs` | The historical key request/response protocol (RHRK) and its source outbox and candidate ledger. That whole exchange is deleted; a joining client reads the current signed snapshot plus each permitted stream tail instead. |
| `src/crypto_state_store.rs` | Carried `MlsWelcomePayload`-shaped accepted-artifact state. A Welcome is no longer an Event; the install path is `MlsInstallQueue` over `MlsWelcomeDelivery` and provider envelopes. |
| `src/mls/welcome_admission.rs` (previous form) | Admitted `ak.mls.welcome` **Events** and merged them into a device-message body. The Event kind is deleted. The endpoint-addressing capability was restored against `MlsWelcomeDelivery`. |
| `src/outbound.rs` (previous form) | Carried a producer predecessor graph and sibling reconciliation for the queued records. Producer Events carry no predecessor, so the queue is a plain retry ledger. |
| `src/queued_record.rs` | Modelled proposal acknowledgement state, local participant-set completion and client-authored ordering members. All three are deleted. |
| `src/subscribe/realm.rs`, `src/subscribe/scan.rs` | Drove one Realm-wide cursor that merged every scope's Events into one sequence. A Realm, each Circle and each Sidecar now advance independently; per-stream progress is `StreamScanRequest` plus `RealmReplica`. |
| `src/sync_client/account_projection.rs`, `src/sync_client/processor.rs` | Folded frames into `SyncUpdates`, a type built around the merged Realm-wide sequence. Deleted with that sequence. |
| `src/protocol.rs`, `src/event.rs` (partially) | A crate-local re-export facade over SDK types. Protocol types are defined only in the SDK and are re-exported directly from `src/lib.rs`. |
| `src/signal.rs`'s `SignalSenderKeyResolver` / `VerifiedSignalSenderKey` | The client no longer resolves a sender's signing key from a local device directory. `SignalStreamFrame::Signal` now delivers a `SignalDeliveryAuthority` with every envelope, and the SDK checks that it binds the exact sender before the client verifies the proof. The resolution seam is a protocol change, not a lost capability. |
| `direct_conversation_founding_action` and its founding-unit carrier | The closed four-Event founding carrier is gone from the SDK. Creation is authored from `DirectConversationAction::SubmitCreation` and submitted through the governance authority like any other producer Event. |
| `src/projection/security_state.rs`'s encryption reads | Whether a scope is encrypted is no longer a projection flag. It is `InstalledMlsEpoch`: installed at an epoch, an authoritative "no accepted genesis" (still plaintext), or not delivered yet. |

## Downstream call-point coverage

`inkson` is the primary consumer and still compiles against the pre-migration
surface, so its call sites are the sharpest test of what was actually lost. Of
its 171 distinct `garth::` head symbols, 98 resolve against the crate as it
stands. The 73 that do not fall into exactly the categories the removal table
above accounts for:

- the historical key exchange family (`HistoryRuntime*`, `HistorySource*`,
  `HistoryCandidate*`, `StagedHistoryCandidate`, `QueuedMlsHistorySecret`);
- the encryption-profile and Cell projection reads
  (`realm_projection_is_encrypted`, `encryption_profile_is_encrypted`,
  `security_projection_for_scope_id`, `installed_cell_value`,
  `realm_authority_root_*`, `LocalSealView`);
- the client-computed coverage planner (`CurrentRealmProgress`,
  `plan_current_install`, `plan_current_entry`);
- the previous queued-record vocabulary (`QueuedRecord`, `QueuedSdkEvent`,
  `AuthoringGeneration`, `AuthoringAuthorityModel`,
  `ScheduledSendSubmissionState`), superseded by `QueuedSubmission` and
  `SendQueueItem`;
- the Realm-wide-cursor sync client (`SubscriptionEngine`, `sync_client`,
  `subscribe`, `EventsScanTransport`, `AccountFrameTransport`,
  `account_updates_to_events`), superseded by `AccountRunner`,
  `AuthorityClient::scan` and `account_batch_to_client_events`;
- the Welcome-as-Event MLS artifact machinery (`AcceptedMlsArtifact*`,
  `QueuedMlsWelcomes`, `QueuedMlsLocalCheckpoint`), superseded by
  `MlsInstallQueue`, `QueuedMlsInstall` and `admit_welcome`;
- the client-side Signal sender-key resolver, superseded by the
  Station-delivered `SignalDeliveryAuthority`;
- two constants that are now SDK enum accessors
  (`SIGNAL_PLAINTEXT_KIND_PRESENCE`, `SIGNAL_PLAINTEXT_KIND_CALL` become
  `SignalPlaintextKind::Presence.as_str()` and
  `SignalPlaintextKind::CallSignal.as_str()`).

None of these needs a garth change. Each one is a downstream migration.

## Self-check

Two checks are run against this document rather than trusted from it.

- Module reachability: every `.rs` file under `src/` must be reachable from the
  crate root along `mod` declarations, including `#[path]` ones. A file that
  compiles nowhere implements nothing, and a green `cargo check` does not
  detect it, because an unreachable file is never compiled.
- Forbidden-term scan: `Seal`, `Cell`, `CBS`, `ControlProposal`, `Bottom`,
  `frontier`, `lattice`, `sequenced_state`, `or_set`, `causal_register`,
  `authority_revision`, `RHRK`, `history_secret`, `exporter`, `policy_root`,
  `encryption_floor`, `encryption_profile`, `Welcome Event`, `Retired`,
  `Legacy` and `Deprecated` must not appear in the crate. `hpke_seal`,
  `OnceCell`/`RefCell` and the RFC 9420 MLS exporter are the ordinary-English
  and standards exceptions.
