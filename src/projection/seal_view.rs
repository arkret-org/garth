//! The client's local view of a Realm's accepted Seal frontier.
//!
//! Safety commands use the Realm's one confirmed head as their basis. Ordinary
//! Events may retain that last verified head in `auth_context.authority_refs`,
//! but do not need a newer Seal merely to publish. The type is `Default` so a
//! client that has not verified a head yet has an explicit empty state.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Snapshot of the latest verified Seal view observed for a Realm.
///
/// `frontier` is empty or contains the one confirmed Seal head. Competing
/// confirmation lineages are invalid safety state and are never resolved by
/// choosing a local winner. `state_root` is the post-state Merkle
/// root soland published in the most recent Seal — clients can use it
/// to detect divergence between their projection and the server view.
/// `leaves` lists the Move ids covered by the current Seal batch (the
/// "heads of the safety sequence that the next Seal will confirm"); UIs
/// surface this so an admin can see which pending Moves an Seal
/// rotation will sweep up.
///
/// The struct is intentionally `Default` so callers that haven't received
/// any Seal view yet (offline, fresh login) still have a clean empty
/// view to feed into builders.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalSealView {
    /// Empty, or the Realm's one verified confirmation head.
    #[serde(default)]
    pub frontier: Vec<String>,
    /// Move ids covered by the current Seal batch (or about to be
    /// closed by the next Seal rotation). Surfaced for admin UIs.
    #[serde(default)]
    pub leaves: Vec<String>,
    /// Post-state Merkle root from the most recent Seal. Optional —
    /// brand new spaces / offline clients may not have one yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_root: Option<String>,
    /// The current MLS epoch as published in the
    /// `ak.component.mls.epoch.v1` sequenced-state cell, when sync surfaces
    /// it. `None` means the Space hasn't published an MLS epoch yet (no
    /// E2EE group or pre-genesis state).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mls_epoch: Option<u64>,
    /// MLS key-schedule content hash (`sha256:<hex>`) from the
    /// `ak.component.key_schedule.v1` sequenced-state cell. The MLS commit
    /// path uses this as `prev_schedule`; the new commit computes a
    /// fresh schedule on top of it. `None` means the Space has not
    /// published a key schedule yet (no prior MLS commit observed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_schedule_hash: Option<String>,
}

impl LocalSealView {
    /// Return the one verified head. Empty or competing lineages return
    /// `None`; callers must not fabricate or choose a safety basis.
    pub fn confirmed_seal_ref(&self) -> Option<&str> {
        match self.frontier.as_slice() {
            [head] => Some(head),
            _ => None,
        }
    }
}

impl LocalSealView {
    /// Best-effort extraction of a Seal view from a per-Realm `/sync`
    /// body. The wire shape soland is moving toward (P0 M3) is:
    ///
    /// ```jsonc
    /// {
    ///   "seal_view": {
    ///     "frontier": ["ak:seal:sha256:..."],
    ///     "leaves":   ["sha256:..."],
    ///     "state_root": "ak:state:sha256:...",
    ///     "cells": { "...": { "value": "..." } }
    ///   }
    /// }
    /// ```
    ///
    /// Until soland publishes the full payload, missing fields default to
    /// empty / `None`. The function is total and never errors — it just
    /// degrades to `LocalSealView::default()` when fields are missing
    /// or have unexpected shapes.
    pub fn from_sync_body(body: &Value) -> Self {
        let seal = body.get("seal_view");
        let mut view = Self::default();
        let Some(seal) = seal else { return view };
        if let Some(arr) = seal.get("frontier").and_then(|v| v.as_array()) {
            view.frontier = arr
                .iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect();
        }
        if let Some(arr) = seal.get("leaves").and_then(|v| v.as_array()) {
            view.leaves = arr
                .iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect();
        }
        if let Some(s) = seal.get("state_root").and_then(|v| v.as_str()) {
            view.state_root = Some(s.to_owned());
        }
        if let Some(cells) = seal.get("cells").and_then(|v| v.as_object()) {
            for (cell_ref, status) in cells {
                // Well-known named cells surfaced for the realm_admin MLS
                // epoch widget. We accept either a raw `value` or a typed
                // `register.value` field - soland's canonical projection
                // uses the latter; tests may emit the former.
                let value_for = |status: &Value| -> Option<Value> {
                    status
                        .get("value")
                        .cloned()
                        .or_else(|| status.get("register").and_then(|r| r.get("value")).cloned())
                };
                if cell_ref.starts_with("ak:cell:ak.component.mls.epoch.v1")
                    && let Some(value) = value_for(status)
                {
                    view.mls_epoch = value
                        .as_u64()
                        .or_else(|| value.get("epoch").and_then(|v| v.as_u64()));
                }
                // B3c: surface the MLS key schedule hash so the next
                // commit's SDK MLS governance binding can carry the
                // SDK-canonical "advance schedule" effect on it.
                if cell_ref.starts_with("ak:cell:ak.component.key_schedule.v1")
                    && let Some(value) = value_for(status)
                {
                    view.key_schedule_hash = value.as_str().map(str::to_owned).or_else(|| {
                        value
                            .get("hash")
                            .and_then(|v| v.as_str())
                            .map(str::to_owned)
                    });
                }
            }
        }
        view
    }

    /// Fold a per-Realm `/sync` body into the view already stored locally.
    ///
    /// `client-sync.md` §4/§5 defines no Seal view on the Realm delta —
    /// `RealmSyncEntry` has no such field, and the one adjacent field it does
    /// define (`state_at_window_start`) is explicitly projection-only and must
    /// not be treated as an authoritative cell value. The authoritative frontier /
    /// `state_root` come from `ak.self.seals.read.frontier.v1` and from
    /// governance proof bundles that passed the `encryption-and-audit.md`
    /// §2.5.1.1 verification order.
    ///
    /// So a sync body WITHOUT `seal_view` carries no statement about the
    /// frontier at all — treating its absence as "the frontier is empty" (what
    /// [`Self::from_sync_body`] returns) overwrites the authoritative value with
    /// a sentinel and, through
    /// the host's seal-view setter, evicts every verified governance proof for
    /// the Realm. Only the
    /// A body that DOES carry `seal_view` is a full authoritative snapshot and
    /// replaces the stored view as before.
    pub fn merged_from_sync_body(&self, body: &Value) -> Self {
        if body.get("seal_view").is_some() {
            return Self::from_sync_body(body);
        }
        self.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_view_from_sync_body_parses_full_payload() {
        let body = serde_json::json!({
            "seal_view": {
                "frontier": ["ak:seal:sha256:aaa"],
                "leaves":   ["sha256:lf1"],
                "state_root": "ak:state:sha256:abc",
                "cells": {
                    "ak:cell:ak.component.mls.epoch.v1:realm": { "value": 7 }
                }
            }
        });
        let view = LocalSealView::from_sync_body(&body);
        assert_eq!(view.frontier.len(), 1);
        assert_eq!(view.leaves, vec!["sha256:lf1".to_owned()]);
        assert_eq!(view.state_root.as_deref(), Some("ak:state:sha256:abc"));
        assert_eq!(view.mls_epoch, Some(7));
        assert_eq!(view.confirmed_seal_ref(), Some("ak:seal:sha256:aaa"));
    }

    #[test]
    fn competing_confirmation_heads_are_not_selected() {
        let view = LocalSealView {
            frontier: vec!["a".to_owned(), "b".to_owned()],
            ..Default::default()
        };
        assert_eq!(view.confirmed_seal_ref(), None);
    }

    #[test]
    fn seal_view_from_sync_body_extracts_mls_epoch() {
        let body = serde_json::json!({
            "seal_view": {
                "frontier": ["ak:seal:sha256:aaa"],
                "leaves": [],
                "cells": {
                    "ak:cell:ak.component.mls.epoch.v1:ak:realm:demo": {
                        "value": 7
                    }
                }
            }
        });
        let view = LocalSealView::from_sync_body(&body);
        assert_eq!(view.mls_epoch, Some(7));
    }

    #[test]
    fn seal_view_mls_epoch_supports_object_value_with_epoch_field() {
        // Some soland builds emit the MLS epoch cell as `{ "value": { "epoch": N } }`
        // (typed view) instead of a bare integer. Both shapes need to round-trip.
        let body = serde_json::json!({
            "seal_view": {
                "frontier": [],
                "cells": {
                    "ak:cell:ak.component.mls.epoch.v1:ak:realm:demo": {
                        "value": { "epoch": 42, "members": 3 }
                    }
                }
            }
        });
        let view = LocalSealView::from_sync_body(&body);
        assert_eq!(view.mls_epoch, Some(42));
    }

    #[test]
    fn seal_view_from_sync_body_missing_returns_default() {
        let body = serde_json::json!({"summary": {"summary": "hi"}});
        let view = LocalSealView::from_sync_body(&body);
        assert_eq!(view, LocalSealView::default());
    }
}
