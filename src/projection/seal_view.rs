//! The client's local view of a Realm's accepted Seal frontier.
//!
//! Every Move a client authors names a predecessor Seal head, and every
//! governance decision is taken at a Seal basis, so the frontier plus the
//! exposed bottom cells is protocol state rather than host state: the same
//! parse has to produce the same view on every host. The type is `Default` so
//! a client that has seen no Seal yet still has a well-formed view to feed
//! into a builder.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// One competing head for a `bottom=expose` cell. Surfaced from sync so the
/// UI can render side-by-side candidates and prefill the "safer side" of a
/// conflict-repair Move.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BottomCellHead {
    /// Move (or Seal head) id that produced this candidate.
    pub move_id: String,
    /// Candidate cell value carried by that Move. `Value::Null` when soland
    /// only published the move_id without an inline value.
    #[serde(default)]
    pub value: Value,
}

/// Per-cell bottom record. `status` is the lattice `bottom=` literal (typically
/// `"expose"`) and `heads` is the competing-candidate list. `heads` may be
/// empty when soland publishes only the bottom flag without per-head values;
/// the UI then falls back to manual JSON entry on the repair dialog.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BottomCellInfo {
    #[serde(default)]
    pub status: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub heads: Vec<BottomCellHead>,
}

/// Snapshot of the latest Seal view observed for a Space. Surfaced from
/// the `/sync` Seal view (P0 M3) and threaded into Move submissions so
/// every cell-driven write references the right frontier instead of the
/// `sha256(empty)` placeholder used previously.
///
/// `frontier` lists the Seal head ids the local client currently treats
/// as the predecessor set (typically a single id but multiple while a
/// concurrent fork is unresolved). `state_root` is the post-state Merkle
/// root soland published in the most recent Seal — clients can use it
/// to detect divergence between their projection and the server view.
/// `leaves` lists the Move ids covered by the current Seal batch (the
/// "leaves of the lattice that the next Seal will close over"); UIs
/// surface this so an admin can see which pending Moves an Seal
/// rotation will sweep up.
///
/// The struct is intentionally `Default` so callers that haven't received
/// any Seal view yet (offline, fresh login) still have a clean empty
/// view to feed into builders.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalSealView {
    /// Seal head ids that the next Move treats as predecessors. Empty
    /// vec means "no Seal seen yet" — Move builders fall back to the
    /// `sha256(empty)` sentinel.
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
    /// Cell map snapshot: cell ref → bottom record (status + competing
    /// heads). Populated when the projection contains a `bottom=expose`
    /// cell so the UI can surface a "concurrent candidates unresolved"
    /// banner with side-by-side head values. Other cells are omitted to
    /// keep this struct compact.
    #[serde(default)]
    pub bottom_cells: BTreeMap<String, BottomCellInfo>,
    /// The current MLS epoch as published in the
    /// `ak.component.mls.epoch.v1` cas-register cell, when sync surfaces
    /// it. `None` means the Space hasn't published an MLS epoch yet (no
    /// E2EE group or pre-genesis state).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mls_epoch: Option<u64>,
    /// MLS key-schedule content hash (`sha256:<hex>`) from the
    /// `ak.component.key_schedule.v1` cas-register cell. The MLS commit
    /// path uses this as `prev_schedule`; the new commit computes a
    /// fresh schedule on top of it. `None` means the Space has not
    /// published a key schedule yet (no prior MLS commit observed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_schedule_hash: Option<String>,
}

impl LocalSealView {
    /// SHA-256 of empty bytes — used as the "no Seal seen yet" sentinel
    /// the Move builders historically defaulted to.
    pub const EMPTY_ANCHOR_REF: &'static str =
        "ak:seal:sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    /// Pick the single Seal ref to feed into a Move builder. Returns the
    /// first frontier head if any, otherwise the empty-bytes sentinel.
    /// When the frontier holds multiple heads (concurrent fork) this picks
    /// the lex-min head so two clients building Moves against the same
    /// view will agree on which predecessor they reference.
    pub fn move_seal_ref(&self) -> String {
        self.frontier
            .iter()
            .min()
            .cloned()
            .unwrap_or_else(|| Self::EMPTY_ANCHOR_REF.to_owned())
    }
}

impl LocalSealView {
    /// Best-effort extraction of an Seal view from a per-Realm `/sync`
    /// body. The wire shape soland is moving toward (P0 M3) is:
    ///
    /// ```jsonc
    /// {
    ///   "seal_view": {
    ///     "frontier": ["ak:seal:sha256:..."],
    ///     "leaves":   ["sha256:..."],
    ///     "state_root": "ak:state:sha256:...",
    ///     "cells": {
    ///       "ak:cell:ak.component.member.state.v1:did:web:alice": {
    ///         "bottom": "expose"
    ///       }
    ///     }
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
        let Some(seal) = seal else {
            view.ingest_structured_bottoms(body);
            return view;
        };
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
                let bottom = status.get("bottom").and_then(|v| v.as_str());
                if let Some(b) = bottom
                    && b == "expose"
                {
                    let mut heads = Vec::new();
                    if let Some(arr) = status.get("heads").and_then(|v| v.as_array()) {
                        for h in arr {
                            let move_id = h
                                .get("move_id")
                                .and_then(|v| v.as_str())
                                .map(str::to_owned)
                                .unwrap_or_default();
                            if move_id.is_empty() {
                                continue;
                            }
                            let value = h.get("value").cloned().unwrap_or(Value::Null);
                            heads.push(BottomCellHead { move_id, value });
                        }
                    }
                    view.bottom_cells.insert(
                        cell_ref.clone(),
                        BottomCellInfo {
                            status: b.to_owned(),
                            heads,
                        },
                    );
                }
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
        view.ingest_structured_bottoms(body);
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
    /// projection-only `bottoms` are refreshed in that case.
    ///
    /// A body that DOES carry `seal_view` is a full authoritative snapshot and
    /// replaces the stored view as before.
    pub fn merged_from_sync_body(&self, body: &Value) -> Self {
        if body.get("seal_view").is_some() {
            return Self::from_sync_body(body);
        }
        let mut merged = self.clone();
        // `bottom_cells` is a per-window projection: rebuild it from this body
        // instead of accumulating stale conflicts across sync windows.
        merged.bottom_cells.clear();
        merged.ingest_structured_bottoms(body);
        merged
    }

    fn ingest_structured_bottoms(&mut self, body: &Value) {
        let Some(entries) = body.get("bottoms").and_then(|v| v.as_array()) else {
            return;
        };
        for entry in entries {
            let Some(bottom) = entry.get("bottom") else {
                continue;
            };
            let cell_ref = entry.get("cell").and_then(|v| v.as_str()).or_else(|| {
                bottom
                    .get("cells")
                    .and_then(|v| v.as_array())
                    .and_then(|cells| cells.first())
                    .and_then(|v| v.as_str())
            });
            let Some(cell_ref) = cell_ref else {
                continue;
            };
            if self.bottom_cells.contains_key(cell_ref) {
                continue;
            }
            let status = entry
                .get("status")
                .and_then(|v| v.as_str())
                .unwrap_or("bottom");
            let kind = bottom.get("kind").and_then(|v| v.as_str()).unwrap_or("");
            if status != "conflict" && kind != "conflict" {
                continue;
            }
            let event_ids: Vec<String> = bottom
                .get("event_ids")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default();
            let mut heads = Vec::new();
            if let Some(arr) = bottom.get("heads").and_then(|v| v.as_array()) {
                for (idx, value) in arr.iter().enumerate() {
                    let move_id = value
                        .get("move_id")
                        .and_then(|v| v.as_str())
                        .or_else(|| value.get("event_id").and_then(|v| v.as_str()))
                        .map(str::to_owned)
                        .or_else(|| event_ids.get(idx).cloned())
                        .unwrap_or_default();
                    let candidate = value.get("value").cloned().unwrap_or_else(|| value.clone());
                    heads.push(BottomCellHead {
                        move_id,
                        value: candidate,
                    });
                }
            } else {
                heads.extend(event_ids.into_iter().map(|move_id| BottomCellHead {
                    move_id,
                    value: Value::Null,
                }));
            }
            self.bottom_cells.insert(
                cell_ref.to_owned(),
                BottomCellInfo {
                    status: status.to_owned(),
                    heads,
                },
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_view_from_sync_body_parses_full_payload() {
        let body = serde_json::json!({
            "seal_view": {
                "frontier": ["ak:seal:sha256:aaa", "ak:seal:sha256:bbb"],
                "leaves":   ["sha256:lf1"],
                "state_root": "ak:state:sha256:abc",
                "cells": {
                    "ak:cell:ak.component.member.state.v1:did:web:alice": {
                        "bottom": "expose",
                        "heads": [
                            {
                                "move_id": "ak:event:AReE983vfLAvHBb4ZLAr1_sY_ndBL3re3FkDrsyTVSpw",
                                "value": {"membership": "join"}
                            },
                            {
                                "move_id": "ak:event:AWXcctzU-Daf2jpmXX0bAgbadCowetMxC0YjP1qd5cF4",
                                "value": {"membership": "ban", "reason": "abuse"}
                            }
                        ]
                    },
                    "ak:cell:ak.component.consent.grant.v1:cnt.x":         { "bottom": "reject" }
                }
            }
        });
        let view = LocalSealView::from_sync_body(&body);
        assert_eq!(view.frontier.len(), 2);
        assert_eq!(view.leaves, vec!["sha256:lf1".to_owned()]);
        assert_eq!(view.state_root.as_deref(), Some("ak:state:sha256:abc"));
        // Only `bottom=expose` cells are surfaced — `reject` cells stay
        // out of the conflict map.
        assert_eq!(view.bottom_cells.len(), 1);
        let info = view
            .bottom_cells
            .get("ak:cell:ak.component.member.state.v1:did:web:alice")
            .expect("expose cell present");
        assert_eq!(info.status, "expose");
        assert_eq!(info.heads.len(), 2);
        assert_eq!(
            info.heads[0].move_id,
            "ak:event:AReE983vfLAvHBb4ZLAr1_sY_ndBL3re3FkDrsyTVSpw"
        );
        assert_eq!(
            info.heads[1]
                .value
                .get("membership")
                .and_then(|v| v.as_str()),
            Some("ban")
        );
    }

    #[test]
    fn seal_view_from_sync_body_parses_structured_bottoms() {
        let body = serde_json::json!({
            "bottoms": [{
                "cell": "ak:cell:ak.component.strand.position.v1:ak:space:board:ak:strand:card",
                "status": "conflict",
                "bottom": {
                    "kind": "conflict",
                    "cells": [
                        "ak:cell:ak.component.strand.position.v1:ak:space:board:ak:strand:card"
                    ],
                    "event_ids": [
                        "ak:event:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-",
                        "ak:event:AQM8rE4gp8l4axkSbbb9_dkqwWE8ZPYHwFsC24o2mrIL"
                    ],
                    "heads": [
                        {"list_space_id": "ak:space:list-a", "rank": "U"},
                        {"list_space_id": "ak:space:list-b", "rank": "U"}
                    ]
                }
            }]
        });

        let view = LocalSealView::from_sync_body(&body);
        let info = view
            .bottom_cells
            .get("ak:cell:ak.component.strand.position.v1:ak:space:board:ak:strand:card")
            .expect("structured bottom conflict surfaced");
        assert_eq!(info.status, "conflict");
        assert_eq!(info.heads.len(), 2);
        assert_eq!(
            info.heads[0].move_id,
            "ak:event:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-"
        );
        assert_eq!(
            info.heads[1]
                .value
                .get("list_space_id")
                .and_then(|v| v.as_str()),
            Some("ak:space:list-b")
        );
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
