//! Runtime projection of flat Direct Conversation Topics and Chat current.

use std::collections::BTreeMap;

use arkret_models_collaboration::objects::space::Space;
use arkret_models_collaboration::objects::strand::Strand;
use arkret_wire::{CurrentSelector, CurrentState, Hash, RealmId, SpaceId, StrandId};

/// A verified current view supplied by the caller, never a wire object.
#[derive(Clone, Debug, Default)]
pub struct DirectStructureView {
    pub chats: BTreeMap<StrandId, Strand>,
    pub spaces: BTreeMap<SpaceId, Space>,
    pub chat_state_digests: BTreeMap<StrandId, Hash>,
}

impl DirectStructureView {
    pub fn from_current(realm: &RealmId, entries: &[CurrentState]) -> Result<Self, String> {
        let mut view = Self::default();
        let mut parents = BTreeMap::new();
        for entry in entries {
            let CurrentState::Value {
                selector,
                value,
                source_stream_ref,
                ..
            } = entry;
            match selector {
                CurrentSelector::Strand { strand_id } => {
                    let strand: Strand =
                        serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
                    if strand.realm_id != *realm || strand.id.as_ref() != Some(strand_id) {
                        return Err("Strand current locator mismatch".into());
                    }
                    require_source(realm, strand.scope_circle_id.as_ref(), source_stream_ref)?;
                    if strand.scope_circle_id.is_none()
                        && arkret_models_collaboration::objects::profiles::resolve_primary_track(
                            &strand.tracks,
                            None,
                        )
                        .ok()
                        .flatten()
                        .is_some_and(|(name, _)| name == "discussion")
                    {
                        let bytes = arkret_wire::canonical::canonical_json_bytes(value)
                            .map_err(|e| e.to_string())?;
                        let digest = Hash::new(arkret_wire::canonical::sha256_digest(bytes))
                            .map_err(|e| e.to_string())?;
                        view.chat_state_digests.insert(strand_id.clone(), digest);
                        view.chats.insert(strand_id.clone(), strand);
                    }
                }
                CurrentSelector::Space { space_id } => {
                    let space: Space =
                        serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
                    if space.realm_id != *realm || space.id.as_ref() != Some(space_id) {
                        return Err("Space current locator mismatch".into());
                    }
                    require_source(realm, space.scope_circle_id.as_ref(), source_stream_ref)?;
                    if space.scope_circle_id.is_none() && space.kind == "topic" {
                        view.spaces.insert(space_id.clone(), space);
                    }
                }
                CurrentSelector::SpaceParent { space_id } => {
                    match source_stream_ref {
                        arkret_wire::CommitStreamRef::Realm { realm_id } if realm_id == realm => {}
                        arkret_wire::CommitStreamRef::Circle { realm_id, .. }
                            if realm_id == realm =>
                        {
                            continue;
                        }
                        _ => return Err("Parent current belongs to another stream".into()),
                    }
                    let parent: Option<SpaceId> = serde_json::from_value(
                        value
                            .get("parent_space_id")
                            .ok_or("incomplete parent current")?
                            .clone(),
                    )
                    .map_err(|e| e.to_string())?;
                    parents.insert(space_id.clone(), parent);
                }
                _ => {}
            }
        }
        view.spaces.retain(|id, space| {
            if let Some(None) = parents.get(id) {
                space.parent_space_id = None;
                true
            } else {
                false
            }
        });
        Ok(view)
    }

    pub fn topics(&self) -> impl Iterator<Item = (&SpaceId, &Space)> {
        self.spaces.iter()
    }
}

fn require_source(
    realm: &RealmId,
    circle: Option<&arkret_wire::CircleId>,
    source: &arkret_wire::CommitStreamRef,
) -> Result<(), String> {
    match (circle, source) {
        (None, arkret_wire::CommitStreamRef::Realm { realm_id }) if realm_id == realm => Ok(()),
        (
            Some(expected),
            arkret_wire::CommitStreamRef::Circle {
                realm_id,
                circle_id,
            },
        ) if realm_id == realm && circle_id == expected => Ok(()),
        _ => Err("Structure current source does not match its scope".into()),
    }
}

#[cfg(test)]
mod tests {
    use arkret_wire::{CommitStreamRef, CurrentRevision, RealmCommitId};
    use serde_json::json;

    use super::*;

    fn event(seed: u8) -> arkret_wire::EventId {
        arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [seed; 32])
    }

    fn current(
        realm: &RealmId,
        selector: CurrentSelector,
        value: serde_json::Value,
    ) -> CurrentState {
        CurrentState::Value {
            selector,
            value,
            source_stream_ref: CommitStreamRef::Realm {
                realm_id: realm.clone(),
            },
            revision: CurrentRevision {
                commit_id: RealmCommitId::from_digest([1; 32]),
                stream_position: 9,
            },
        }
    }

    #[test]
    fn flat_topics_use_one_strand_current_and_exact_digest_without_board() {
        let token = "ASOv-EoZPg5yuM1Pv__u1K8vD3Q9342GxwoWmkKwjqOn";
        let realm = RealmId::new(format!("ak:realm:{token}")).unwrap();
        let chat = StrandId::new(format!("ak:strand:{token}")).unwrap();
        let topic = SpaceId::new(format!("ak:space:{token}")).unwrap();
        let value = json!({"id":chat,"schema":"ak.schema.strand.v1","realm_id":realm,
            "tracks":{"discussion":{"is_primary":true,"enabled":true}}, "state":"active",
            "created_by":{"kind":"account","account_id":{"principal_id":"ak:did_core:web:alice.example","station_id":"ak:did_core:web:station.example"}},
            "created_at":"2026-10-04T00:00:00.000Z", "topic":{"space_id":topic,"rank":"a0"}});
        let rows = vec![current(
            &realm,
            CurrentSelector::Strand {
                strand_id: chat.clone(),
            },
            value.clone(),
        )];
        let view = DirectStructureView::from_current(&realm, &rows).unwrap();
        assert_eq!(view.chats[&chat].topic.as_ref().unwrap().space_id, topic);
        let expected = Hash::new(arkret_wire::canonical::sha256_digest(
            arkret_wire::canonical::canonical_json_bytes(&value).unwrap(),
        ))
        .unwrap();
        assert_eq!(view.chat_state_digests[&chat], expected);
        let mut unclassified = value;
        unclassified.as_object_mut().unwrap().remove("topic");
        let next = DirectStructureView::from_current(
            &realm,
            &[current(
                &realm,
                CurrentSelector::Strand {
                    strand_id: chat.clone(),
                },
                unclassified,
            )],
        )
        .unwrap();
        assert!(next.chats[&chat].topic.is_none());
        assert_ne!(next.chat_state_digests[&chat], expected);
        let foreign =
            RealmId::new("ak:realm:AWgGCEbMHnelRQfzqg1C_onV9Ej_FdpdAZyM_JoFgAd3").unwrap();
        assert!(DirectStructureView::from_current(&foreign, &rows).is_err());
    }

    #[test]
    fn topic_navigation_excludes_list_and_board_spaces() {
        let realm = RealmId::from_event_id(&event(7));
        let actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        ));
        let mut rows = Vec::new();
        for (index, kind) in ["topic", "list", "board"].into_iter().enumerate() {
            let space_id = SpaceId::from_event_id(&event(index as u8));
            let space = Space::new(
                space_id.clone(),
                realm.clone(),
                kind,
                "Title",
                actor.clone(),
            );
            rows.push(current(
                &realm,
                CurrentSelector::Space {
                    space_id: space_id.clone(),
                },
                serde_json::to_value(space).unwrap(),
            ));
            rows.push(current(
                &realm,
                CurrentSelector::SpaceParent { space_id },
                json!({"parent_space_id":null}),
            ));
        }
        let view = DirectStructureView::from_current(&realm, &rows).unwrap();
        assert_eq!(view.spaces.len(), 1);
        assert_eq!(view.topics().next().unwrap().1.kind, "topic");
    }

    #[test]
    fn unrelated_private_current_does_not_break_realm_navigation() {
        let realm = RealmId::from_event_id(&event(7));
        let sidecar_id = arkret_wire::SidecarId::from_event_id(&event(8));
        let mut row = current(
            &realm,
            CurrentSelector::MlsGroup {
                scope_ref: arkret_wire::ScopeRef::Sidecar {
                    realm_id: realm.clone(),
                    sidecar_id: sidecar_id.clone(),
                },
            },
            json!({}),
        );
        let CurrentState::Value {
            source_stream_ref, ..
        } = &mut row;
        *source_stream_ref = CommitStreamRef::Sidecar {
            realm_id: realm.clone(),
            sidecar_id,
        };
        assert!(DirectStructureView::from_current(&realm, &[row]).is_ok());
    }

    #[test]
    fn circle_structure_is_filtered_only_after_its_source_scope_is_checked() {
        let realm = RealmId::from_event_id(&event(7));
        let circle = arkret_wire::CircleId::from_event_id(&event(8));
        let chat = StrandId::from_event_id(&event(9));
        let value = json!({"id":chat,"schema":"ak.schema.strand.v1","realm_id":realm,
            "scope_circle_id":circle,"tracks":{"discussion":{"is_primary":true,"enabled":true}},
            "state":"active", "created_by":{"kind":"account","account_id":{
                "principal_id":"ak:did_core:web:alice.example","station_id":"ak:did_core:web:station.example"}},
            "created_at":"2026-10-04T00:00:00.000Z"});
        let mut row = current(&realm, CurrentSelector::Strand { strand_id: chat }, value);
        assert!(DirectStructureView::from_current(&realm, &[row.clone()]).is_err());
        let CurrentState::Value {
            source_stream_ref, ..
        } = &mut row;
        *source_stream_ref = CommitStreamRef::Circle {
            realm_id: realm.clone(),
            circle_id: circle,
        };
        assert!(
            DirectStructureView::from_current(&realm, &[row.clone()])
                .unwrap()
                .chats
                .is_empty()
        );
        let CurrentState::Value {
            source_stream_ref, ..
        } = &mut row;
        *source_stream_ref = CommitStreamRef::Circle {
            realm_id: realm.clone(),
            circle_id: arkret_wire::CircleId::from_event_id(&event(10)),
        };
        assert!(DirectStructureView::from_current(&realm, &[row]).is_err());
    }
}
