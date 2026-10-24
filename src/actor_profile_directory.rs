//! Authorized co-member Actor Profile resolution and its display cache.
//!
//! A global Actor Profile lives in its owner's Principal Control Realm, so a
//! co-member reaches it only through `ak.self.actor_profile.read.resolve.v1`
//! with a shared Collaboration Realm as the authorization basis. This module
//! owns that orchestration for every host: the round trip, the per-row
//! validation, and the fresh / stale / unavailable classification a UI needs in
//! order to decide what it is allowed to claim about a peer's name.
//!
//! What a row proves is checked by
//! [`arkret_models_collaboration::actor_profile_resolution::validate_resolved_actor_profile`]:
//! the exact committed Event, the display projection and the requested actor are
//! one subject. A row that fails that check is recorded as unavailable rather
//! than displayed, because a projection the client cannot bind to an Event is
//! not weaker evidence — it is none. That degradation is per actor on purpose:
//! one row the client cannot bind does not cost it the rows that bound fine,
//! which is what the operation's single-valued per-actor failure is for.
//!
//! The protocol declares no freshness lease for a profile, so the window that
//! separates fresh from stale is a local display policy, not a wire fact. The
//! distinction still matters: a stale row may be rendered as a peer's current
//! name, and a fresh row is additionally allowed to answer "has this peer
//! renamed since the holder last confirmed it", because reporting `changed`
//! from an old read would accuse a peer on the strength of a cache
//! (`zh/discovery/client-preferences.md` section 3.6,
//! `zh/discovery/profiles-presence.md` section 2.3).

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;

use arkret_models_collaboration::actor_profile_resolution::{
    ConfirmedDisplayNameState, classify_confirmed_display_name, validate_resolved_actor_profile,
};
use arkret_models_collaboration::objects::productivity::ContactRemark;
use arkret_models_identity::actor_profile::ActorProfile;
use arkret_models_identity::actor_profile_operations::{
    ACTOR_PROFILE_RESOLVE_MAX_ACTORS, ActorProfileResolveRequestBody,
    ActorProfileResolveResponseBody, ResolvedActorProfile,
};
use arkret_wire::{ActorId, RealmId};
use chrono::{DateTime, TimeDelta, Utc};

use crate::{Error, MaybeSendSync, Result};

/// Local freshness window for a resolved profile.
///
/// Five minutes is short enough that a rename is noticed within one ordinary
/// session and long enough that a roster render does not re-resolve every
/// visible member. Hosts with a different display policy set their own.
pub const DEFAULT_ACTOR_PROFILE_FRESH_FOR_SECONDS: i64 = 300;

#[cfg(not(target_arch = "wasm32"))]
pub type BoxActorProfileFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

#[cfg(target_arch = "wasm32")]
pub type BoxActorProfileFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + 'a>>;

/// Transport for the single authorized profile read.
pub trait ActorProfileResolveTransport: MaybeSendSync {
    fn resolve_actor_profiles<'a>(
        &'a self,
        request: &'a ActorProfileResolveRequestBody,
    ) -> BoxActorProfileFuture<'a, ActorProfileResolveResponseBody>;
}

impl ActorProfileResolveTransport for arkret_http_client::Client {
    fn resolve_actor_profiles<'a>(
        &'a self,
        request: &'a ActorProfileResolveRequestBody,
    ) -> BoxActorProfileFuture<'a, ActorProfileResolveResponseBody> {
        Box::pin(async move {
            self.actor_profile_resolve(request)
                .await
                .map_err(Error::from)
        })
    }
}

/// Why a cached row is not usable as current evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActorProfileUnavailableCause {
    /// The Station reported the single `profile_unavailable` value. Unknown
    /// actor, actor without an accepted profile, non-member actor and
    /// unauthorized caller are indistinguishable here by design.
    ReportedUnavailable,
    /// The row arrived but its Event, projection and actor did not agree.
    EvidenceRejected,
}

/// What the cache can say about one actor in one Realm.
#[derive(Clone, Debug)]
pub enum ActorProfileView<'a> {
    /// Validated evidence read inside the freshness window.
    Fresh {
        evidence: &'a ResolvedActorProfile,
        resolved_at: DateTime<Utc>,
    },
    /// Validated evidence older than the freshness window. Displayable as the
    /// peer's name; not a basis for a rename claim.
    Stale {
        evidence: &'a ResolvedActorProfile,
        resolved_at: DateTime<Utc>,
    },
    /// The last read produced no usable profile.
    Unavailable {
        cause: ActorProfileUnavailableCause,
        observed_at: DateTime<Utc>,
    },
    /// Never resolved in this Realm.
    Unknown,
}

impl ActorProfileView<'_> {
    /// The profile a display surface may render, fresh or stale.
    pub fn displayable(&self) -> Option<&ActorProfile> {
        match self {
            Self::Fresh { evidence, .. } | Self::Stale { evidence, .. } => {
                Some(&evidence.actor_profile)
            }
            Self::Unavailable { .. } | Self::Unknown => None,
        }
    }

    /// The evidence a rename comparison may use. Only a fresh row qualifies.
    pub fn current_evidence(&self) -> Option<&ResolvedActorProfile> {
        match self {
            Self::Fresh { evidence, .. } => Some(evidence),
            Self::Stale { .. } | Self::Unavailable { .. } | Self::Unknown => None,
        }
    }

    pub fn is_fresh(&self) -> bool {
        matches!(self, Self::Fresh { .. })
    }
}

/// The resolved evidence is boxed: a full Event plus projection dwarfs the
/// unavailable variant, and the map stores one entry per visible member.
#[derive(Clone, Debug)]
enum CacheEntry {
    Resolved {
        evidence: Box<ResolvedActorProfile>,
        resolved_at: DateTime<Utc>,
    },
    Unavailable {
        cause: ActorProfileUnavailableCause,
        observed_at: DateTime<Utc>,
    },
}

impl CacheEntry {
    fn observed_at(&self) -> DateTime<Utc> {
        match self {
            Self::Resolved { resolved_at, .. } => *resolved_at,
            Self::Unavailable { observed_at, .. } => *observed_at,
        }
    }
}

/// Per-Realm cache of authorized co-member profile reads.
///
/// Keyed by `(realm_id, actor_id)` because the authorization basis is the
/// shared Realm: the same owner reached through a Realm the caller has since
/// left is not the same permission, and a row must never survive into a Realm
/// that did not authorize it.
#[derive(Clone, Debug)]
pub struct ActorProfileDirectory {
    fresh_for: TimeDelta,
    entries: BTreeMap<(RealmId, ActorId), CacheEntry>,
}

impl Default for ActorProfileDirectory {
    fn default() -> Self {
        Self::new()
    }
}

impl ActorProfileDirectory {
    pub fn new() -> Self {
        Self::with_fresh_for(
            TimeDelta::try_seconds(DEFAULT_ACTOR_PROFILE_FRESH_FOR_SECONDS)
                .expect("the default freshness window is a valid duration"),
        )
    }

    pub fn with_fresh_for(fresh_for: TimeDelta) -> Self {
        Self {
            fresh_for,
            entries: BTreeMap::new(),
        }
    }

    pub fn fresh_for(&self) -> TimeDelta {
        self.fresh_for
    }

    /// Classify what is known about one actor in one Realm.
    pub fn view(
        &self,
        realm_id: &RealmId,
        actor_id: &ActorId,
        now: DateTime<Utc>,
    ) -> ActorProfileView<'_> {
        match self.entries.get(&(realm_id.clone(), actor_id.clone())) {
            None => ActorProfileView::Unknown,
            Some(CacheEntry::Unavailable { cause, observed_at }) => ActorProfileView::Unavailable {
                cause: *cause,
                observed_at: *observed_at,
            },
            Some(CacheEntry::Resolved {
                evidence,
                resolved_at,
            }) => {
                if self.is_within_window(*resolved_at, now) {
                    ActorProfileView::Fresh {
                        evidence,
                        resolved_at: *resolved_at,
                    }
                } else {
                    ActorProfileView::Stale {
                        evidence,
                        resolved_at: *resolved_at,
                    }
                }
            }
        }
    }

    /// Compare a Contact confirmation baseline against current evidence.
    ///
    /// A stale or unavailable row yields `Unknown`, never `Changed`: the holder
    /// is told the comparison could not be made rather than told a peer renamed
    /// on the strength of an old read.
    pub fn confirmed_display_name_state(
        &self,
        realm_id: &RealmId,
        actor_id: &ActorId,
        remark: Option<&ContactRemark>,
        now: DateTime<Utc>,
    ) -> ConfirmedDisplayNameState {
        let view = self.view(realm_id, actor_id, now);
        classify_confirmed_display_name(remark, view.current_evidence())
    }

    /// Actors among `actor_ids` that need a round trip, in request order and
    /// deduplicated.
    ///
    /// An unavailable row is retried on the same window as a stale one, so a
    /// peer that has just published its first profile becomes visible without
    /// the client polling an anti-enumeration surface in a loop.
    pub fn pending_refresh(
        &self,
        realm_id: &RealmId,
        actor_ids: &[ActorId],
        now: DateTime<Utc>,
    ) -> Vec<ActorId> {
        let mut pending: Vec<ActorId> = Vec::new();
        for actor_id in actor_ids {
            let needs_refresh = match self.entries.get(&(realm_id.clone(), actor_id.clone())) {
                None => true,
                Some(entry) => !self.is_within_window(entry.observed_at(), now),
            };
            if needs_refresh && !pending.contains(actor_id) {
                pending.push(actor_id.clone());
            }
        }
        pending
    }

    /// Resolve the actors that need refreshing and record every outcome.
    ///
    /// Returns the actors actually requested. Nothing is requested when every
    /// entry is still inside the window, so a render loop can call this
    /// unconditionally. The request is chunked to the operation's own bound so
    /// a large roster does not have to be batched by each caller.
    pub async fn refresh<T>(
        &mut self,
        transport: &T,
        realm_id: &RealmId,
        actor_ids: &[ActorId],
        now: DateTime<Utc>,
    ) -> Result<Vec<ActorId>>
    where
        T: ActorProfileResolveTransport,
    {
        let pending = self.pending_refresh(realm_id, actor_ids, now);
        for chunk in pending.chunks(ACTOR_PROFILE_RESOLVE_MAX_ACTORS) {
            let request = ActorProfileResolveRequestBody::new(realm_id.clone(), chunk.to_vec());
            let outcome = transport.resolve_actor_profiles(&request).await?;
            self.record(realm_id, chunk, outcome, now);
        }
        Ok(pending)
    }

    /// Record one already-validated outcome for `requested`.
    ///
    /// Exposed separately so a host that already holds a resolve response (a
    /// replayed fixture, a shared batch fetched for another surface) installs it
    /// without a second round trip. Rows are re-validated here: a caller cannot
    /// smuggle an unchecked projection into the cache.
    pub fn record(
        &mut self,
        realm_id: &RealmId,
        requested: &[ActorId],
        outcome: ActorProfileResolveResponseBody,
        now: DateTime<Utc>,
    ) {
        let mut accounted: Vec<ActorId> = Vec::new();
        for row in outcome.profiles {
            let actor_id = row.actor_id.clone();
            let entry = match validate_resolved_actor_profile(&row) {
                Ok(_) => CacheEntry::Resolved {
                    evidence: Box::new(row),
                    resolved_at: now,
                },
                Err(_) => CacheEntry::Unavailable {
                    cause: ActorProfileUnavailableCause::EvidenceRejected,
                    observed_at: now,
                },
            };
            accounted.push(actor_id.clone());
            self.entries.insert((realm_id.clone(), actor_id), entry);
        }
        for failure in outcome.failures.into_iter().flatten() {
            accounted.push(failure.actor_id.clone());
            self.entries.insert(
                (realm_id.clone(), failure.actor_id),
                CacheEntry::Unavailable {
                    cause: ActorProfileUnavailableCause::ReportedUnavailable,
                    observed_at: now,
                },
            );
        }
        // A row the response never accounted for is not left showing an older
        // value: the caller asked about it and got nothing back for it.
        for actor_id in requested {
            if !accounted.contains(actor_id) {
                self.entries.insert(
                    (realm_id.clone(), actor_id.clone()),
                    CacheEntry::Unavailable {
                        cause: ActorProfileUnavailableCause::ReportedUnavailable,
                        observed_at: now,
                    },
                );
            }
        }
    }

    /// Drop every cached row for a Realm.
    ///
    /// Called when the holder leaves the Realm or its membership is suspended:
    /// the shared membership was the authorization basis, so once it is gone the
    /// rows it justified must not keep rendering.
    pub fn forget_realm(&mut self, realm_id: &RealmId) {
        self.entries.retain(|(realm, _), _| realm != realm_id);
    }

    /// Drop every cached row for one actor across all Realms.
    pub fn forget_actor(&mut self, actor_id: &ActorId) {
        self.entries.retain(|(_, actor), _| actor != actor_id);
    }

    fn is_within_window(&self, observed_at: DateTime<Utc>, now: DateTime<Utc>) -> bool {
        // The stamp is always this client's own read time, so a stamp ahead of
        // `now` means the host clock stepped backwards. That reads as fresh and
        // self-corrects once `now` passes the stamp again.
        now.signed_duration_since(observed_at) < self.fresh_for
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use arkret_models_identity::actor_profile_operations::{
        ActorProfileResolveFailure, ActorProfileResolveFailureReason,
    };
    use arkret_wire::{ActorProfileId, DidCoreId, ScopeRef};
    use serde_json::json;

    use super::*;

    const PEER: &str = "ak:did_core:webvh:z6mkother";
    const STATION: &str = "ak:did_core:webvh:z6mkfixturestation";
    const SHARED_REALM: &str = "ak:realm:AfTcej7ZFNg8uTbkOiUJT0KN1F_c9l1fmtil65CUwncm";
    const PEER_PCR: &str = "ak:realm:ARmJMvTcKFyiF-V_8oL4mIoHfnlqERCrcgNBONtY4HQD";

    fn instant(offset_seconds: i64) -> DateTime<Utc> {
        let base: DateTime<Utc> = "2026-08-11T00:00:00Z".parse().unwrap();
        base + TimeDelta::try_seconds(offset_seconds).unwrap()
    }

    fn shared_realm() -> RealmId {
        RealmId::new(SHARED_REALM).unwrap()
    }

    fn peer_row(display_name: &str) -> ResolvedActorProfile {
        let mut event = arkret_wire::test_support::raw_event_at(
            "ak.profile.create",
            ScopeRef::Realm {
                realm_id: RealmId::new(PEER_PCR).unwrap(),
            },
            DidCoreId::new(PEER).unwrap(),
            DidCoreId::new(STATION).unwrap(),
            json!({"object": {
                "principal_id": PEER,
                "actor_kind": "user",
                "display_name": display_name
            }}),
            instant(0),
        )
        .unwrap();
        event
            .refresh_content_bound_identity_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
            .unwrap();
        let profile_id = ActorProfileId::from_event_id(&event.event_id);
        let profile_commit = crate::test_fixtures::commit(
            7,
            &event,
            arkret_wire::CommitStreamRef::Realm {
                realm_id: RealmId::new(PEER_PCR).unwrap(),
            },
            1,
        );
        ResolvedActorProfile {
            actor_id: event.actor_id.clone(),
            actor_profile: serde_json::from_value(json!({
                "id": profile_id.as_str(),
                "schema": "ak.schema.actor_profile.v1",
                "realm_id": PEER_PCR,
                "principal_id": PEER,
                "actor_kind": "user",
                "display_name": display_name,
                "created_at": "2026-08-11T00:00:00.000Z"
            }))
            .unwrap(),
            profile_event: event,
            profile_commit,
            account_status: None,
        }
    }

    fn peer_actor() -> ActorId {
        peer_row("anything").actor_id
    }

    fn remark(confirmed: Option<&str>) -> ContactRemark {
        let mut remark = ContactRemark::new(DidCoreId::new(PEER).unwrap(), "", instant(0));
        remark.confirmed_display_name = confirmed.map(str::to_owned);
        remark
    }

    /// Records every request and replays scripted outcomes in order.
    struct ScriptedTransport {
        requests: Mutex<Vec<ActorProfileResolveRequestBody>>,
        outcomes: Mutex<VecDeque<ActorProfileResolveResponseBody>>,
    }

    impl ScriptedTransport {
        fn new(outcomes: Vec<ActorProfileResolveResponseBody>) -> Self {
            Self {
                requests: Mutex::new(Vec::new()),
                outcomes: Mutex::new(outcomes.into()),
            }
        }

        fn request_count(&self) -> usize {
            self.requests.lock().expect("transport lock").len()
        }
    }

    impl ActorProfileResolveTransport for ScriptedTransport {
        fn resolve_actor_profiles<'a>(
            &'a self,
            request: &'a ActorProfileResolveRequestBody,
        ) -> BoxActorProfileFuture<'a, ActorProfileResolveResponseBody> {
            self.requests
                .lock()
                .expect("transport lock")
                .push(request.clone());
            let outcome = self.outcomes.lock().expect("transport lock").pop_front();
            Box::pin(async move {
                outcome.ok_or_else(|| Error::Protocol("scripted transport exhausted".to_owned()))
            })
        }
    }

    fn resolved(row: ResolvedActorProfile) -> ActorProfileResolveResponseBody {
        ActorProfileResolveResponseBody {
            profiles: vec![row],
            failures: None,
        }
    }

    fn unavailable(actor_id: ActorId) -> ActorProfileResolveResponseBody {
        ActorProfileResolveResponseBody {
            profiles: Vec::new(),
            failures: Some(vec![ActorProfileResolveFailure {
                actor_id,
                reason: ActorProfileResolveFailureReason::ProfileUnavailable,
            }]),
        }
    }

    #[tokio::test]
    async fn a_resolved_row_is_fresh_then_stale_and_a_refresh_restores_freshness() {
        let realm = shared_realm();
        let actor = peer_actor();
        let mut directory = ActorProfileDirectory::new();
        assert!(matches!(
            directory.view(&realm, &actor, instant(0)),
            ActorProfileView::Unknown
        ));

        let transport = ScriptedTransport::new(vec![
            resolved(peer_row("Alice Zhang")),
            resolved(peer_row("Alice C.")),
        ]);
        let requested = directory
            .refresh(&transport, &realm, std::slice::from_ref(&actor), instant(0))
            .await
            .unwrap();
        assert_eq!(requested, vec![actor.clone()]);
        let view = directory.view(&realm, &actor, instant(10));
        assert!(view.is_fresh());
        assert_eq!(view.displayable().unwrap().display_name, "Alice Zhang");

        // Inside the window nothing is requested again.
        assert!(
            directory
                .refresh(
                    &transport,
                    &realm,
                    std::slice::from_ref(&actor),
                    instant(10)
                )
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(transport.request_count(), 1);

        let stale = directory.view(&realm, &actor, instant(600));
        assert!(!stale.is_fresh());
        assert_eq!(
            stale.displayable().unwrap().display_name,
            "Alice Zhang",
            "a stale row still renders the peer name"
        );
        assert!(
            stale.current_evidence().is_none(),
            "a stale row is not current evidence"
        );

        directory
            .refresh(
                &transport,
                &realm,
                std::slice::from_ref(&actor),
                instant(600),
            )
            .await
            .unwrap();
        assert_eq!(transport.request_count(), 2);
        let refreshed = directory.view(&realm, &actor, instant(601));
        assert!(refreshed.is_fresh());
        assert_eq!(refreshed.displayable().unwrap().display_name, "Alice C.");
    }

    #[tokio::test]
    async fn profile_unavailable_is_recorded_and_retried_on_the_same_window() {
        let realm = shared_realm();
        let actor = peer_actor();
        let mut directory = ActorProfileDirectory::new();
        let transport = ScriptedTransport::new(vec![
            unavailable(actor.clone()),
            resolved(peer_row("Alice Zhang")),
        ]);

        directory
            .refresh(&transport, &realm, std::slice::from_ref(&actor), instant(0))
            .await
            .unwrap();
        assert!(matches!(
            directory.view(&realm, &actor, instant(1)),
            ActorProfileView::Unavailable {
                cause: ActorProfileUnavailableCause::ReportedUnavailable,
                ..
            }
        ));
        assert!(
            directory
                .pending_refresh(&realm, std::slice::from_ref(&actor), instant(1))
                .is_empty(),
            "an unavailable row is not re-asked inside the window"
        );

        directory
            .refresh(
                &transport,
                &realm,
                std::slice::from_ref(&actor),
                instant(600),
            )
            .await
            .unwrap();
        assert!(
            directory.view(&realm, &actor, instant(601)).is_fresh(),
            "a peer that publishes its first profile becomes visible on the next window"
        );
    }

    #[tokio::test]
    async fn a_row_whose_evidence_does_not_bind_is_unavailable_rather_than_displayed() {
        let realm = shared_realm();
        let actor = peer_actor();
        let mut broken = peer_row("Alice Zhang");
        broken.actor_profile.id = None;
        let transport = ScriptedTransport::new(vec![resolved(broken)]);
        let mut directory = ActorProfileDirectory::new();

        directory
            .refresh(&transport, &realm, std::slice::from_ref(&actor), instant(0))
            .await
            .unwrap();
        assert!(matches!(
            directory.view(&realm, &actor, instant(0)),
            ActorProfileView::Unavailable {
                cause: ActorProfileUnavailableCause::EvidenceRejected,
                ..
            }
        ));
        assert!(
            directory
                .view(&realm, &actor, instant(0))
                .displayable()
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_rename_claim_needs_fresh_evidence() {
        let realm = shared_realm();
        let actor = peer_actor();
        let confirmed = remark(Some("Alice Zhang"));
        let transport = ScriptedTransport::new(vec![resolved(peer_row("Alice C."))]);
        let mut directory = ActorProfileDirectory::new();

        assert_eq!(
            directory.confirmed_display_name_state(&realm, &actor, Some(&confirmed), instant(0)),
            ConfirmedDisplayNameState::Unknown {
                confirmed: Some("Alice Zhang".to_owned())
            },
            "an unresolved peer cannot be reported as renamed"
        );

        directory
            .refresh(&transport, &realm, std::slice::from_ref(&actor), instant(0))
            .await
            .unwrap();
        assert_eq!(
            directory.confirmed_display_name_state(&realm, &actor, Some(&confirmed), instant(1)),
            ConfirmedDisplayNameState::Changed {
                confirmed: "Alice Zhang".to_owned(),
                current: "Alice C.".to_owned()
            }
        );
        assert_eq!(
            directory.confirmed_display_name_state(&realm, &actor, Some(&confirmed), instant(600)),
            ConfirmedDisplayNameState::Unknown {
                confirmed: Some("Alice Zhang".to_owned())
            },
            "the same row goes back to unknown once it leaves the freshness window"
        );
    }

    #[tokio::test]
    async fn leaving_the_realm_drops_the_rows_that_membership_authorized() {
        let realm = shared_realm();
        let actor = peer_actor();
        let transport = ScriptedTransport::new(vec![resolved(peer_row("Alice Zhang"))]);
        let mut directory = ActorProfileDirectory::new();
        directory
            .refresh(&transport, &realm, std::slice::from_ref(&actor), instant(0))
            .await
            .unwrap();
        assert!(directory.view(&realm, &actor, instant(0)).is_fresh());

        directory.forget_realm(&realm);
        assert!(matches!(
            directory.view(&realm, &actor, instant(0)),
            ActorProfileView::Unknown
        ));
    }

    #[test]
    fn an_actor_the_response_never_accounted_for_stops_rendering_an_older_value() {
        let realm = shared_realm();
        let actor = peer_actor();
        let mut directory = ActorProfileDirectory::new();
        directory.record(
            &realm,
            std::slice::from_ref(&actor),
            resolved(peer_row("Alice Zhang")),
            instant(0),
        );
        assert!(directory.view(&realm, &actor, instant(0)).is_fresh());

        directory.record(
            &realm,
            std::slice::from_ref(&actor),
            ActorProfileResolveResponseBody {
                profiles: Vec::new(),
                failures: None,
            },
            instant(600),
        );
        assert!(matches!(
            directory.view(&realm, &actor, instant(600)),
            ActorProfileView::Unavailable { .. }
        ));
    }
}
