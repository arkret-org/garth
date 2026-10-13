//! Local projection of already verified presence Signal plaintext.
//!
//! The Signal receiver verifies proof, MLS/decryptor, actor binding and
//! sequence before producing `SignalReceiveOutcome::Accepted`. This module
//! stores only that accepted branch; it is never a Station projection.

use std::collections::BTreeMap;

use arkret_models_collaboration::signal_plaintext::{
    PresenceState, SignalPlaintext, SignalSequenceDomain,
};
use arkret_models_discovery::{
    PresenceStatus, aggregate_presence_states, validate_last_active_at, validate_status_message,
};
use arkret_wire::ActorId;
use chrono::{DateTime, Utc};

use crate::signal::SignalReceiveOutcome;
use crate::{Error, Result};

#[derive(Clone, Debug)]
struct Observation {
    domain: SignalSequenceDomain,
    state: PresenceStatus,
    status_message: Option<String>,
    last_active_at: Option<String>,
    sent_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Default)]
pub struct PresenceProjection {
    by_endpoint: BTreeMap<String, Observation>,
}

impl PresenceProjection {
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply only a SignalReceiver-accepted plaintext. Stale and expired
    /// outcomes never alter the projection.
    pub fn apply_verified(
        &mut self,
        outcome: &SignalReceiveOutcome,
        sent_at: DateTime<Utc>,
    ) -> Result<bool> {
        let SignalReceiveOutcome::Accepted {
            domain,
            plaintext: SignalPlaintext::Presence(presence),
            effective_expires_at,
            ..
        } = outcome
        else {
            return Ok(false);
        };
        if domain.sender_actor_id != presence.actor_id || *effective_expires_at <= sent_at {
            return Err(Error::Protocol(
                "accepted presence plaintext differs from its verified sender or lifetime"
                    .to_owned(),
            ));
        }
        if let Some(message) = &presence.status_message {
            validate_status_message(message).map_err(|error| Error::Protocol(error.to_string()))?;
        }
        if let Some(last_active_at) = &presence.last_active_at {
            validate_last_active_at(last_active_at)
                .map_err(|error| Error::Protocol(error.to_string()))?;
        }
        let state = match presence.state {
            PresenceState::Dnd => PresenceStatus::Dnd,
            PresenceState::Online => PresenceStatus::Online,
            PresenceState::Idle => PresenceStatus::Idle,
            PresenceState::Offline => PresenceStatus::Offline,
        };
        let key = domain.canonical_key()?;
        self.by_endpoint.insert(
            key,
            Observation {
                domain: (**domain).clone(),
                state,
                status_message: presence.status_message.clone(),
                last_active_at: presence.last_active_at.clone(),
                sent_at,
                expires_at: *effective_expires_at,
            },
        );
        Ok(true)
    }

    /// Immediately forget a replaced Agent runtime key or revoked endpoint.
    pub fn remove_endpoint(&mut self, domain: &SignalSequenceDomain) -> Result<()> {
        self.by_endpoint.remove(&domain.canonical_key()?);
        Ok(())
    }

    fn active_for(
        &self,
        actor: &ActorId,
        now: DateTime<Utc>,
    ) -> impl Iterator<Item = &Observation> {
        let actor = actor.clone();
        self.by_endpoint.values().filter(move |row| {
            row.domain.sender_actor_id == actor && row.sent_at <= now && row.expires_at > now
        })
    }

    pub fn aggregated(&self, actor: &ActorId, now: DateTime<Utc>) -> PresenceStatus {
        aggregate_presence_states(self.active_for(actor, now).map(|row| row.state))
    }

    pub fn status_message<'a>(&'a self, actor: &ActorId, now: DateTime<Utc>) -> Option<&'a str> {
        self.active_for(actor, now)
            .filter(|row| {
                row.status_message
                    .as_deref()
                    .is_some_and(|value| !value.is_empty())
            })
            .max_by_key(|row| row.sent_at)
            .and_then(|row| row.status_message.as_deref())
    }

    pub fn last_active_at<'a>(&'a self, actor: &ActorId, now: DateTime<Utc>) -> Option<&'a str> {
        self.active_for(actor, now)
            .filter(|row| row.last_active_at.is_some())
            .max_by_key(|row| row.sent_at)
            .and_then(|row| row.last_active_at.as_deref())
    }

    pub fn observation_count(&self, actor: &ActorId, now: DateTime<Utc>) -> usize {
        self.active_for(actor, now).count()
    }
}
