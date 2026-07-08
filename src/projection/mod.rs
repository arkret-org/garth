use cokret::RealmState;
use cokret_core::{Event, RealmId, Result};

pub trait DomainProjector {
    fn apply_domain_events(&mut self, realm_id: &RealmId, events: &[Event]) -> Result<()>;
}

#[derive(Clone, Debug)]
pub struct ProjectionMount {
    state: RealmState,
}

impl ProjectionMount {
    pub fn new(realm_id: RealmId) -> Self {
        Self {
            state: RealmState::new(realm_id),
        }
    }

    pub fn state(&self) -> &RealmState {
        &self.state
    }

    pub fn state_mut(&mut self) -> &mut RealmState {
        &mut self.state
    }

    pub fn apply_events(&mut self, events: &[Event]) -> Result<()> {
        self.state.apply_events(events)
    }

    pub fn apply_events_with_domain<P>(&mut self, events: &[Event], projector: &mut P) -> Result<()>
    where
        P: DomainProjector,
    {
        self.apply_events(events)?;
        projector.apply_domain_events(&self.state.realm_id, events)
    }
}

impl DomainProjector for () {
    fn apply_domain_events(&mut self, _realm_id: &RealmId, _events: &[Event]) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use cokret_core::RealmId;

    use super::*;

    #[derive(Default)]
    struct CountingProjector {
        calls: usize,
        last_realm: Option<RealmId>,
        last_len: usize,
    }

    impl DomainProjector for CountingProjector {
        fn apply_domain_events(&mut self, realm_id: &RealmId, events: &[Event]) -> Result<()> {
            self.calls += 1;
            self.last_realm = Some(realm_id.clone());
            self.last_len = events.len();
            Ok(())
        }
    }

    fn realm_id() -> RealmId {
        RealmId::new("ck:realm:01904100-0000-7000-8000-000000000001").unwrap()
    }

    #[test]
    fn applies_sdk_reducer_then_domain_projector() {
        let realm_id = realm_id();
        let mut mount = ProjectionMount::new(realm_id.clone());
        let mut projector = CountingProjector::default();

        mount.apply_events_with_domain(&[], &mut projector).unwrap();

        assert_eq!(mount.state().realm_id, realm_id);
        assert_eq!(projector.calls, 1);
        assert_eq!(projector.last_realm.as_ref(), Some(&realm_id));
        assert_eq!(projector.last_len, 0);
    }
}
