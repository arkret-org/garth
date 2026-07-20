//! Client-side in-memory discovery index.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{Did, RealmId};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealmSearchEntry {
    pub realm_id: RealmId,
    pub name: String,
    pub description: Option<String>,
    pub tags: BTreeSet<String>,
    pub members: BTreeSet<Did>,
    pub public: bool,
    pub category: Option<String>,
}

impl RealmSearchEntry {
    pub fn new(realm_id: RealmId, name: impl Into<String>) -> Self {
        Self {
            realm_id,
            name: name.into(),
            description: None,
            tags: BTreeSet::new(),
            members: BTreeSet::new(),
            public: false,
            category: None,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct DirectoryService {
    realms: BTreeMap<RealmId, RealmSearchEntry>,
}

impl DirectoryService {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn publish_realm(&mut self, mut entry: RealmSearchEntry) {
        entry.public = true;
        self.realms.insert(entry.realm_id.clone(), entry);
    }

    pub fn recommend_realms(
        &self,
        preferred_tags: BTreeSet<String>,
        already_joined: BTreeSet<RealmId>,
        limit: usize,
    ) -> Vec<&RealmSearchEntry> {
        let mut results: Vec<_> = self
            .realms
            .values()
            .filter(|entry| entry.public && !already_joined.contains(&entry.realm_id))
            .map(|entry| {
                let score = entry
                    .tags
                    .iter()
                    .filter(|tag| preferred_tags.contains(*tag))
                    .count();
                (score, entry)
            })
            .filter(|(score, _)| *score > 0)
            .collect();
        results.sort_by(|(left_score, left), (right_score, right)| {
            right_score
                .cmp(left_score)
                .then_with(|| left.name.cmp(&right.name))
        });
        results
            .into_iter()
            .take(limit)
            .map(|(_, entry)| entry)
            .collect()
    }
}
