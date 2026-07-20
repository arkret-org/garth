use super::*;

/// Sliding Sync list configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlidingWindow {
    /// Inclusive start index.
    pub start: usize,
    /// Exclusive end index.
    pub end: usize,
}

impl SlidingWindow {
    /// Create a new window.
    pub fn new(start: usize, end: usize) -> Result<Self> {
        if start > end {
            return Err(Error::Protocol(
                "sliding sync window start is after end".to_owned(),
            ));
        }
        Ok(Self { start, end })
    }

    /// Number of items covered by this window.
    pub fn len(&self) -> usize {
        self.end.saturating_sub(self.start)
    }

    /// True if the window is empty.
    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }
}

/// Sliding Sync state for a Realm list.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SlidingSync {
    all_realms: Vec<RealmId>,
    subscribed_realms: BTreeSet<RealmId>,
    windows: Vec<SlidingWindow>,
    batch_size: Option<u32>,
    timeline_filter: Option<TimelineFilter>,
}

impl SlidingSync {
    /// Create an empty Sliding Sync state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the known ordered Realm list.
    pub fn set_realm_list(&mut self, realms: Vec<RealmId>) {
        self.all_realms = realms;
    }

    /// Replace the active windows.
    pub fn set_windows(&mut self, windows: Vec<SlidingWindow>) {
        self.windows = windows;
    }

    /// Set timeline batch size.
    pub fn set_batch_size(&mut self, batch_size: Option<u32>) {
        self.batch_size = batch_size;
    }

    /// Set timeline filter for generated subscriptions.
    pub fn set_timeline_filter(&mut self, timeline_filter: Option<TimelineFilter>) {
        self.timeline_filter = timeline_filter;
    }

    /// Apply incremental insertions/removals to the ordered Realm list.
    pub fn apply_delta(&mut self, removals: &[RealmId], insertions: Vec<(usize, RealmId)>) {
        let removal_set: BTreeSet<_> = removals.iter().cloned().collect();
        self.all_realms
            .retain(|realm_id| !removal_set.contains(realm_id));

        for (index, realm_id) in insertions {
            let index = index.min(self.all_realms.len());
            self.all_realms.insert(index, realm_id);
        }
    }

    /// realms currently visible through all windows.
    pub fn visible_realms(&self) -> Vec<RealmId> {
        let mut visible = BTreeSet::new();
        for window in &self.windows {
            for realm_id in self.all_realms.iter().skip(window.start).take(window.len()) {
                visible.insert(realm_id.clone());
            }
        }
        visible.into_iter().collect()
    }

    /// Build protocol subscriptions for the current visible realms.
    pub fn subscription_config(&mut self) -> SubscriptionConfig {
        let visible = self.visible_realms();
        self.subscribed_realms = visible.iter().cloned().collect();

        SubscriptionConfig {
            subscriptions: visible
                .into_iter()
                .map(|realm_id| RealmSubscription {
                    realm_id,
                    timeline_filter: self.timeline_filter.clone(),
                    required_state: Vec::new(),
                })
                .collect(),
            batch_size: self.batch_size,
            timeline_filter: None,
        }
    }

    /// True if a Realm is part of the current visible subscription set.
    pub fn is_subscribed(&self, realm_id: &RealmId) -> bool {
        self.subscribed_realms.contains(realm_id)
    }

    /// Export sliding-window state for persistence.
    pub fn snapshot(&self) -> Self {
        self.clone()
    }

    /// Restore sliding-window state from a previous snapshot.
    pub fn from_snapshot(snapshot: Self) -> Self {
        snapshot
    }
}

/// Sort order for the Realm list.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RealmListSort {
    /// Most recent activity first.
    #[default]
    Recency,
    /// Name ascending.
    Name,
    /// Unread count descending.
    Unread,
    /// Favorites first, then recency.
    Favorite,
}

/// Filter for Realm list projections.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealmListFilter {
    /// Membership buckets to include. Empty means all buckets.
    #[serde(default)]
    pub memberships: BTreeSet<MembershipBucket>,
    /// Favorite flag filter.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub favorite: Option<bool>,
    /// Include only realms with unread notifications.
    #[serde(default)]
    pub unread_only: bool,
    /// Optional category filter.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
}

impl RealmListFilter {
    fn matches(&self, entry: &RealmListEntry) -> bool {
        (self.memberships.is_empty() || self.memberships.contains(&entry.membership))
            && self
                .favorite
                .map(|favorite| entry.favorite == favorite)
                .unwrap_or(true)
            && (!self.unread_only || entry.unread_count > 0 || entry.highlight_count > 0)
            && self
                .category
                .as_ref()
                .map(|category| entry.category.as_ref() == Some(category))
                .unwrap_or(true)
    }
}

/// One item in a Realm list.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealmListEntry {
    /// Realm ID.
    pub realm_id: RealmId,
    /// Display name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Membership bucket.
    pub membership: MembershipBucket,
    /// Last event ID used for recency.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_event_id: Option<EventId>,
    /// Last deterministic timeline position.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_activity: Option<TimelineOrderKey>,
    /// Notification count.
    pub unread_count: u64,
    /// Highlight count.
    pub highlight_count: u64,
    /// User favorite flag.
    pub favorite: bool,
    /// Optional category.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
}

impl RealmListEntry {
    /// Create a list entry with default joined membership.
    pub fn joined(realm_id: RealmId) -> Self {
        Self {
            realm_id,
            name: None,
            membership: MembershipBucket::Joined,
            last_event_id: None,
            last_activity: None,
            unread_count: 0,
            highlight_count: 0,
            favorite: false,
            category: None,
        }
    }
}

/// Incremental Realm list change.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RealmListChange {
    /// New visible entry.
    Inserted { index: usize, entry: RealmListEntry },
    /// Existing visible entry changed in place.
    Updated { index: usize, entry: RealmListEntry },
    /// Entry disappeared from the visible projection.
    Removed { old_index: usize, realm_id: RealmId },
    /// Existing entry moved after sorting/filtering.
    Moved {
        old_index: usize,
        new_index: usize,
        realm_id: RealmId,
    },
}

/// Result of applying one Realm-list mutation.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealmListUpdate {
    /// Ordered visible Realm IDs after the mutation.
    #[serde(default)]
    pub ordered: Vec<RealmId>,
    /// Incremental changes suitable for UI bindings.
    #[serde(default)]
    pub changes: Vec<RealmListChange>,
}

/// Serializable Realm-list state.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealmListSnapshot {
    /// Entries by Realm.
    #[serde(default)]
    pub entries: BTreeMap<RealmId, RealmListEntry>,
    /// Visible ordered projection.
    #[serde(default)]
    pub ordered: Vec<RealmId>,
    /// Current sort.
    pub sort: RealmListSort,
    /// Current filter.
    pub filter: RealmListFilter,
}

/// Realm list service with deterministic sorting, filtering and deltas.
#[derive(Clone, Debug, Default)]
pub struct RealmListService {
    entries: BTreeMap<RealmId, RealmListEntry>,
    ordered: Vec<RealmId>,
    sort: RealmListSort,
    filter: RealmListFilter,
}

impl RealmListService {
    /// Create an empty list service.
    pub fn new() -> Self {
        Self::default()
    }

    /// Restore service state from a snapshot.
    pub fn from_snapshot(snapshot: RealmListSnapshot) -> Self {
        Self {
            entries: snapshot.entries,
            ordered: snapshot.ordered,
            sort: snapshot.sort,
            filter: snapshot.filter,
        }
    }

    /// Export list state for persistence by the embedding application.
    pub fn snapshot(&self) -> RealmListSnapshot {
        RealmListSnapshot {
            entries: self.entries.clone(),
            ordered: self.ordered.clone(),
            sort: self.sort,
            filter: self.filter.clone(),
        }
    }

    /// Current ordered visible entries.
    pub fn entries(&self) -> Vec<&RealmListEntry> {
        self.ordered
            .iter()
            .filter_map(|realm_id| self.entries.get(realm_id))
            .collect()
    }

    /// Set sort mode and return the resulting delta.
    pub fn set_sort(&mut self, sort: RealmListSort) -> RealmListUpdate {
        let previous = self.visible_entries();
        self.sort = sort;
        self.rebuild_update(previous)
    }

    /// Set filter and return the resulting delta.
    pub fn set_filter(&mut self, filter: RealmListFilter) -> RealmListUpdate {
        let previous = self.visible_entries();
        self.filter = filter;
        self.rebuild_update(previous)
    }

    /// Insert or update one entry.
    pub fn upsert(&mut self, entry: RealmListEntry) -> RealmListUpdate {
        let previous = self.visible_entries();
        self.entries.insert(entry.realm_id.clone(), entry);
        self.rebuild_update(previous)
    }

    /// Remove one entry.
    pub fn remove(&mut self, realm_id: &RealmId) -> RealmListUpdate {
        let previous = self.visible_entries();
        self.entries.remove(realm_id);
        self.rebuild_update(previous)
    }

    /// Apply a processed sync update to list metadata.
    pub fn apply_space_update(
        &mut self,
        update: &RealmUpdate,
        membership: MembershipBucket,
    ) -> RealmListUpdate {
        let mut entry = self
            .entries
            .get(&update.realm_id)
            .cloned()
            .unwrap_or_else(|| RealmListEntry::joined(update.realm_id.clone()));
        entry.membership = membership;
        if let Some(metadata) = update
            .entry
            .state_at_window_start
            .as_ref()
            .map(|state| &state.realm_metadata)
        {
            entry.name = metadata.title.clone();
        }
        if let Some(unread) = &update.entry.unread_notifications {
            entry.unread_count = unread.notification_count.unwrap_or(0);
            entry.highlight_count = unread.highlight_count.unwrap_or(0);
        }
        if let Some(timeline) = &update.entry.timeline
            && let Some(event) = timeline.events.last()
        {
            entry.last_event_id = Some(event.event_id.clone());
            entry.last_activity = Some(TimelineOrderKey::from_event(
                event,
                event.prev_refs.len() as u64,
            ));
        }
        self.upsert(entry)
    }

    fn rebuild_update(&mut self, previous: Vec<RealmListEntry>) -> RealmListUpdate {
        let current = self.rebuild_order();
        let changes = diff_realm_lists(&previous, &current);
        RealmListUpdate {
            ordered: current.iter().map(|entry| entry.realm_id.clone()).collect(),
            changes,
        }
    }

    fn rebuild_order(&mut self) -> Vec<RealmListEntry> {
        let mut entries = self.visible_entries();
        entries.sort_by(|left, right| compare_space_entries(left, right, self.sort));
        self.ordered = entries.iter().map(|entry| entry.realm_id.clone()).collect();
        entries
    }

    fn visible_entries(&self) -> Vec<RealmListEntry> {
        self.entries
            .values()
            .filter(|entry| self.filter.matches(entry))
            .cloned()
            .collect()
    }
}

fn compare_space_entries(
    left: &RealmListEntry,
    right: &RealmListEntry,
    sort: RealmListSort,
) -> std::cmp::Ordering {
    let name_order = left
        .name
        .cmp(&right.name)
        .then_with(|| left.realm_id.cmp(&right.realm_id));
    match sort {
        RealmListSort::Recency => right
            .last_activity
            .cmp(&left.last_activity)
            .then(name_order),
        RealmListSort::Name => name_order,
        RealmListSort::Unread => right
            .highlight_count
            .cmp(&left.highlight_count)
            .then_with(|| right.unread_count.cmp(&left.unread_count))
            .then_with(|| right.last_activity.cmp(&left.last_activity))
            .then(name_order),
        RealmListSort::Favorite => right
            .favorite
            .cmp(&left.favorite)
            .then_with(|| right.last_activity.cmp(&left.last_activity))
            .then(name_order),
    }
}

fn diff_realm_lists(
    previous: &[RealmListEntry],
    current: &[RealmListEntry],
) -> Vec<RealmListChange> {
    let previous_index: BTreeMap<_, _> = previous
        .iter()
        .enumerate()
        .map(|(index, entry)| (entry.realm_id.clone(), (index, entry)))
        .collect();
    let current_index: BTreeMap<_, _> = current
        .iter()
        .enumerate()
        .map(|(index, entry)| (entry.realm_id.clone(), (index, entry)))
        .collect();
    let mut changes = Vec::new();

    for (realm_id, (old_index, _)) in &previous_index {
        if !current_index.contains_key(realm_id) {
            changes.push(RealmListChange::Removed {
                old_index: *old_index,
                realm_id: realm_id.clone(),
            });
        }
    }
    for (realm_id, (new_index, entry)) in &current_index {
        match previous_index.get(realm_id) {
            None => changes.push(RealmListChange::Inserted {
                index: *new_index,
                entry: (*entry).clone(),
            }),
            Some((old_index, previous_entry)) if *old_index != *new_index => {
                changes.push(RealmListChange::Moved {
                    old_index: *old_index,
                    new_index: *new_index,
                    realm_id: realm_id.clone(),
                });
                if *previous_entry != *entry {
                    changes.push(RealmListChange::Updated {
                        index: *new_index,
                        entry: (*entry).clone(),
                    });
                }
            }
            Some((_, previous_entry)) if *previous_entry != *entry => {
                changes.push(RealmListChange::Updated {
                    index: *new_index,
                    entry: (*entry).clone(),
                });
            }
            _ => {}
        }
    }
    changes
}
