use std::borrow::Borrow;
use std::collections::{BTreeSet, VecDeque};

/// Default bound on the dedupe window. The cursor already guarantees old
/// events are not replayed, so `seen_events` only needs to cover the recent
/// redelivery window.
pub(super) const DEFAULT_SEEN_EVENTS_CAPACITY: usize = 4096;

#[derive(Clone, Debug)]
pub(super) struct BoundedSeenWindow<T> {
    entries: VecDeque<T>,
    index: BTreeSet<T>,
    capacity: usize,
}

impl<T> BoundedSeenWindow<T>
where
    T: Ord + Clone,
{
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            index: BTreeSet::new(),
            capacity: capacity.max(1),
        }
    }

    pub fn from_entries(entries: VecDeque<T>, capacity: usize) -> Self {
        let mut window = Self::new(capacity);
        for entry in entries {
            window.remember(entry);
        }
        window
    }

    pub fn contains<Q>(&self, value: &Q) -> bool
    where
        T: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.index.contains(value)
    }

    pub fn remember(&mut self, value: T) -> bool {
        if !self.index.insert(value.clone()) {
            return false;
        }

        self.entries.push_back(value);
        while self.entries.len() > self.capacity {
            if let Some(evicted) = self.entries.pop_front() {
                self.index.remove(&evicted);
            }
        }
        true
    }

    pub fn entries(&self) -> &VecDeque<T> {
        &self.entries
    }
}

impl<T> Default for BoundedSeenWindow<T>
where
    T: Ord + Clone,
{
    fn default() -> Self {
        Self::new(DEFAULT_SEEN_EVENTS_CAPACITY)
    }
}
