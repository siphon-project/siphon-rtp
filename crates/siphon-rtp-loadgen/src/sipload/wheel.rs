//! Millisecond due buckets, bounded to one packetisation interval.

use std::collections::{HashMap, HashSet};
pub(super) struct Wheel {
    slots: Vec<HashSet<u32>>,
    positions: HashMap<u32, u64>,
    next_tick: u64,
}
impl Wheel {
    pub fn new(milliseconds: usize) -> Self {
        Self {
            slots: (0..milliseconds.max(1)).map(|_| HashSet::new()).collect(),
            positions: HashMap::new(),
            next_tick: 0,
        }
    }
    pub fn schedule(&mut self, id: u32, due: u64) {
        self.remove(id);
        let due = due.max(self.next_tick);
        let slot = due as usize % self.slots.len();
        self.slots[slot].insert(id);
        self.positions.insert(id, due);
    }
    pub fn remove(&mut self, id: u32) {
        if let Some(due) = self.positions.remove(&id) {
            let slot = due as usize % self.slots.len();
            self.slots[slot].remove(&id);
        }
    }
    pub fn due(&mut self, now: u64) -> Vec<u32> {
        let mut due = Vec::new();
        // After a stall, each bucket is inspected once, regardless of elapsed revolutions.
        let start = self
            .next_tick
            .max((now + 1).saturating_sub(self.slots.len() as u64));
        for tick in start..=now {
            let slot = tick as usize % self.slots.len();
            self.slots[slot].retain(|id| {
                if self
                    .positions
                    .get(id)
                    .is_some_and(|deadline| *deadline <= now)
                {
                    due.push(*id);
                    self.positions.remove(id);
                    false
                } else {
                    true
                }
            });
        }
        self.next_tick = self.next_tick.max(now + 1);
        due
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_due_phases_are_visited_and_removal_clears_the_slot() {
        let mut wheel = Wheel::new(20);
        wheel.schedule(1, 2);
        wheel.schedule(2, 15);
        assert!(wheel.due(1).is_empty());
        assert_eq!(wheel.due(2), vec![1]);
        wheel.schedule(1, 22);
        wheel.remove(2);
        assert!(wheel.due(21).is_empty());
        assert_eq!(wheel.due(22), vec![1]);
        assert!(wheel.positions.is_empty());
    }
    #[test]
    fn stalls_visit_each_bucket_once_without_replaying_slots() {
        let mut wheel = Wheel::new(20);
        wheel.schedule(1, 0);
        wheel.schedule(2, 5);
        let mut due = wheel.due(1000);
        due.sort();
        assert_eq!(due, vec![1, 2]);
        assert!(wheel.due(1000).is_empty());
        wheel.schedule(1, 1020);
        assert!(wheel.due(1019).is_empty());
        assert_eq!(wheel.due(1020), vec![1]);
    }
}
