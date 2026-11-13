//! Version vectors: `device id -> (number of saves by that device, save tag)`.
//!
//! The save tag is a random 64-bit value chosen at every save and carried
//! along when other devices build on top of the file. It lets a device
//! recognise ITS OWN save even after the file was superseded (crash recovery)
//! and recognise a save made by a clone using its id with the same counter.
//! Comparisons use only the counters.

use std::cmp::Ordering;
use std::collections::BTreeMap;

pub type DeviceId = [u8; 16];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Dot {
    pub counter: u64,
    pub tag: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VersionVector(pub BTreeMap<DeviceId, Dot>);

/// Result of comparing a file's vector F against the locally known vector L.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Relation {
    /// F == L for every device.
    Equal,
    /// F >= L everywhere and > somewhere: linear progress.
    Ahead,
    /// F <= L everywhere and < somewhere: an older version (rollback).
    Behind,
    /// Neither: histories forked (concurrent offline edits, or an attack).
    Concurrent,
}

impl VersionVector {
    pub fn get(&self, d: &DeviceId) -> u64 {
        self.0.get(d).map_or(0, |x| x.counter)
    }

    pub fn tag(&self, d: &DeviceId) -> Option<u64> {
        self.0.get(d).map(|x| x.tag)
    }

    /// Sets a counter with tag 0 (tests).
    pub fn set(&mut self, d: DeviceId, n: u64) {
        self.set_tagged(d, n, 0);
    }

    pub fn set_tagged(&mut self, d: DeviceId, counter: u64, tag: u64) {
        if counter == 0 {
            self.0.remove(&d);
        } else {
            self.0.insert(d, Dot { counter, tag });
        }
    }

    /// Compares `self` (F) with `local` (L), counters only.
    pub fn relation_to(&self, local: &VersionVector) -> Relation {
        let mut greater = false;
        let mut less = false;
        for d in self.0.keys().chain(local.0.keys()) {
            match self.get(d).cmp(&local.get(d)) {
                Ordering::Greater => greater = true,
                Ordering::Less => less = true,
                Ordering::Equal => {}
            }
        }
        match (greater, less) {
            (false, false) => Relation::Equal,
            (true, false) => Relation::Ahead,
            (false, true) => Relation::Behind,
            (true, true) => Relation::Concurrent,
        }
    }

    /// Component-wise maximum (the dot with the higher counter wins).
    pub fn merged(&self, other: &VersionVector) -> VersionVector {
        let mut out = self.clone();
        for (d, dot) in &other.0 {
            if dot.counter > out.get(d) {
                out.0.insert(*d, *dot);
            }
        }
        out
    }

    /// True if `self >= other` for every device.
    pub fn dominates(&self, other: &VersionVector) -> bool {
        matches!(self.relation_to(other), Relation::Equal | Relation::Ahead)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vv(pairs: &[(u8, u64)]) -> VersionVector {
        let mut v = VersionVector::default();
        for (d, n) in pairs {
            v.set([*d; 16], *n);
        }
        v
    }

    #[test]
    fn relations() {
        assert_eq!(vv(&[]).relation_to(&vv(&[])), Relation::Equal);
        assert_eq!(vv(&[(1, 2)]).relation_to(&vv(&[(1, 1)])), Relation::Ahead);
        assert_eq!(vv(&[(1, 1)]).relation_to(&vv(&[(1, 2)])), Relation::Behind);
        assert_eq!(
            vv(&[(1, 2), (2, 1)]).relation_to(&vv(&[(1, 3)])),
            Relation::Concurrent
        );
        // A device missing on one side counts as 0.
        assert_eq!(
            vv(&[(1, 1), (2, 1)]).relation_to(&vv(&[(1, 1)])),
            Relation::Ahead
        );
        assert_eq!(
            vv(&[(1, 2), (2, 3)]).merged(&vv(&[(1, 5), (3, 1)])),
            vv(&[(1, 5), (2, 3), (3, 1)])
        );
    }

    #[test]
    fn tags_do_not_affect_ordering_and_follow_the_winner() {
        let mut a = VersionVector::default();
        a.set_tagged([1; 16], 2, 111);
        let mut b = VersionVector::default();
        b.set_tagged([1; 16], 2, 222);
        assert_eq!(a.relation_to(&b), Relation::Equal);
        let mut c = VersionVector::default();
        c.set_tagged([1; 16], 3, 333);
        assert_eq!(a.merged(&c).tag(&[1; 16]), Some(333));
    }
}
