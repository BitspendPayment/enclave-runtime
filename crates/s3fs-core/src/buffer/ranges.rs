//! `RangeSet` — a small set of disjoint, sorted, half-open `u64` ranges.
//!
//! Used to track which byte ranges within a part are dirty (so that a partial
//! flush knows what to read-modify-write) and to compute the *unmodified*
//! complement that needs `UploadPartCopy` during `commit`.
//!
//! Performance is `O(n)` per insert in the worst case, where `n` is the
//! current number of disjoint ranges. For real workloads `n` is small
//! (sequential writers produce 1; even random writers cluster).

use std::ops::Range;

/// Set of disjoint `u64` byte ranges, kept sorted by `start` and merged on
/// adjacency (half-open: `r1.end == r2.start` merges).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RangeSet {
    ranges: Vec<Range<u64>>,
}

impl RangeSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    pub fn len(&self) -> usize {
        self.ranges.len()
    }

    /// Borrow the underlying disjoint sorted ranges.
    pub fn ranges(&self) -> &[Range<u64>] {
        &self.ranges
    }

    /// Total byte coverage across all ranges.
    pub fn total_bytes(&self) -> u64 {
        self.ranges.iter().map(|r| r.end - r.start).sum()
    }

    /// Drop all ranges.
    pub fn clear(&mut self) {
        self.ranges.clear();
    }

    /// Insert `range`, merging with any overlapping or adjacent existing
    /// ranges. Empty ranges (`start == end`) are silently ignored.
    pub fn insert(&mut self, range: Range<u64>) {
        if range.start >= range.end {
            return;
        }
        // Find the insertion span: ranges that overlap or are adjacent to
        // `range`. Those get coalesced into one.
        let mut new_start = range.start;
        let mut new_end = range.end;
        // Index range to remove.
        let mut first_to_remove: Option<usize> = None;
        let mut last_to_remove: Option<usize> = None;

        for (i, r) in self.ranges.iter().enumerate() {
            // r ends strictly before `new_start` (no overlap, no adjacency)
            if r.end < new_start {
                continue;
            }
            // r starts strictly after `new_end` (no overlap, no adjacency)
            if r.start > new_end {
                break;
            }
            // Overlap or adjacency; absorb r.
            new_start = new_start.min(r.start);
            new_end = new_end.max(r.end);
            first_to_remove.get_or_insert(i);
            last_to_remove = Some(i);
        }

        let merged = Range {
            start: new_start,
            end: new_end,
        };
        match (first_to_remove, last_to_remove) {
            (Some(a), Some(b)) => {
                // Replace the run [a..=b] with the merged range.
                self.ranges.splice(a..=b, std::iter::once(merged));
            }
            _ => {
                // No absorption: insert at the right position to keep sorted.
                let pos = self.ranges.partition_point(|r| r.end < merged.start);
                self.ranges.insert(pos, merged);
            }
        }
    }

    /// Returns `true` iff every byte in `bound` is covered by some range.
    pub fn covers_range(&self, bound: Range<u64>) -> bool {
        if bound.start >= bound.end {
            return true;
        }
        for r in &self.ranges {
            if r.start <= bound.start && r.end >= bound.end {
                return true;
            }
            if r.start > bound.start {
                return false;
            }
        }
        false
    }

    /// Returns the sub-ranges of `bound` that are **not** covered, in order.
    /// These are the byte ranges a partial-part flush must fetch from S3 to
    /// fill the gaps before re-uploading.
    pub fn complement_within(&self, bound: Range<u64>) -> Vec<Range<u64>> {
        let mut gaps = Vec::new();
        if bound.start >= bound.end {
            return gaps;
        }
        let mut cursor = bound.start;
        for r in &self.ranges {
            if r.end <= cursor {
                continue;
            }
            if r.start >= bound.end {
                break;
            }
            if r.start > cursor {
                gaps.push(Range {
                    start: cursor,
                    end: r.start.min(bound.end),
                });
            }
            cursor = cursor.max(r.end);
            if cursor >= bound.end {
                break;
            }
        }
        if cursor < bound.end {
            gaps.push(Range {
                start: cursor,
                end: bound.end,
            });
        }
        gaps
    }
}

#[cfg(test)]
#[allow(clippy::single_range_in_vec_init)] // `&[a..b]` is a one-element slice of Range — intentional
mod tests {
    use super::*;

    #[test]
    fn empty_set() {
        let s = RangeSet::new();
        assert!(s.is_empty());
        assert_eq!(s.total_bytes(), 0);
        assert!(s.ranges().is_empty());
    }

    #[test]
    fn insert_disjoint_keeps_sorted() {
        let mut s = RangeSet::new();
        s.insert(20..30);
        s.insert(0..10);
        s.insert(50..60);
        assert_eq!(s.ranges(), &[0..10, 20..30, 50..60]);
        assert_eq!(s.total_bytes(), 30);
    }

    #[test]
    fn insert_merges_overlapping() {
        let mut s = RangeSet::new();
        s.insert(0..10);
        s.insert(5..15); // overlaps
        assert_eq!(s.ranges(), &[0..15]);
    }

    #[test]
    fn insert_merges_adjacent() {
        let mut s = RangeSet::new();
        s.insert(0..10);
        s.insert(10..20); // touches at 10
        assert_eq!(s.ranges(), &[0..20]);
    }

    #[test]
    fn insert_swallows_run_of_ranges() {
        let mut s = RangeSet::new();
        s.insert(0..5);
        s.insert(10..15);
        s.insert(20..25);
        s.insert(2..23); // covers parts of all three
        assert_eq!(s.ranges(), &[0..25]);
    }

    #[test]
    fn insert_inside_existing_range_noop() {
        let mut s = RangeSet::new();
        s.insert(0..100);
        s.insert(40..50);
        assert_eq!(s.ranges(), &[0..100]);
    }

    #[test]
    fn empty_insert_is_ignored() {
        let mut s = RangeSet::new();
        s.insert(10..10);
        // `start > end` is also defensively ignored, but constructing one
        // trips clippy::reversed_empty_ranges; the start==end case above is
        // sufficient to exercise the early-return path.
        assert!(s.is_empty());
    }

    #[test]
    fn covers_range_strict() {
        let mut s = RangeSet::new();
        s.insert(0..100);
        assert!(s.covers_range(0..100));
        assert!(s.covers_range(10..50));
        assert!(s.covers_range(99..100));
        assert!(!s.covers_range(0..101));
        assert!(!s.covers_range(100..101));
    }

    #[test]
    fn complement_within_full_coverage_is_empty() {
        let mut s = RangeSet::new();
        s.insert(0..100);
        let gaps = s.complement_within(0..100);
        assert!(gaps.is_empty());
    }

    #[test]
    fn complement_within_partial_coverage() {
        let mut s = RangeSet::new();
        s.insert(10..20);
        s.insert(40..50);
        // bound 0..60 → gaps: 0..10, 20..40, 50..60
        let gaps = s.complement_within(0..60);
        assert_eq!(gaps, vec![0..10, 20..40, 50..60]);
    }

    #[test]
    fn complement_within_clipped_to_bound() {
        let mut s = RangeSet::new();
        s.insert(0..100);
        // bound entirely inside an existing range → no gaps
        assert!(s.complement_within(20..80).is_empty());
        // bound outside → entire bound is a gap
        let mut s2 = RangeSet::new();
        s2.insert(0..10);
        assert_eq!(s2.complement_within(50..60), vec![50..60]);
    }

    #[test]
    fn complement_within_with_adjacency() {
        let mut s = RangeSet::new();
        s.insert(0..10);
        s.insert(20..30);
        // bound exactly hits the boundaries of dirty ranges
        let gaps = s.complement_within(10..20);
        assert_eq!(gaps, vec![10..20]);
    }

    #[test]
    fn clear_resets() {
        let mut s = RangeSet::new();
        s.insert(0..10);
        s.insert(20..30);
        s.clear();
        assert!(s.is_empty());
        assert_eq!(s.total_bytes(), 0);
    }
}
