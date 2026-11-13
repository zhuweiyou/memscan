//! Scan result storage.
//!
//! Results are stored in a compact arena: each entry keeps its address plus a
//! `(offset, len)` pointer into one contiguous value buffer. This avoids one heap
//! allocation per match, which matters when a scan produces millions of hits.

use crate::address::Address;

/// A raw match produced by a scan worker before being merged into a [`FoundList`].
#[derive(Clone, Debug)]
pub struct RawMatch {
    pub address: Address,
    pub data: Vec<u8>,
}

/// One stored result: the address and where its previous value lives in the arena.
#[derive(Clone, Copy, Debug)]
pub struct FoundEntry {
    pub address: Address,
    pub(crate) value_offset: u32,
    pub(crate) value_len: u16,
}

/// A compact list of found addresses plus their previously observed values.
#[derive(Clone, Default, Debug)]
pub struct FoundList {
    entries: Vec<FoundEntry>,
    arena: Vec<u8>,
}

impl FoundList {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_capacity(entries: usize) -> Self {
        FoundList {
            entries: Vec::with_capacity(entries),
            arena: Vec::new(),
        }
    }

    pub fn from_matches(matches: Vec<RawMatch>) -> Self {
        let mut list = FoundList::with_capacity(matches.len());
        for m in matches {
            list.push(m.address, &m.data);
        }
        list
    }

    /// Append a result. Values longer than `u16::MAX` are truncated; the arena is
    /// capped at 4 GiB of stored bytes (practically unreachable for real scans).
    pub fn push(&mut self, address: Address, value: &[u8]) {
        let len = value.len().min(u16::MAX as usize);
        let offset = self.arena.len();
        if offset > u32::MAX as usize {
            // Extremely unlikely; skip rather than corrupt offsets.
            return;
        }
        self.arena.extend_from_slice(&value[..len]);
        self.entries.push(FoundEntry {
            address,
            value_offset: offset as u32,
            value_len: len as u16,
        });
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn clear(&mut self) {
        self.entries.clear();
        self.arena.clear();
    }

    pub fn entries(&self) -> &[FoundEntry] {
        &self.entries
    }

    #[inline]
    pub fn value_of(&self, entry: &FoundEntry) -> &[u8] {
        let start = entry.value_offset as usize;
        let end = start + entry.value_len as usize;
        &self.arena[start..end]
    }

    /// Iterate `(address, previous_value_bytes)` pairs.
    pub fn iter(&self) -> impl Iterator<Item = (Address, &[u8])> + '_ {
        self.entries
            .iter()
            .map(move |e| (e.address, self.value_of(e)))
    }

    pub fn sort_by_address(&mut self) {
        self.entries.sort_unstable_by_key(|e| e.address);
    }

    pub fn total_value_bytes(&self) -> usize {
        self.arena.len()
    }

    /// Keep only the first `n` entries (address order as currently stored).
    pub fn truncate(&mut self, n: usize) {
        self.entries.truncate(n);
    }
}
