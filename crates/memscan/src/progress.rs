//! Scan progress counters and cooperative cancellation.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

/// Shared control object passed to scans. It carries atomic counters that a
/// caller (e.g. the CLI) can poll to render progress, plus a cancel flag.
#[derive(Clone, Default)]
pub struct ScanControl {
    cancel: Arc<AtomicBool>,
    examined_bytes: Arc<AtomicU64>,
    total_bytes: Arc<AtomicU64>,
    match_count: Arc<AtomicU64>,
}

impl ScanControl {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::SeqCst);
    }

    #[inline]
    pub fn is_cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }

    pub fn set_total(&self, total: u64) {
        self.total_bytes.store(total, Ordering::Relaxed);
    }

    #[inline]
    pub fn add_examined(&self, n: u64) {
        self.examined_bytes.fetch_add(n, Ordering::Relaxed);
    }

    #[inline]
    pub fn add_matches(&self, n: u64) {
        self.match_count.fetch_add(n, Ordering::Relaxed);
    }

    pub fn reset(&self) {
        self.cancel.store(false, Ordering::SeqCst);
        self.examined_bytes.store(0, Ordering::Relaxed);
        self.total_bytes.store(0, Ordering::Relaxed);
        self.match_count.store(0, Ordering::Relaxed);
    }

    /// Take a consistent-enough snapshot for display purposes.
    pub fn snapshot(&self) -> ScanProgress {
        ScanProgress {
            examined_bytes: self.examined_bytes.load(Ordering::Relaxed),
            total_bytes: self.total_bytes.load(Ordering::Relaxed),
            matches: self.match_count.load(Ordering::Relaxed),
            cancelled: self.cancel.load(Ordering::Relaxed),
        }
    }
}

/// A point-in-time view of scan progress.
#[derive(Clone, Copy, Debug, Default)]
pub struct ScanProgress {
    pub examined_bytes: u64,
    pub total_bytes: u64,
    pub matches: u64,
    pub cancelled: bool,
}

impl ScanProgress {
    pub fn fraction(&self) -> f64 {
        if self.total_bytes == 0 {
            0.0
        } else {
            (self.examined_bytes as f64 / self.total_bytes as f64).clamp(0.0, 1.0)
        }
    }
}
