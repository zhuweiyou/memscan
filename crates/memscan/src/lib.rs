//! # memscan
//!
//! A generic, reusable process-memory scanner modeled on Cheat Engine's
//! `memscan.pas`. It knows nothing about WeChat — it can scan any process you can
//! open. The `wxmemscan` package is a complete example that builds on this crate:
//! it locates WeChat processes and drives the scanner from a GUI.
//!
//! Capabilities:
//! * CE-style value types: byte/word/dword/qword/float/double, ANSI/UTF-8 string,
//!   UTF-16LE wide string and AOB byte patterns with nibble wildcards.
//! * First scan + next scan with CE's comparison options (exact, between, bigger,
//!   smaller, changed, unchanged, increased/decreased [by]).
//! * Cross-platform region enumeration (via `proc-maps`) with CE's writable/
//!   executable/copy-on-write/private/image/mapped filters.
//! * Chunked reads with boundary overlap and page-wise fallback, parallel across
//!   chunks with rayon, cooperative cancellation and atomic progress counters.
//!
//! Platform support: Windows, macOS and Linux, implemented on top of
//! `process-memory` (read/write) + `proc-maps` (regions) + `sysinfo` (processes).
//! There is a single cross-platform backend (`backend.rs`), not a per-OS trait.
//!
//! ```
//! use memscan::{Address, FirstScanRequest, MemScan, ScanControl, VariableType};
//!
//! # fn run() -> memscan::Result<()> {
//! // Scan the current process for a known token.
//! let mut scan = MemScan::attach(std::process::id())?;
//! let mut req = FirstScanRequest::default();
//! req.value_type = VariableType::String;
//! req.value = "needle".to_string();
//! let summary = scan.first_scan(&req, &ScanControl::new())?;
//! println!("{} matches", summary.matches);
//! # Ok(()) }
//! ```

pub mod address;
pub mod api;
pub mod error;
pub mod pattern;
pub mod process;
pub mod progress;
pub mod region;
pub mod result;
pub mod scanner;
pub mod types;
pub mod value;

pub use address::Address;
pub use api::{
    find_processes_by_name, resolve_pid, scan_text_by_name, scan_text_by_name_or_pid,
    scan_text_by_pid, scan_text_in_heaviest, InstancePolicy, TextMatch, TextScanOptions,
};
pub use error::{Error, Result};
pub use pattern::AobPattern;
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
mod backend;

#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
pub use backend::{enumerate_processes, open_process, Process};

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
compile_error!("memscan currently supports Windows, macOS and Linux");
pub use process::{ModuleInfo, ProcessInfo};
pub use progress::{ScanControl, ScanProgress};
pub use region::{
    AddressRange, MemoryRegion, RegionFilter, RegionKind, MEM_COMMIT, MEM_IMAGE, MEM_MAPPED,
    MEM_PRIVATE, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
    PAGE_GUARD, PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
};
pub use result::{FoundEntry, FoundList, RawMatch};
pub use scanner::{
    FirstScanRequest, MemScan, NextScanRequest, ScanSummary, DEFAULT_CHUNK, DEFAULT_START,
    DEFAULT_STOP,
};
pub use types::{
    FastScanMethod, RoundingType, ScanOption, ScanType, StringEncoding, TriState, VariableType,
};
pub use value::NumericValue;
