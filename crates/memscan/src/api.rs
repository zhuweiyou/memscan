//! High-level convenience API for one-shot text searches.
//!
//! If you don't want to assemble [`FirstScanRequest`] / [`MemScan`] yourself, use
//! these helpers. They are completely generic (any process) and support the
//! CE-style fuzzy syntax (`?` wildcards).
//!
//! ```no_run
//! use memscan::api::{scan_text_by_name_or_pid, TextScanOptions};
//!
//! # fn main() -> memscan::Result<()> {
//! // Fuzzy search "we?ha?" in the process whose name contains "WeChatAppEx".
//! let hits = scan_text_by_name_or_pid("WeChatAppEx", "we?ha?", &TextScanOptions::default())?;
//! for m in hits.iter().take(10) {
//!     println!("[{}] {} {:?}", m.pid, m.address, String::from_utf8_lossy(&m.data));
//! }
//! # Ok(()) }
//! ```

use crate::address::Address;
use crate::backend::enumerate_processes;
use crate::error::{Error, Result};
use crate::process::ProcessInfo;
use crate::progress::ScanControl;
use crate::scanner::{FirstScanRequest, MemScan};
use crate::types::{StringEncoding, TriState, VariableType};

/// Which process instance(s) to scan when a name matches several processes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum InstancePolicy {
    /// Scan only the first matching process (enumeration order).
    First,
    /// Scan only the process using the most memory (the actively used one).
    Heaviest,
    /// Scan every matching process (default; results merged, each carries its pid).
    #[default]
    All,
}

/// Options for a one-shot text scan.
#[derive(Clone, Debug)]
pub struct TextScanOptions {
    /// How to handle multiple processes sharing a name.
    pub instance_policy: InstancePolicy,
    /// Case-insensitive ASCII matching (default `true`).
    pub case_insensitive: bool,
    /// Treat `?` in the pattern as a single-character wildcard (default `true`).
    pub wildcard: bool,
    /// Text encoding. `Auto` = UTF-8/ANSI for a `String` scan (the common case).
    pub encoding: StringEncoding,
    /// Only scan writable regions. Default `false` (scan all readable regions).
    pub writable_only: bool,
    /// Optional cap on returned matches (per process).
    pub max_results: Option<usize>,
    /// Worker threads; `0` = auto.
    pub threads: usize,
}

impl Default for TextScanOptions {
    fn default() -> Self {
        TextScanOptions {
            instance_policy: InstancePolicy::All,
            case_insensitive: true,
            wildcard: true,
            encoding: StringEncoding::Auto,
            writable_only: false,
            max_results: None,
            threads: 0,
        }
    }
}

/// One text match in a target process.
#[derive(Clone, Debug)]
pub struct TextMatch {
    pub pid: u32,
    pub process: String,
    pub address: Address,
    pub data: Vec<u8>,
}

impl TextMatch {
    /// Best-effort UTF-8 lossy preview of the matched bytes.
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.data).into_owned()
    }
}

/// Find processes whose executable name contains `name` (case-insensitive).
///
/// Matches both `"WeChatAppEx"` and `"WeChatAppEx.exe"` style inputs.
pub fn find_processes_by_name(name: &str) -> Result<Vec<ProcessInfo>> {
    let needle = name.to_ascii_lowercase();
    if needle.is_empty() {
        return Err(Error::InvalidValue("empty process name".into()));
    }
    Ok(enumerate_processes()?
        .into_iter()
        .filter(|p| p.name.to_ascii_lowercase().contains(&needle))
        .collect())
}

/// Scan one specific process (by pid) for a fuzzy text pattern.
pub fn scan_text_by_pid(pid: u32, pattern: &str, opts: &TextScanOptions) -> Result<Vec<TextMatch>> {
    let raw = scan_pid_raw(pid, pattern, opts)?;
    Ok(raw
        .into_iter()
        .map(|(address, data)| TextMatch {
            pid,
            process: String::new(),
            address,
            data,
        })
        .collect())
}

/// Scan every process whose name contains `name` for a fuzzy text pattern.
///
/// Processes that cannot be opened (permission / exited) are skipped silently.
pub fn scan_text_by_name(
    name: &str,
    pattern: &str,
    opts: &TextScanOptions,
) -> Result<Vec<TextMatch>> {
    let mut targets = find_processes_by_name(name)?;
    if targets.is_empty() {
        return Err(Error::ProcessNotFound(name.to_string()));
    }
    apply_policy(&mut targets, opts.instance_policy);
    let mut out = Vec::new();
    for proc in targets {
        match scan_pid_raw(proc.pid, pattern, opts) {
            Ok(hits) => {
                for (address, data) in hits {
                    out.push(TextMatch {
                        pid: proc.pid,
                        process: proc.name.clone(),
                        address,
                        data,
                    });
                }
            }
            // Skip inaccessible processes, but surface real scan errors.
            Err(Error::OpenProcess { .. }) => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(out)
}

/// Scan only the **heaviest** instance among processes whose name contains `name`.
///
/// When several processes share a name (e.g. multiple `WeChatAppEx.exe`), the one
/// using the most memory is usually the actively used instance, so this is the
/// "search just the one I care about" helper.
pub fn scan_text_in_heaviest(
    name: &str,
    pattern: &str,
    opts: &TextScanOptions,
) -> Result<Vec<TextMatch>> {
    let mut opts = opts.clone();
    opts.instance_policy = InstancePolicy::Heaviest;
    scan_text_by_name(name, pattern, &opts)
}

/// Trim `targets` in place according to `policy`.
fn apply_policy(targets: &mut Vec<ProcessInfo>, policy: InstancePolicy) {
    match policy {
        InstancePolicy::All => {}
        InstancePolicy::First => targets.truncate(1),
        InstancePolicy::Heaviest => {
            targets.sort_by(|a, b| b.working_set.cmp(&a.working_set));
            targets.truncate(1);
        }
    }
}

/// Convenience: `spec` may be a numeric PID or a process-name substring.
///
/// * numeric spec -> scan that single PID.
/// * name spec    -> scan **all** processes whose name contains it (results merged,
///   each [`TextMatch`] carries its `pid`, so you can tell instances apart). Use
///   [`scan_text_in_heaviest`] to restrict to the largest instance.
pub fn scan_text_by_name_or_pid(
    spec: &str,
    pattern: &str,
    opts: &TextScanOptions,
) -> Result<Vec<TextMatch>> {
    let spec = spec.trim();
    if let Ok(pid) = spec.parse::<u32>() {
        scan_text_by_pid(pid, pattern, opts)
    } else {
        scan_text_by_name(spec, pattern, opts)
    }
}

/// Return the pid of the single "most likely" process for `spec` (numeric pid or
/// name). When several processes match a name, the one with the largest working
/// set is chosen (the actively used instance).
pub fn resolve_pid(spec: &str) -> Result<u32> {
    let spec = spec.trim();
    if let Ok(pid) = spec.parse::<u32>() {
        return Ok(pid);
    }
    let mut matches = find_processes_by_name(spec)?;
    if matches.is_empty() {
        return Err(Error::ProcessNotFound(spec.to_string()));
    }
    matches.sort_by(|a, b| b.working_set.cmp(&a.working_set));
    Ok(matches[0].pid)
}

fn scan_pid_raw(
    pid: u32,
    pattern: &str,
    opts: &TextScanOptions,
) -> Result<Vec<(Address, Vec<u8>)>> {
    if pattern.is_empty() {
        return Err(Error::InvalidValue("empty search pattern".into()));
    }
    let mut scan = MemScan::attach(pid)?;
    let mut req = FirstScanRequest::default();
    req.value_type = VariableType::String;
    req.value = pattern.to_string();
    req.case_insensitive = opts.case_insensitive;
    req.wildcard = opts.wildcard;
    req.encoding = opts.encoding;
    req.max_results = opts.max_results;
    req.threads = opts.threads;
    if opts.writable_only {
        req.filter.writable = TriState::Include;
    }
    let control = ScanControl::new();
    scan.first_scan(&req, &control)?;
    Ok(scan
        .found()
        .iter()
        .map(|(address, data)| (address, data.to_vec()))
        .collect())
}
