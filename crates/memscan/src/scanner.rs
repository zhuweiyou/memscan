//! The scanning engine: first scan (CE "First Scan") and rescan (CE "Next Scan").
//!
//! Design notes (matching Cheat Engine's `memscan.pas`):
//!
//! * First scan enumerates committed, readable regions (see `RegionFilter`),
//!   splits each into chunks, reads them with an overlap of `value_len-1` bytes so
//!   values spanning a chunk boundary are still found, and scans in parallel.
//! * Exact integer scans are compiled to a byte pattern and reuse the SIMD
//!   substring matcher — much faster than a per-address compare loop.
//! * Next scan only revisits previously found addresses. Addresses are walked in
//!   ascending order with a 4 KiB page cache so each page is read at most once
//!   (CE groups found addresses per page the same way).
//! * All work is cooperative: [`ScanControl`] exposes atomic progress counters and
//!   a cancel flag checked by every worker.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rayon::prelude::*;

use crate::address::Address;
use crate::backend::{self, Process};
use crate::error::{Error, Result};
use crate::pattern::AobPattern;
use crate::process::ModuleInfo;
use crate::progress::ScanControl;
use crate::region::{AddressRange, MemoryRegion, RegionFilter};
use crate::result::{FoundList, RawMatch};
use crate::types::{ScanOption, StringEncoding, VariableType};
use crate::value::NumericValue;

/// Lowest address scanned by default (CE scans from 0).
pub const DEFAULT_START: usize = 0x0;
/// Highest address scanned by default (56-bit user space).
pub const DEFAULT_STOP: usize = 0x7FFF_FFFF_FFFF;
/// Default read chunk size (4 MiB).
pub const DEFAULT_CHUNK: usize = 4 * 1024 * 1024;

/// A first-scan request.
#[derive(Clone, Debug)]
pub struct FirstScanRequest {
    pub value_type: VariableType,
    pub option: ScanOption,
    /// Primary value text (number, text, or AOB depending on `value_type`).
    pub value: String,
    /// Upper bound for `ValueBetween`.
    pub value2: Option<String>,
    pub signed: bool,
    pub hex: bool,
    pub case_insensitive: bool,
    /// Treat `?` in text as a wildcard (CE-style fuzzy syntax).
    pub wildcard: bool,
    pub encoding: StringEncoding,
    pub start: Address,
    pub stop: Address,
    pub filter: RegionFilter,
    /// Alignment in bytes; `None` uses the type's natural alignment.
    pub align: Option<usize>,
    /// If non-empty, only regions intersecting these ranges are scanned.
    pub module_ranges: Vec<AddressRange>,
    pub max_results: Option<usize>,
    pub chunk_size: usize,
    /// 0 means "use the global rayon pool".
    pub threads: usize,
}

impl Default for FirstScanRequest {
    fn default() -> Self {
        FirstScanRequest {
            value_type: VariableType::String,
            option: ScanOption::ExactValue,
            value: String::new(),
            value2: None,
            signed: false,
            hex: false,
            case_insensitive: true,
            wildcard: true,
            encoding: StringEncoding::Auto,
            start: Address::new(DEFAULT_START),
            stop: Address::new(DEFAULT_STOP),
            filter: RegionFilter::default(),
            align: None,
            module_ranges: Vec::new(),
            max_results: None,
            chunk_size: DEFAULT_CHUNK,
            threads: 0,
        }
    }
}

/// A next-scan (rescan) request.
#[derive(Clone, Debug)]
pub struct NextScanRequest {
    pub option: ScanOption,
    pub value: Option<String>,
    pub value2: Option<String>,
    pub max_results: Option<usize>,
    pub threads: usize,
}

impl Default for NextScanRequest {
    fn default() -> Self {
        NextScanRequest {
            option: ScanOption::Unchanged,
            value: None,
            value2: None,
            max_results: None,
            threads: 0,
        }
    }
}

/// Outcome of a scan.
#[derive(Clone, Debug, Default)]
pub struct ScanSummary {
    pub examined_bytes: u64,
    pub region_count: usize,
    pub chunks: usize,
    pub matches: usize,
    /// Number of results currently tracked after this scan.
    pub total_found: usize,
    pub duration: Duration,
    pub cancelled: bool,
}

/// Persistent scan state (like CE's `TMemScan`): keeps the found list so a next
/// scan can refine it. One `MemScan` corresponds to one attached process.
pub struct MemScan {
    process: Arc<Process>,
    found: FoundList,
    last: Option<LastState>,
}

#[derive(Clone, Copy)]
struct LastState {
    value_type: VariableType,
    signed: bool,
}

impl MemScan {
    /// Attach to a process by pid.
    pub fn attach(pid: u32) -> Result<Self> {
        Ok(MemScan {
            process: Arc::new(backend::open_process(pid)?),
            found: FoundList::new(),
            last: None,
        })
    }

    /// Build from an already-open process handle.
    pub fn from_process(process: Arc<Process>) -> Self {
        MemScan {
            process,
            found: FoundList::new(),
            last: None,
        }
    }

    pub fn pid(&self) -> u32 {
        self.process.pid()
    }

    pub fn process(&self) -> &Process {
        &self.process
    }

    pub fn found(&self) -> &FoundList {
        &self.found
    }

    pub fn result_count(&self) -> usize {
        self.found.len()
    }

    /// Enumerate scannable regions with the given filter (convenience wrapper).
    pub fn regions(&self, filter: &RegionFilter) -> Result<Vec<MemoryRegion>> {
        self.process.regions(
            Address::new(DEFAULT_START),
            Address::new(DEFAULT_STOP),
            filter,
        )
    }

    pub fn modules(&self) -> Result<Vec<ModuleInfo>> {
        self.process.modules()
    }

    /// Run a first scan, replacing the current result set.
    pub fn first_scan(&mut self, req: &FirstScanRequest, ctl: &ScanControl) -> Result<ScanSummary> {
        let started = Instant::now();
        let engine = Engine::build(req)?;
        let align = resolve_alignment(req, &engine);

        let mut regions = self.process.regions(req.start, req.stop, &req.filter)?;
        if !req.module_ranges.is_empty() {
            regions = restrict_regions(regions, &req.module_ranges);
        }
        let region_count = regions.len();

        let overlap = engine.value_len().saturating_sub(1);
        let tasks = build_tasks(&regions, req.chunk_size, overlap);
        let chunks = tasks.len();
        let total: u64 = tasks.iter().map(|t| t.scan_len as u64).sum();
        ctl.set_total(total);

        let limit = req.max_results.unwrap_or(usize::MAX);
        let produced = AtomicUsize::new(0);
        let process: &Process = &self.process;
        let engine_ref = &engine;

        let per_task: Vec<Vec<RawMatch>> = run_in_pool(req.threads, || {
            tasks
                .par_iter()
                .map(|task| scan_chunk(process, engine_ref, task, align, ctl, &produced, limit))
                .collect()
        })?;

        let mut matches: Vec<RawMatch> = per_task.into_iter().flatten().collect();
        matches.sort_unstable_by_key(|m| m.address);
        if matches.len() > limit {
            matches.truncate(limit);
        }

        let count = matches.len();
        self.found = FoundList::from_matches(matches);
        self.last = Some(LastState {
            value_type: req.value_type,
            signed: req.signed,
        });

        Ok(ScanSummary {
            examined_bytes: total,
            region_count,
            chunks,
            matches: count,
            total_found: self.found.len(),
            duration: started.elapsed(),
            cancelled: ctl.is_cancelled(),
        })
    }

    /// Run a next scan, filtering the current result set.
    pub fn next_scan(&mut self, req: &NextScanRequest, ctl: &ScanControl) -> Result<ScanSummary> {
        let started = Instant::now();
        let last = self.last.ok_or_else(|| {
            Error::InvalidRequest("next scan requires a previous first scan".into())
        })?;

        if self.found.is_empty() {
            return Ok(ScanSummary {
                total_found: 0,
                duration: started.elapsed(),
                cancelled: ctl.is_cancelled(),
                ..Default::default()
            });
        }

        let comparison = NextComparison::build(req, last)?;
        let total = self.found.len();
        ctl.set_total(total as u64);

        let entries = self.found.entries();
        let mut kept: Vec<RawMatch> = Vec::new();
        let mut page_base = usize::MAX;
        let mut page = vec![0u8; 0x1000];

        for entry in entries {
            if ctl.is_cancelled() {
                // Keep remaining entries untouched by copying them through.
                kept.push(RawMatch {
                    address: entry.address,
                    data: self.found.value_of(entry).to_vec(),
                });
                continue;
            }
            let addr = entry.address.0;
            let this_page = addr & !0xFFF;
            if this_page != page_base {
                page_base = this_page;
                page.resize(0x1000, 0);
                let got = self
                    .process
                    .read_memory(Address::new(this_page), &mut page)
                    .unwrap_or(0);
                page.truncate(got);
            }
            let off = addr - this_page;
            let len = entry.value_len as usize;
            ctl.add_examined(1);
            if off + len > page.len() {
                // Page unreadable / entry gone: drop it (CE behaves the same).
                continue;
            }
            let new_bytes = &page[off..off + len];
            if comparison.keep(new_bytes, self.found.value_of(entry)) {
                kept.push(RawMatch {
                    address: entry.address,
                    data: new_bytes.to_vec(),
                });
            }
        }

        let limit = req.max_results.unwrap_or(usize::MAX);
        if kept.len() > limit {
            kept.truncate(limit);
        }
        let count = kept.len();
        self.found = FoundList::from_matches(kept);

        Ok(ScanSummary {
            examined_bytes: total as u64,
            region_count: 0,
            chunks: 0,
            matches: count,
            total_found: self.found.len(),
            duration: started.elapsed(),
            cancelled: ctl.is_cancelled(),
        })
    }
}

// ---------------------------------------------------------------------------
// Engine description
// ---------------------------------------------------------------------------

enum Engine {
    /// Byte-pattern search (AOB / string / exact integer).
    Pattern {
        pattern: AobPattern,
        store_len: usize,
    },
    /// Per-address numeric comparison.
    Numeric {
        ty: VariableType,
        signed: bool,
        option: ScanOption,
        target: NumericValue,
        target2: Option<NumericValue>,
        size: usize,
    },
}

impl Engine {
    fn value_len(&self) -> usize {
        match self {
            Engine::Pattern { store_len, .. } => *store_len,
            Engine::Numeric { size, .. } => *size,
        }
    }

    fn build(req: &FirstScanRequest) -> Result<Self> {
        match req.value_type {
            VariableType::ByteArray => {
                ensure_option(req.option, ScanOption::ExactValue, "AOB")?;
                // CE's `vtByteArray` is a raw byte pattern: case-insensitivity only
                // applies to text scans. Folding hex bytes here would make e.g. 0x44
                // match 0x64 and produce spurious hits, so AOB is always exact.
                let pattern = AobPattern::parse(&req.value, false)?;
                Ok(Engine::Pattern {
                    store_len: pattern.len(),
                    pattern,
                })
            }
            VariableType::String | VariableType::UnicodeString => {
                ensure_option(req.option, ScanOption::ExactValue, "string")?;
                let encoding = resolve_encoding(req.encoding, req.value_type);
                let pattern = AobPattern::from_text(
                    &req.value,
                    encoding,
                    req.case_insensitive,
                    req.wildcard,
                )?;
                Ok(Engine::Pattern {
                    store_len: pattern.len(),
                    pattern,
                })
            }
            ty => {
                let size = ty
                    .scalar_size()
                    .ok_or_else(|| Error::InvalidRequest(format!("{ty} has no fixed size")))?;
                // Exact integer => compile to a byte pattern (fast path).
                if req.option == ScanOption::ExactValue && !ty.is_float() {
                    let target = NumericValue::parse(&req.value, ty, req.signed, req.hex)?;
                    let bytes = target
                        .to_le_bytes(ty)
                        .ok_or_else(|| Error::InvalidValue("value does not fit type".into()))?;
                    return Ok(Engine::Pattern {
                        pattern: AobPattern::from_bytes_exact(&bytes),
                        store_len: size,
                    });
                }
                let target = if req.option == ScanOption::UnknownValue {
                    NumericValue::Signed(0)
                } else {
                    NumericValue::parse(&req.value, ty, req.signed, req.hex)?
                };
                let target2 = match req.option {
                    ScanOption::ValueBetween => {
                        let t2 = req.value2.as_deref().ok_or_else(|| {
                            Error::InvalidValue("between needs an upper bound".into())
                        })?;
                        Some(NumericValue::parse(t2, ty, req.signed, req.hex)?)
                    }
                    _ => None,
                };
                Ok(Engine::Numeric {
                    ty,
                    signed: req.signed,
                    option: req.option,
                    target,
                    target2,
                    size,
                })
            }
        }
    }
}

fn ensure_option(actual: ScanOption, expected: ScanOption, what: &str) -> Result<()> {
    if actual != expected {
        return Err(Error::InvalidRequest(format!(
            "{what} scans only support the 'exact' option, got '{actual}'"
        )));
    }
    Ok(())
}

fn resolve_encoding(enc: StringEncoding, ty: VariableType) -> StringEncoding {
    match enc {
        StringEncoding::Auto => {
            if ty == VariableType::UnicodeString {
                StringEncoding::Utf16Le
            } else {
                StringEncoding::Utf8
            }
        }
        other => other,
    }
}

fn resolve_alignment(req: &FirstScanRequest, engine: &Engine) -> usize {
    if let Some(a) = req.align {
        return a.max(1);
    }
    match engine {
        Engine::Numeric { option, ty, .. } => {
            if *option == ScanOption::UnknownValue {
                1
            } else {
                ty.natural_alignment()
            }
        }
        Engine::Pattern { .. } => {
            // Exact integer compiled to a pattern keeps the numeric alignment;
            // strings / AOB scan every offset.
            if req.value_type.is_numeric() && req.option == ScanOption::ExactValue {
                req.value_type.natural_alignment()
            } else {
                1
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Chunking & worker
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct ChunkTask {
    base: Address,
    scan_len: usize,
    read_len: usize,
}

fn build_tasks(regions: &[MemoryRegion], chunk_size: usize, overlap: usize) -> Vec<ChunkTask> {
    let chunk = chunk_size.max(0x1000);
    let mut tasks = Vec::new();
    for r in regions {
        let mut pos = 0usize;
        while pos < r.size {
            let scan_len = chunk.min(r.size - pos);
            let read_len = (scan_len + overlap).min(r.size - pos);
            tasks.push(ChunkTask {
                base: r.base + pos,
                scan_len,
                read_len,
            });
            pos += scan_len;
        }
    }
    tasks
}

fn scan_chunk(
    process: &Process,
    engine: &Engine,
    task: &ChunkTask,
    align: usize,
    ctl: &ScanControl,
    produced: &AtomicUsize,
    limit: usize,
) -> Vec<RawMatch> {
    if ctl.is_cancelled() {
        return Vec::new();
    }
    let mut buffer = vec![0u8; task.read_len];
    let got = process.read_memory(task.base, &mut buffer).unwrap_or(0);
    if got == 0 {
        ctl.add_examined(task.scan_len as u64);
        return Vec::new();
    }
    buffer.truncate(got);

    let mut out = Vec::new();
    match engine {
        Engine::Pattern { pattern, store_len } => {
            let offsets = pattern.find_all(&buffer, task.base, align);
            for off in offsets {
                if off >= task.scan_len || off + store_len > got {
                    continue;
                }
                if produced.load(Ordering::Relaxed) >= limit {
                    break;
                }
                produced.fetch_add(1, Ordering::Relaxed);
                out.push(RawMatch {
                    address: task.base + off,
                    data: buffer[off..off + store_len].to_vec(),
                });
            }
        }
        Engine::Numeric {
            ty,
            signed,
            option,
            target,
            target2,
            size,
        } => {
            let step = align.max(1);
            let start_off = if step <= 1 {
                0
            } else {
                (step - (task.base.0 % step)) % step
            };
            let mut off = start_off;
            while off < task.scan_len && off + size <= got {
                if ctl.is_cancelled() {
                    break;
                }
                if let Some(val) = NumericValue::read(&buffer[off..off + size], *ty, *signed) {
                    if numeric_first_match(*option, &val, target, target2.as_ref()) {
                        if produced.load(Ordering::Relaxed) >= limit {
                            break;
                        }
                        produced.fetch_add(1, Ordering::Relaxed);
                        out.push(RawMatch {
                            address: task.base + off,
                            data: buffer[off..off + size].to_vec(),
                        });
                    }
                }
                off += step;
            }
        }
    }
    ctl.add_examined(task.scan_len as u64);
    out
}

fn numeric_first_match(
    option: ScanOption,
    value: &NumericValue,
    target: &NumericValue,
    target2: Option<&NumericValue>,
) -> bool {
    use std::cmp::Ordering;
    match option {
        ScanOption::UnknownValue => true,
        ScanOption::ExactValue => value.compare(target) == Some(Ordering::Equal),
        ScanOption::BiggerThan => value.compare(target) == Some(Ordering::Greater),
        ScanOption::SmallerThan => value.compare(target) == Some(Ordering::Less),
        ScanOption::ValueBetween => {
            let Some(t2) = target2 else {
                return false;
            };
            let (lo, hi) = if target.compare(t2) == Some(Ordering::Greater) {
                (t2, target)
            } else {
                (target, t2)
            };
            matches!(
                value.compare(lo),
                Some(Ordering::Greater) | Some(Ordering::Equal)
            ) && matches!(
                value.compare(hi),
                Some(Ordering::Less) | Some(Ordering::Equal)
            )
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Next-scan comparison
// ---------------------------------------------------------------------------

enum NextComparison {
    Bytes {
        changed: bool, // true = changed, false = unchanged
    },
    Numeric {
        ty: VariableType,
        signed: bool,
        option: ScanOption,
        target: Option<NumericValue>,
        target2: Option<NumericValue>,
    },
}

impl NextComparison {
    fn build(req: &NextScanRequest, last: LastState) -> Result<Self> {
        let ty = last.value_type;
        if ty.is_string_like() || ty == VariableType::ByteArray {
            return match req.option {
                ScanOption::Changed => Ok(NextComparison::Bytes { changed: true }),
                ScanOption::Unchanged => Ok(NextComparison::Bytes { changed: false }),
                other => Err(Error::InvalidRequest(format!(
                    "string/AOB next scan supports only changed/unchanged, got '{other}'"
                ))),
            };
        }
        let parse = |text: Option<&str>| -> Result<Option<NumericValue>> {
            match text {
                Some(t) => Ok(Some(NumericValue::parse(t, ty, last.signed, false)?)),
                None => Ok(None),
            }
        };
        let needs_value = matches!(
            req.option,
            ScanOption::ExactValue
                | ScanOption::BiggerThan
                | ScanOption::SmallerThan
                | ScanOption::ValueBetween
                | ScanOption::IncreasedValueBy
                | ScanOption::DecreasedValueBy
        );
        if needs_value && req.value.is_none() {
            return Err(Error::InvalidValue(format!(
                "option '{}' requires a value",
                req.option
            )));
        }
        let target = parse(req.value.as_deref())?;
        let target2 = if req.option == ScanOption::ValueBetween {
            let t2 = req
                .value2
                .as_deref()
                .ok_or_else(|| Error::InvalidValue("between needs an upper bound".into()))?;
            Some(NumericValue::parse(t2, ty, last.signed, false)?)
        } else {
            None
        };
        Ok(NextComparison::Numeric {
            ty,
            signed: last.signed,
            option: req.option,
            target,
            target2,
        })
    }

    fn keep(&self, new_bytes: &[u8], old_bytes: &[u8]) -> bool {
        use std::cmp::Ordering;
        match self {
            NextComparison::Bytes { changed } => {
                let is_changed = new_bytes != old_bytes;
                is_changed == *changed
            }
            NextComparison::Numeric {
                ty,
                signed,
                option,
                target,
                target2,
            } => {
                let new = match NumericValue::read(new_bytes, *ty, *signed) {
                    Some(v) => v,
                    None => return false,
                };
                let old = NumericValue::read(old_bytes, *ty, *signed);
                match option {
                    ScanOption::Changed => match old {
                        Some(o) => new.compare(&o) != Some(Ordering::Equal),
                        None => true,
                    },
                    ScanOption::Unchanged => match old {
                        Some(o) => new.compare(&o) == Some(Ordering::Equal),
                        None => false,
                    },
                    ScanOption::IncreasedValue => match old {
                        Some(o) => new.compare(&o) == Some(Ordering::Greater),
                        None => false,
                    },
                    ScanOption::DecreasedValue => match old {
                        Some(o) => new.compare(&o) == Some(Ordering::Less),
                        None => false,
                    },
                    ScanOption::IncreasedValueBy => match (old, target) {
                        (Some(o), Some(t)) => new
                            .difference(&o)
                            .map(|d| {
                                t.as_f64() as i128 == d
                                    || NumericValue::Signed(d).as_f64() == t.as_f64()
                            })
                            .unwrap_or(false),
                        _ => false,
                    },
                    ScanOption::DecreasedValueBy => match (old, target) {
                        (Some(o), Some(t)) => o
                            .difference(&new)
                            .map(|d| {
                                t.as_f64() as i128 == d
                                    || NumericValue::Signed(d).as_f64() == t.as_f64()
                            })
                            .unwrap_or(false),
                        _ => false,
                    },
                    ScanOption::ExactValue => match target {
                        Some(t) => new.compare(t) == Some(Ordering::Equal),
                        None => false,
                    },
                    ScanOption::BiggerThan => match target {
                        Some(t) => new.compare(t) == Some(Ordering::Greater),
                        None => false,
                    },
                    ScanOption::SmallerThan => match target {
                        Some(t) => new.compare(t) == Some(Ordering::Less),
                        None => false,
                    },
                    ScanOption::ValueBetween => match (target, target2) {
                        (Some(t1), Some(t2)) => {
                            let (lo, hi) = if t1.compare(t2) == Some(Ordering::Greater) {
                                (t2, t1)
                            } else {
                                (t1, t2)
                            };
                            matches!(
                                new.compare(lo),
                                Some(Ordering::Greater) | Some(Ordering::Equal)
                            ) && matches!(
                                new.compare(hi),
                                Some(Ordering::Less) | Some(Ordering::Equal)
                            )
                        }
                        _ => false,
                    },
                    ScanOption::UnknownValue => true,
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn restrict_regions(regions: Vec<MemoryRegion>, ranges: &[AddressRange]) -> Vec<MemoryRegion> {
    let mut out = Vec::new();
    for r in regions {
        let r_end = r.end();
        for range in ranges {
            let s = r.base.0.max(range.base.0);
            let e = r_end.0.min(range.end().0);
            if e > s {
                out.push(MemoryRegion {
                    base: Address::new(s),
                    size: e - s,
                    protect: r.protect,
                    state: r.state,
                    mem_type: r.mem_type,
                });
            }
        }
    }
    out.sort_unstable_by_key(|r| r.base.0);
    out
}

fn run_in_pool<T, F>(threads: usize, f: F) -> Result<T>
where
    F: FnOnce() -> T + Send,
    T: Send,
{
    if threads > 0 {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .map_err(|e| Error::other(format!("failed to build thread pool: {e}")))?;
        Ok(pool.install(f))
    } else {
        Ok(f())
    }
}
