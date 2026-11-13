//! # wxmemscan::wechat
//!
//! Thin WeChat-specific layer on top of [`memscan`]. Everything here is about
//! *locating* WeChat-related processes; all actual memory searching lives in
//! `memscan` and works on any process.
//!
//! Process identification is **platform abstracted** via [`WeChatClassifier`]:
//! Windows matches `*.exe` image names, macOS matches app bundles / helpful
//! Chromium-style helper processes (which are not `.exe`), and other platforms
//! fall back to a generic substring matcher. [`current_classifier`] picks the
//! right one at compile time.
//!
//! Covers classic WeChat and the newer Weixin 4.x client, plus the mini-program and
//! built-in browser helper processes.

mod platform;

use memscan::{enumerate_processes, AddressRange, ModuleInfo, ProcessInfo, Result};

/// Which WeChat client a process belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum WeChatKind {
    /// Mini-program / app-service host (where mini programs actually run).
    AppEx,
    /// Embedded web view / browser helper.
    Browser,
    /// Main WeChat client (3.x on Windows, `WeChat.app` on macOS).
    Main,
    /// Weixin 4.x main client.
    Weixin,
}

impl WeChatKind {
    /// Human readable label (Chinese, matching the tool's audience).
    pub const fn label(self) -> &'static str {
        match self {
            WeChatKind::AppEx => "小程序进程",
            WeChatKind::Browser => "内置浏览器",
            WeChatKind::Main => "微信主程序",
            WeChatKind::Weixin => "微信4.0主程序",
        }
    }

    /// Whether this process is the one that hosts mini-program logic.
    pub const fn is_mini_program_host(self) -> bool {
        matches!(self, WeChatKind::AppEx)
    }
}

/// How to recognize WeChat processes and modules on a given platform.
pub trait WeChatClassifier: Send + Sync {
    /// Platform identifier, e.g. `"windows"`, `"macos"`, `"generic"`.
    fn platform(&self) -> &'static str;

    /// Classify a process by executable name and (optional) image path.
    fn classify(&self, name: &str, path: Option<&str>) -> Option<WeChatKind>;

    /// Whether a loaded module / dylib name looks WeChat-related.
    fn classify_module(&self, module_name: &str) -> bool;

    /// Sample process names this platform looks for (for help / UI).
    fn hints(&self) -> &'static [&'static str];
}

/// The classifier for the current platform (selected at compile time).
pub fn current_classifier() -> &'static dyn WeChatClassifier {
    platform::current_classifier()
}

/// Classify an executable name with the current platform's rules.
pub fn classify(process_name: &str) -> Option<WeChatKind> {
    current_classifier().classify(process_name, None)
}

/// Whether a process name belongs to any WeChat client on this platform.
pub fn is_wechat_process(process_name: &str) -> bool {
    classify(process_name).is_some()
}

/// Whether a module name looks WeChat-related on this platform.
pub fn is_wechat_module_name(module_name: &str) -> bool {
    current_classifier().classify_module(module_name)
}

/// A discovered WeChat process.
#[derive(Clone, Debug)]
pub struct WechatProcess {
    pub pid: u32,
    pub name: String,
    pub kind: WeChatKind,
    pub path: Option<String>,
    /// Working set size in bytes (rough physical memory in use).
    pub working_set: u64,
    /// Private / commit bytes.
    pub private_bytes: u64,
    /// Cumulative CPU time (user + kernel) in 100 ns units.
    pub cpu_time_100ns: u64,
}

impl WechatProcess {
    pub fn label(&self) -> &'static str {
        self.kind.label()
    }
}

impl std::fmt::Display for WechatProcess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {} ({})", self.pid, self.name, self.kind.label())
    }
}

fn from_info(info: ProcessInfo, clf: &dyn WeChatClassifier) -> Option<WechatProcess> {
    let kind = clf.classify(&info.name, info.path.as_deref())?;
    Some(WechatProcess {
        pid: info.pid,
        name: info.name,
        kind,
        path: info.path,
        working_set: info.working_set,
        private_bytes: info.private_bytes,
        cpu_time_100ns: info.cpu_time_100ns,
    })
}

/// Sort processes so the most resource-heavy instance comes first.
///
/// The instance actually being used (active mini-program / chat window) is almost
/// always the one using the most memory, so working set is the primary key; commit
/// bytes and cumulative CPU time break ties.
pub fn sort_by_usage(processes: &mut [WechatProcess]) {
    processes.sort_by(|a, b| {
        b.working_set
            .cmp(&a.working_set)
            .then(b.private_bytes.cmp(&a.private_bytes))
            .then(b.cpu_time_100ns.cmp(&a.cpu_time_100ns))
    });
}

/// Return the process using the most memory (the default search target).
pub fn heaviest(processes: &[WechatProcess]) -> Option<&WechatProcess> {
    processes.iter().max_by(|a, b| {
        a.working_set
            .cmp(&b.working_set)
            .then(a.private_bytes.cmp(&b.private_bytes))
            .then(a.cpu_time_100ns.cmp(&b.cpu_time_100ns))
    })
}

/// Convenience: all WeChat processes already sorted by resource usage (descending).
pub fn find_wechat_processes_by_usage() -> Result<Vec<WechatProcess>> {
    let mut list = find_wechat_processes()?;
    sort_by_usage(&mut list);
    Ok(list)
}

/// Find every running WeChat-related process across all client variants.
pub fn find_wechat_processes() -> Result<Vec<WechatProcess>> {
    let clf = current_classifier();
    let all = enumerate_processes()?;
    Ok(all
        .into_iter()
        .filter_map(|info| from_info(info, clf))
        .collect())
}

/// Find running processes of one specific WeChat kind.
pub fn find_by_kind(kind: WeChatKind) -> Result<Vec<WechatProcess>> {
    Ok(find_wechat_processes()?
        .into_iter()
        .filter(|p| p.kind == kind)
        .collect())
}

/// Find only the mini-program host process(es).
pub fn find_mini_program_processes() -> Result<Vec<WechatProcess>> {
    find_by_kind(WeChatKind::AppEx)
}

/// Build address ranges from the WeChat-related modules of a process.
///
/// This is *optional* scoping (useful to restrict a scan to a client image's
/// code/rodata). Runtime strings usually live in anonymous private regions, so the
/// default scan should not be module-limited — prefer `RegionFilter::writable`.
pub fn wechat_module_ranges(modules: &[ModuleInfo]) -> Vec<AddressRange> {
    let clf = current_classifier();
    modules
        .iter()
        .filter(|m| clf.classify_module(&m.name))
        .map(|m| AddressRange::new(m.base, m.size))
        .collect()
}
