//! Process and module metadata (backend independent).

use std::fmt;

use crate::address::Address;

/// A running process discovered by the platform backend.
#[derive(Clone, Debug)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    /// Best-effort full image path; `None` if unavailable (e.g. permission).
    pub path: Option<String>,
    /// Working set size in bytes (rough physical memory in use).
    pub working_set: u64,
    /// Private / commit bytes (pagefile usage).
    pub private_bytes: u64,
    /// Total CPU time (user + kernel) in 100 ns units. Cumulative, not a rate.
    pub cpu_time_100ns: u64,
}

impl fmt::Display for ProcessInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.path {
            Some(p) => write!(f, "[{}] {} ({})", self.pid, self.name, p),
            None => write!(f, "[{}] {}", self.pid, self.name),
        }
    }
}

/// A module (DLL/EXE image) loaded in a target process.
#[derive(Clone, Debug)]
pub struct ModuleInfo {
    pub name: String,
    pub base: Address,
    pub size: usize,
    pub path: Option<String>,
}

impl ModuleInfo {
    pub fn end(&self) -> Address {
        Address(self.base.0.saturating_add(self.size))
    }
    pub fn contains(&self, addr: Address) -> bool {
        addr.0 >= self.base.0 && addr.0 < self.end().0
    }
}

impl fmt::Display for ModuleInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {}-{} size={}",
            self.name,
            self.base,
            self.end(),
            self.size
        )
    }
}
