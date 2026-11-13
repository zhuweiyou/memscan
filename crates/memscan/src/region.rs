//! Memory region description and CE-style region filtering.
//!
//! The numeric constants mirror the Windows `PAGE_*`, `MEM_*` values so the same
//! [`RegionFilter`] logic can be reused for any backend that maps its native
//! protections onto these values in `backend.rs`.

use std::fmt;

use crate::address::Address;
use crate::types::TriState;

// Page protection flags (Windows values).
pub const PAGE_NOACCESS: u32 = 0x01;
pub const PAGE_READONLY: u32 = 0x02;
pub const PAGE_READWRITE: u32 = 0x04;
pub const PAGE_WRITECOPY: u32 = 0x08;
pub const PAGE_EXECUTE: u32 = 0x10;
pub const PAGE_EXECUTE_READ: u32 = 0x20;
pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;
pub const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;
pub const PAGE_GUARD: u32 = 0x100;
pub const PAGE_NOCACHE: u32 = 0x200;
pub const PAGE_WRITECOMBINE: u32 = 0x400;

// Allocation state.
pub const MEM_COMMIT: u32 = 0x1000;
pub const MEM_RESERVE: u32 = 0x2000;
pub const MEM_FREE: u32 = 0x10000;

// Allocation type.
pub const MEM_PRIVATE: u32 = 0x20000;
pub const MEM_MAPPED: u32 = 0x40000;
pub const MEM_IMAGE: u32 = 0x1000000;

/// Backing kind of a committed region.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegionKind {
    Private,
    Image,
    Mapped,
    Unknown,
}

/// A committed region of a target process address space.
#[derive(Clone, Debug)]
pub struct MemoryRegion {
    pub base: Address,
    pub size: usize,
    /// Raw `Protect` flags.
    pub protect: u32,
    /// Raw `State` flags.
    pub state: u32,
    /// Raw allocation `Type` flags.
    pub mem_type: u32,
}

impl MemoryRegion {
    #[inline]
    pub fn end(&self) -> Address {
        Address(self.base.0.saturating_add(self.size))
    }

    pub fn kind(&self) -> RegionKind {
        if self.mem_type & MEM_IMAGE != 0 {
            RegionKind::Image
        } else if self.mem_type & MEM_MAPPED != 0 {
            RegionKind::Mapped
        } else if self.mem_type & MEM_PRIVATE != 0 {
            RegionKind::Private
        } else {
            RegionKind::Unknown
        }
    }

    #[inline]
    pub fn is_committed(&self) -> bool {
        self.state & MEM_COMMIT != 0
    }

    #[inline]
    pub fn has_guard(&self) -> bool {
        self.protect & PAGE_GUARD != 0
    }

    #[inline]
    pub fn is_noaccess(&self) -> bool {
        self.protect & PAGE_NOACCESS != 0
    }

    #[inline]
    pub fn is_readable(&self) -> bool {
        self.protect
            & (PAGE_READONLY
                | PAGE_READWRITE
                | PAGE_EXECUTE_READ
                | PAGE_EXECUTE_READWRITE
                | PAGE_WRITECOPY
                | PAGE_EXECUTE_WRITECOPY)
            != 0
    }

    #[inline]
    pub fn is_writable(&self) -> bool {
        self.protect
            & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)
            != 0
    }

    #[inline]
    pub fn is_executable(&self) -> bool {
        self.protect
            & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)
            != 0
    }

    #[inline]
    pub fn is_copy_on_write(&self) -> bool {
        self.protect & (PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY) != 0
    }

    pub fn protection_string(&self) -> String {
        let mut flags = Vec::new();
        let p = self.protect;
        if p & PAGE_GUARD != 0 {
            flags.push("G");
        }
        if p & PAGE_NOACCESS != 0 {
            flags.push("NA");
        }
        if p & PAGE_EXECUTE_WRITECOPY != 0 {
            flags.push("Ewc");
        } else if p & PAGE_EXECUTE_READWRITE != 0 {
            flags.push("Erw");
        } else if p & PAGE_EXECUTE_READ != 0 {
            flags.push("Er");
        } else if p & PAGE_EXECUTE != 0 {
            flags.push("E");
        } else if p & PAGE_READWRITE != 0 {
            flags.push("Rw");
        } else if p & PAGE_WRITECOPY != 0 {
            flags.push("Wc");
        } else if p & PAGE_READONLY != 0 {
            flags.push("R");
        }
        if flags.is_empty() {
            format!("0x{:X}", p)
        } else {
            flags.join("|")
        }
    }
}

impl fmt::Display for MemoryRegion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} - {} size={} protect={} type={:?}",
            self.base,
            self.end(),
            self.size,
            self.protection_string(),
            self.kind()
        )
    }
}

/// CE-style memory region selection.
#[derive(Clone, Debug)]
pub struct RegionFilter {
    /// Include only writable regions / exclude writable regions / don't care.
    pub writable: TriState,
    /// Same for executable regions.
    pub executable: TriState,
    /// Same for copy-on-write regions.
    pub copy_on_write: TriState,
    pub include_private: bool,
    pub include_image: bool,
    pub include_mapped: bool,
    /// Skip guard pages (default true, CE always does).
    pub skip_guard: bool,
    /// Skip PAGE_NOACCESS regions (default true, CE always does).
    pub skip_noaccess: bool,
    /// Ignore PAGE_NOCACHE / PAGE_WRITECOMBINE allocations (CE option, default true).
    pub skip_special_cache: bool,
}

impl Default for RegionFilter {
    fn default() -> Self {
        RegionFilter {
            writable: TriState::DontCare,
            executable: TriState::DontCare,
            copy_on_write: TriState::DontCare,
            include_private: true,
            include_image: true,
            include_mapped: true,
            skip_guard: true,
            skip_noaccess: true,
            // Inclusive by default: don't drop PAGE_NOCACHE/WRITECOMBINE mappings
            // unless the caller explicitly asks to.
            skip_special_cache: false,
        }
    }
}

impl RegionFilter {
    /// Whether `region` should be scanned, replicating CE's validity checks.
    pub fn matches(&self, region: &MemoryRegion) -> bool {
        if !region.is_committed() {
            return false;
        }
        if self.skip_guard && region.has_guard() {
            return false;
        }
        if self.skip_noaccess && region.is_noaccess() {
            return false;
        }
        match region.kind() {
            RegionKind::Private if !self.include_private => return false,
            RegionKind::Image if !self.include_image => return false,
            RegionKind::Mapped if !self.include_mapped => return false,
            _ => {}
        }
        if self.skip_special_cache && region.protect & (PAGE_NOCACHE | PAGE_WRITECOMBINE) != 0 {
            return false;
        }
        match self.writable {
            TriState::Include if !region.is_writable() => return false,
            TriState::Exclude if region.is_writable() => return false,
            _ => {}
        }
        match self.executable {
            TriState::Include if !region.is_executable() => return false,
            TriState::Exclude if region.is_executable() => return false,
            _ => {}
        }
        match self.copy_on_write {
            TriState::Include if !region.is_copy_on_write() => return false,
            TriState::Exclude if region.is_copy_on_write() => return false,
            _ => {}
        }
        true
    }
}

/// A half-open module address range `[base, base+size)`.
#[derive(Clone, Copy, Debug)]
pub struct AddressRange {
    pub base: Address,
    pub size: usize,
}

impl AddressRange {
    pub fn new(base: Address, size: usize) -> Self {
        AddressRange { base, size }
    }
    pub fn end(&self) -> Address {
        Address(self.base.0.saturating_add(self.size))
    }
    pub fn contains(&self, addr: Address) -> bool {
        addr.0 >= self.base.0 && addr.0 < self.end().0
    }
    pub fn overlaps(&self, start: Address, end: Address) -> bool {
        self.base.0 < end.0 && start.0 < self.end().0
    }
}
