//! 跨平台后端：基于成熟 crate，而不是自己维护各平台 FFI。
//!
//! 这是 `memscan` 唯一的后端实现，因此直接放在 crate 根（`backend` 模块），
//! 不再做 `platform` trait 抽象。
//!
//! * 读写内存：`process-memory`（Windows `ReadProcessMemory/WriteProcessMemory`、
//!   macOS `task_for_pid` + `vm_read_overwrite/mach_vm_write`、Linux `process_vm_readv`）。
//! * 内存区域枚举：`proc-maps`（Linux `/proc/pid/maps`、macOS `mach_vm_region`、
//!   Windows `VirtualQueryEx`）。
//! * 进程枚举：`sysinfo`。
//!
//! 这样 `memscan` 只保留平台无关的搜索引擎，平台差异全部交给这些久经验证的库。
//! macOS 依然受系统权限约束：读取其它进程需要 root 或
//! `com.apple.security.cs.debugger` 权限，SIP / 加固进程无法读取。

use std::collections::BTreeMap;

use proc_maps::get_process_maps;
use process_memory::{CopyAddress, Pid, ProcessHandle, PutAddress, TryIntoProcessHandle};

use crate::address::Address;
use crate::error::{Error, Result};
use crate::process::{ModuleInfo, ProcessInfo};
use crate::region::{
    MemoryRegion, RegionFilter, MEM_COMMIT, MEM_IMAGE, MEM_PRIVATE, PAGE_EXECUTE,
    PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE,
};

/// 一个已打开的目标进程句柄。
pub struct Process {
    pid: u32,
    handle: ProcessHandle,
    page_size: usize,
    pointer_size: usize,
    is_64bit: bool,
}

// `ProcessHandle` 在不同平台分别是 Mach 端口名或 Win32 HANDLE；两者都只是进程级句柄，
// 可以从多个线程并发读写（扫描器依赖这一点做并行分块读取）。
unsafe impl Send for Process {}
unsafe impl Sync for Process {}

impl Process {
    /// 打开 `pid`，取得可读写的进程句柄。
    pub fn open(pid: u32) -> Result<Self> {
        if pid == 0 {
            return Err(Error::ProcessNotFound("pid 0（内核任务）无法扫描".into()));
        }
        let handle = (pid as Pid)
            .try_into_process_handle()
            .map_err(|e| Error::OpenProcess {
                pid,
                source: std::io::Error::new(
                    e.kind(),
                    format!(
                        "{e}（macOS 下 task_for_pid 需要 root 或 cs.debugger 权限；\
                         目标也不能是 SIP/加固保护进程）"
                    ),
                ),
            })?;
        Ok(Process {
            pid,
            handle,
            page_size: page_size(),
            pointer_size: std::mem::size_of::<usize>(),
            is_64bit: std::mem::size_of::<usize>() == 8,
        })
    }

    /// 简便读取：返回实际读到的字节（短读不报错）。
    pub fn read_bytes(&self, address: Address, len: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; len];
        let got = self.read_memory(address, &mut buf)?;
        buf.truncate(got);
        Ok(buf)
    }

    /// 简便写入：要求整段写入成功。
    pub fn write_bytes(&self, address: Address, data: &[u8]) -> Result<()> {
        let n = self.write_memory(address, data)?;
        if n != data.len() {
            return Err(Error::other(format!(
                "short write at {address}: {n}/{} bytes",
                data.len()
            )));
        }
        Ok(())
    }

    /// 按过滤器列出可扫描区域（`regions` 的便捷包装）。
    pub fn region_list(&self, filter: &RegionFilter) -> Result<Vec<MemoryRegion>> {
        self.regions(
            Address::new(crate::scanner::DEFAULT_START),
            Address::new(crate::scanner::DEFAULT_STOP),
            filter,
        )
    }

    /// 列出模块（`modules` 的便捷包装）。
    pub fn module_list(&self) -> Result<Vec<ModuleInfo>> {
        self.modules()
    }

    /// 逐页读取；单页失败不会中断整块读取（与 CE 的部分读取重试语义一致）。
    fn read_pagewise(&self, address: Address, buffer: &mut [u8]) -> usize {
        let page_size = self.page_size.max(1);
        let mut total = 0usize;
        while total < buffer.len() {
            let addr = address.0.wrapping_add(total);
            let page_left = page_size - (addr & (page_size - 1));
            let n = page_left.min(buffer.len() - total);
            if self
                .handle
                .copy_address(addr, &mut buffer[total..total + n])
                .is_err()
            {
                break;
            }
            total += n;
        }
        total
    }
}

impl Process {
    /// 目标进程 PID。
    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn pointer_size(&self) -> usize {
        self.pointer_size
    }

    pub fn is_64bit(&self) -> bool {
        self.is_64bit
    }

    pub fn read_memory(&self, address: Address, buffer: &mut [u8]) -> Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if self.handle.copy_address(address.0, buffer).is_ok() {
            return Ok(buffer.len());
        }
        Ok(self.read_pagewise(address, buffer))
    }

    pub fn write_memory(&self, address: Address, buffer: &[u8]) -> Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        self.handle
            .put_address(address.0, buffer)
            .map(|()| buffer.len())
            .map_err(|e| Error::Read {
                addr: address,
                source: e,
            })
    }

    pub fn regions(
        &self,
        start: Address,
        stop: Address,
        filter: &RegionFilter,
    ) -> Result<Vec<MemoryRegion>> {
        let maps = get_process_maps(self.pid as proc_maps::Pid)
            .map_err(|e| Error::other(format!("get_process_maps(pid={}) 失败: {e}", self.pid)))?;

        let mut out = Vec::new();
        for m in maps {
            let m_start = m.start();
            let m_end = m_start.saturating_add(m.size());
            let rstart = m_start.max(start.0);
            let rend = m_end.min(stop.0);
            if rend <= rstart {
                continue;
            }
            let has_path = m
                .filename()
                .map(|p| !p.as_os_str().is_empty())
                .unwrap_or(false);
            let region = MemoryRegion {
                base: Address(rstart),
                size: rend - rstart,
                protect: map_protection(m.is_read(), m.is_write(), m.is_exec()),
                state: MEM_COMMIT,
                mem_type: if has_path { MEM_IMAGE } else { MEM_PRIVATE },
            };
            if filter.matches(&region) {
                out.push(region);
            }
        }
        Ok(out)
    }

    pub fn modules(&self) -> Result<Vec<ModuleInfo>> {
        let maps = get_process_maps(self.pid as proc_maps::Pid)
            .map_err(|e| Error::other(format!("get_process_maps(pid={}) 失败: {e}", self.pid)))?;

        // 把同一路径的多个映射段合并成一个 [base, end) 区间。
        let mut spans: BTreeMap<String, (usize, usize)> = BTreeMap::new();
        for m in maps {
            let Some(path) = m.filename() else { continue };
            let path = path.to_string_lossy();
            if !path.starts_with('/') {
                continue;
            }
            let start = m.start();
            let end = start.saturating_add(m.size());
            let entry = spans.entry(path.into_owned()).or_insert((start, end));
            entry.0 = entry.0.min(start);
            entry.1 = entry.1.max(end);
        }

        Ok(spans
            .into_iter()
            .map(|(path, (base, end))| {
                let name = std::path::Path::new(&path)
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| path.clone());
                ModuleInfo {
                    name,
                    base: Address(base),
                    size: end.saturating_sub(base),
                    path: Some(path),
                }
            })
            .collect())
    }
}

/// 把 r/w/x 权限位映射为 `region.rs` 使用的 Windows `PAGE_*` 常量。
fn map_protection(read: bool, write: bool, exec: bool) -> u32 {
    match (read, write, exec) {
        (false, false, false) => PAGE_NOACCESS,
        (true, false, false) => PAGE_READONLY,
        (false, true, false) | (true, true, false) => PAGE_READWRITE,
        (false, false, true) => PAGE_EXECUTE,
        (true, false, true) => PAGE_EXECUTE_READ,
        (false, true, true) | (true, true, true) => PAGE_EXECUTE_READWRITE,
    }
}

/// 系统页大小（macOS arm64 为 16 KiB）。
fn page_size() -> usize {
    #[cfg(unix)]
    {
        let v = libc_sysconf_pagesize();
        if v > 0 {
            return v as usize;
        }
    }
    0x1000
}

#[cfg(unix)]
fn libc_sysconf_pagesize() -> i64 {
    // _SC_PAGESIZE = 29 on macOS, 30 on Linux; use the platform constant.
    #[cfg(target_os = "macos")]
    const SC_PAGESIZE: i32 = 29;
    #[cfg(not(target_os = "macos"))]
    const SC_PAGESIZE: i32 = 30;

    extern "C" {
        fn sysconf(name: i32) -> i64;
    }
    unsafe { sysconf(SC_PAGESIZE) }
}

/// 打开进程（自由函数版，等价于 [`Process::open`]）。
pub fn open_process(pid: u32) -> Result<Process> {
    Process::open(pid)
}

/// 用 `sysinfo` 枚举所有进程。
pub fn enumerate_processes() -> Result<Vec<ProcessInfo>> {
    use sysinfo::{ProcessesToUpdate, System};

    let mut sys = System::new();
    sys.refresh_processes(ProcessesToUpdate::All, true);

    let mut out = Vec::with_capacity(sys.processes().len());
    for (pid, p) in sys.processes() {
        out.push(ProcessInfo {
            pid: pid.as_u32(),
            name: p.name().to_string_lossy().into_owned(),
            path: p.exe().map(|x| x.to_string_lossy().into_owned()),
            working_set: p.memory(),
            private_bytes: p.virtual_memory(),
            // sysinfo 的累计 CPU 时间为毫秒，这里换算成 100ns 单位（仅用于排序展示）。
            cpu_time_100ns: p.accumulated_cpu_time().saturating_mul(10_000),
        });
    }
    Ok(out)
}
