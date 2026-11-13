//! # wxmemscan
//!
//! 微信 / 微信小程序进程内存搜索的桌面程序，基于 [`memscan`] 核心包。
//!
//! 这个 crate 同时是 **`memscan` 的完整使用示例**：
//! * [`wechat`] 演示如何在通用进程列表之上识别微信主程序、Helper（Renderer/GPU）
//!   等小程序宿主进程；
//! * `src/main.rs` 演示如何用 `memscan` 的 `MemScan` / `FirstScanRequest` /
//!   `NextScanRequest` 在 GUI 里做首扫、再次扫描与结果展示；
//! * `examples/headless_wx_scan.rs` 演示不启动 GUI 时如何用 API 直接扫描。

pub mod wechat;

pub use wechat::{
    find_by_kind, find_mini_program_processes, find_wechat_processes,
    find_wechat_processes_by_usage, heaviest, sort_by_usage, WeChatKind, WechatProcess,
};
