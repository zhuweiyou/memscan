//! 无 GUI 的示例：演示如何用 `memscan` 核心包搜索微信进程内存。
//!
//! 运行：
//! ```bash
//! cargo run -p wxmemscan --example headless_wx_scan -- "WeChat"
//! ```
//!
//! * 有微信进程：取内存占用最大的那个，扫描命令行给定的文本。
//! * 没有微信进程：退化为对当前进程做一次自检扫描，方便直接跑通。

use memscan::{FirstScanRequest, MemScan, ScanControl, TriState, VariableType};
use wxmemscan::wechat::find_wechat_processes_by_usage;

fn main() -> memscan::Result<()> {
    let pattern = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "WeChat".to_string());

    let processes = find_wechat_processes_by_usage()?;
    if processes.is_empty() {
        println!("未发现微信相关进程，改用当前进程演示 memscan 核心 API。\n");

        let marker = "WXMEMSCAN_DEMO_MARKER_0123456789";
        std::hint::black_box(marker);

        let mut scan = MemScan::attach(std::process::id())?;
        let mut req = FirstScanRequest::default();
        req.value_type = VariableType::String;
        req.value = marker.to_string();
        req.case_insensitive = false;
        req.wildcard = false;
        req.filter.writable = TriState::Include;

        let summary = scan.first_scan(&req, &ScanControl::new())?;
        println!("自检：首扫命中 {} 处", summary.matches);
        for (address, bytes) in scan.found().iter().take(10) {
            println!("  {address}  {:?}", String::from_utf8_lossy(bytes));
        }
        return Ok(());
    }

    println!(
        "发现 {} 个微信相关进程（按内存占用排序）：",
        processes.len()
    );
    for p in &processes {
        println!("  [{}] {}  ({})", p.pid, p.name, p.kind.label());
    }

    let target = &processes[0];
    println!(
        "\n扫描 {}（pid={}）中的文本 {:?} …",
        target.name, target.pid, pattern
    );

    let mut scan = MemScan::attach(target.pid)?;
    let mut req = FirstScanRequest::default();
    req.value_type = VariableType::String;
    req.value = pattern;
    req.filter.writable = TriState::Include;

    let summary = scan.first_scan(&req, &ScanControl::new())?;
    println!("命中 {} 处，前 10 条：", summary.matches);
    for (address, bytes) in scan.found().iter().take(10) {
        println!("  {address}  {:?}", String::from_utf8_lossy(bytes));
    }
    Ok(())
}
