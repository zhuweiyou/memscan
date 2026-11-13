//! wxmemscan desktop UI (egui/eframe)：微信进程内存搜索，同时也是 `memscan` 的完整使用示例。
//!
//! Layout:
//! * left panel  : WeChat process list, sorted by memory/CPU usage (largest first,
//!                 auto-selected), so the instance you actually use is the default.
//! * central     : scan form, next-scan (CE rescan) controls and results.
//! * bottom      : live progress / status.
//!
//! All scanning happens on a worker thread; the UI only touches [`ScanControl`]
//! atomics and channels, so it never blocks on a multi-hundred-MB scan.

use std::collections::HashMap;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use eframe::egui;

use memscan::{
    FirstScanRequest, MemScan, NextScanRequest, ScanControl, ScanOption, ScanProgress, ScanSummary,
    StringEncoding, TriState, VariableType,
};
use wxmemscan::wechat::{self, WeChatKind};

/// Color palette with light + dark variants (WeChat-green accent).
///
/// The active variant is chosen globally via [`pal::set_dark`] so every widget
/// helper picks the right color without threading a palette parameter around.
mod pal {
    use eframe::egui::Color32;
    use std::sync::atomic::{AtomicBool, Ordering};

    static DARK: AtomicBool = AtomicBool::new(true);

    pub fn set_dark(d: bool) {
        DARK.store(d, Ordering::Relaxed);
    }
    pub fn is_dark() -> bool {
        DARK.load(Ordering::Relaxed)
    }
    fn pick(d: Color32, l: Color32) -> Color32 {
        if is_dark() {
            d
        } else {
            l
        }
    }

    pub fn bg() -> Color32 {
        pick(
            Color32::from_rgb(0x16, 0x17, 0x1A),
            Color32::from_rgb(0xF3, 0xF4, 0xF6),
        )
    }
    pub fn panel() -> Color32 {
        pick(
            Color32::from_rgb(0x1D, 0x1E, 0x22),
            Color32::from_rgb(0xFF, 0xFF, 0xFF),
        )
    }
    pub fn card() -> Color32 {
        pick(
            Color32::from_rgb(0x26, 0x28, 0x2E),
            Color32::from_rgb(0xFF, 0xFF, 0xFF),
        )
    }
    pub fn card_hover() -> Color32 {
        pick(
            Color32::from_rgb(0x30, 0x33, 0x3B),
            Color32::from_rgb(0xEF, 0xF2, 0xF5),
        )
    }
    pub fn field() -> Color32 {
        pick(
            Color32::from_rgb(0x1B, 0x1C, 0x20),
            Color32::from_rgb(0xFF, 0xFF, 0xFF),
        )
    }
    pub fn border() -> Color32 {
        pick(
            Color32::from_rgb(0x37, 0x3B, 0x44),
            Color32::from_rgb(0xD9, 0xDD, 0xE2),
        )
    }
    pub fn text() -> Color32 {
        pick(
            Color32::from_rgb(0xE9, 0xEB, 0xEE),
            Color32::from_rgb(0x1B, 0x1D, 0x21),
        )
    }
    pub fn muted() -> Color32 {
        pick(
            Color32::from_rgb(0x9A, 0xA1, 0xAB),
            Color32::from_rgb(0x6B, 0x72, 0x80),
        )
    }
    pub fn accent() -> Color32 {
        Color32::from_rgb(0x07, 0xC1, 0x60)
    }
    pub fn accent_dim() -> Color32 {
        pick(
            Color32::from_rgb(0x0D, 0x37, 0x27),
            Color32::from_rgb(0xE2, 0xF7, 0xEB),
        )
    }
    pub fn on_accent() -> Color32 {
        Color32::from_rgb(0x06, 0x1A, 0x10)
    }
    pub fn cpu() -> Color32 {
        pick(
            Color32::from_rgb(0xF2, 0xA3, 0x3C),
            Color32::from_rgb(0xB4, 0x6E, 0x00),
        )
    }
    pub fn err() -> Color32 {
        pick(
            Color32::from_rgb(0xFF, 0x6B, 0x6B),
            Color32::from_rgb(0xD9, 0x30, 0x25),
        )
    }
}

// ---------------------------------------------------------------------------
// Value / option tables
// ---------------------------------------------------------------------------

const TYPES: &[(&str, VariableType)] = &[
    ("字节 byte", VariableType::Byte),
    ("字 word", VariableType::Word),
    ("双字 dword", VariableType::DWord),
    ("四字 qword", VariableType::Qword),
    ("浮点 float", VariableType::Single),
    ("双精度 double", VariableType::Double),
    ("字符串 string", VariableType::String),
    ("宽字符串 wstring", VariableType::UnicodeString),
    ("字节数组 AOB", VariableType::ByteArray),
];

const FIRST_OPTS: &[(&str, ScanOption)] = &[
    ("精确", ScanOption::ExactValue),
    ("区间", ScanOption::ValueBetween),
    ("大于", ScanOption::BiggerThan),
    ("小于", ScanOption::SmallerThan),
];

const ENCODINGS: &[(&str, StringEncoding)] = &[
    ("自动", StringEncoding::Auto),
    ("UTF-8 / ANSI", StringEncoding::Utf8),
    ("UTF-16LE", StringEncoding::Utf16Le),
];

/// Process kind filter. `None` means all WeChat processes.
const KIND_FILTERS: &[(&str, Option<WeChatKind>)] = &[
    ("小程序 (WeChatAppEx)", Some(WeChatKind::AppEx)),
    ("内置浏览器 (WechatBrowser)", Some(WeChatKind::Browser)),
    ("微信主程序 (WeChat)", Some(WeChatKind::Main)),
    ("Weixin 4.x", Some(WeChatKind::Weixin)),
    ("全部微信进程", None),
];

// ---------------------------------------------------------------------------
// Worker protocol
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct ProcView {
    pid: u32,
    name: String,
    kind: WeChatKind,
    kind_label: String,
    working_set: u64,
    private_bytes: u64,
    cpu_percent: f32,
}

#[derive(Clone)]
struct ResultRow {
    address: usize,
    preview: String,
    hex: String,
}

enum Cmd {
    Refresh,
    First {
        pid: u32,
        req: FirstScanRequest,
        module_scope: bool,
    },
    Next(NextScanRequest),
}

enum Evt {
    Processes(Vec<ProcView>),
    Done {
        summary: ScanSummary,
        results: Vec<ResultRow>,
    },
    Error(String),
}

const MAX_UI_RESULTS: usize = 5000;

fn snapshot(scan: &MemScan) -> Vec<ResultRow> {
    scan.found()
        .iter()
        .take(MAX_UI_RESULTS)
        .map(|(addr, data)| ResultRow {
            address: addr.get(),
            preview: preview(data, 90),
            hex: hex_bytes(data),
        })
        .collect()
}

fn spawn_worker(
    control: ScanControl,
    cmd_rx: Receiver<Cmd>,
    evt_tx: Sender<Evt>,
) -> JoinHandle<()> {
    std::thread::Builder::new()
        .name("wxmemscan-scan".into())
        .spawn(move || {
            let mut session: Option<MemScan> = None;
            let mut last_cpu: HashMap<u32, (u64, Instant)> = HashMap::new();
            while let Ok(cmd) = cmd_rx.recv() {
                match cmd {
                    Cmd::Refresh => {
                        let now = Instant::now();
                        match wechat::find_wechat_processes() {
                            Ok(list) => {
                                let mut views = Vec::with_capacity(list.len());
                                let mut new_cpu = HashMap::with_capacity(list.len());
                                for p in list {
                                    let cpu_percent = last_cpu
                                        .get(&p.pid)
                                        .map(|(t0, i0)| {
                                            let dt =
                                                now.duration_since(*i0).as_secs_f64().max(1e-3);
                                            let dc =
                                                p.cpu_time_100ns.saturating_sub(*t0) as f64 * 1e-7;
                                            (dc / dt * 100.0) as f32
                                        })
                                        .unwrap_or(0.0);
                                    new_cpu.insert(p.pid, (p.cpu_time_100ns, now));
                                    views.push(ProcView {
                                        pid: p.pid,
                                        name: p.name,
                                        kind: p.kind,
                                        kind_label: p.kind.label().to_string(),
                                        working_set: p.working_set,
                                        private_bytes: p.private_bytes,
                                        cpu_percent,
                                    });
                                }
                                last_cpu = new_cpu;
                                // Heaviest first: memory, then CPU%, then commit.
                                views.sort_by(|a, b| {
                                    b.working_set
                                        .cmp(&a.working_set)
                                        .then(
                                            b.cpu_percent
                                                .partial_cmp(&a.cpu_percent)
                                                .unwrap_or(std::cmp::Ordering::Equal),
                                        )
                                        .then(b.private_bytes.cmp(&a.private_bytes))
                                });
                                let _ = evt_tx.send(Evt::Processes(views));
                            }
                            Err(e) => {
                                let _ = evt_tx.send(Evt::Error(format!("枚举进程失败: {e}")));
                            }
                        }
                    }
                    Cmd::First {
                        pid,
                        req,
                        module_scope,
                    } => {
                        session = None;
                        control.reset();
                        match MemScan::attach(pid) {
                            Ok(mut scan) => {
                                let mut req = req;
                                if module_scope {
                                    let modules = scan.modules().unwrap_or_default();
                                    req.module_ranges = wechat::wechat_module_ranges(&modules);
                                }
                                match scan.first_scan(&req, &control) {
                                    Ok(summary) => {
                                        let results = snapshot(&scan);
                                        let _ = evt_tx.send(Evt::Done { summary, results });
                                        session = Some(scan);
                                    }
                                    Err(e) => {
                                        let _ =
                                            evt_tx.send(Evt::Error(format!("首次扫描失败: {e}")));
                                    }
                                }
                            }
                            Err(e) => {
                                let _ = evt_tx.send(Evt::Error(format!(
                                    "打开进程 {pid} 失败（可能需要管理员权限）: {e}"
                                )));
                            }
                        }
                    }
                    Cmd::Next(req) => match session.as_mut() {
                        Some(scan) => {
                            control.reset();
                            match scan.next_scan(&req, &control) {
                                Ok(summary) => {
                                    let results = snapshot(scan);
                                    let _ = evt_tx.send(Evt::Done { summary, results });
                                }
                                Err(e) => {
                                    let _ = evt_tx.send(Evt::Error(format!("再次扫描失败: {e}")));
                                }
                            }
                        }
                        None => {
                            let _ = evt_tx.send(Evt::Error("请先进行首次扫描".into()));
                        }
                    },
                }
            }
        })
        .expect("spawn scan worker")
}

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------

struct WxMemApp {
    processes: Vec<ProcView>,
    selected_pid: Option<u32>,
    kind_filter_idx: usize,
    theme_pref: egui::ThemePreference,
    applied_dark: Option<bool>,
    last_refresh: Instant,

    // scan form
    type_idx: usize,
    opt_idx: usize,
    enc_idx: usize,
    value: String,
    value2: String,
    case_insensitive: bool,
    wildcard: bool,
    signed: bool,
    hex: bool,
    writable: bool,
    module_scope: bool,
    max_results: String,
    show_hex: bool,

    // next-scan inputs
    next_value: String,
    next_value2: String,

    // session state
    session_active: bool,
    scanning: bool,
    progress: ScanProgress,
    summary: Option<ScanSummary>,
    results: Vec<ResultRow>,
    status: String,
    error: Option<String>,

    // worker
    cmd_tx: Sender<Cmd>,
    evt_rx: Receiver<Evt>,
    control: ScanControl,
    _worker: Option<JoinHandle<()>>,
}

impl WxMemApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let egui_ctx = &cc.egui_ctx;
        // Theme: follow the OS by default; allow override via env for testing/CI.
        let theme_pref = match std::env::var("WXMEM_THEME").ok().as_deref() {
            Some("light") => egui::ThemePreference::Light,
            Some("dark") => egui::ThemePreference::Dark,
            _ => egui::ThemePreference::System,
        };
        egui_ctx.set_theme(theme_pref);
        let dark = matches!(egui_ctx.theme(), egui::Theme::Dark);
        apply_theme(egui_ctx, dark);

        let control = ScanControl::new();
        let (cmd_tx, cmd_rx) = channel();
        let (evt_tx, evt_rx) = channel();
        let worker = spawn_worker(control.clone(), cmd_rx, evt_tx);
        let _ = cmd_tx.send(Cmd::Refresh);

        Self {
            processes: Vec::new(),
            selected_pid: None,
            // Default: all WeChat processes, so the heaviest instance overall is selected.
            kind_filter_idx: 4,
            theme_pref,
            applied_dark: Some(dark),
            last_refresh: Instant::now(),
            type_idx: 6, // string
            opt_idx: 0,
            enc_idx: 0,
            value: String::new(),
            value2: String::new(),
            case_insensitive: true,
            wildcard: true,
            signed: false,
            hex: false,
            writable: true,
            module_scope: false,
            max_results: "500".to_string(),
            show_hex: false,
            next_value: String::new(),
            next_value2: String::new(),
            session_active: false,
            scanning: false,
            progress: ScanProgress::default(),
            summary: None,
            results: Vec::new(),
            status: "就绪".to_string(),
            error: None,
            cmd_tx,
            evt_rx,
            control,
            _worker: Some(worker),
        }
    }

    fn drain_events(&mut self) {
        let events: Vec<Evt> = self.evt_rx.try_iter().collect();
        for evt in events {
            match evt {
                Evt::Processes(list) => {
                    if list.is_empty() {
                        self.status = "未发现微信进程（请先启动微信/小程序）".to_string();
                    }
                    self.processes = list;
                    self.normalize_selection();
                }
                Evt::Done { summary, results } => {
                    self.scanning = false;
                    self.session_active = true;
                    self.results = results;
                    self.status = if summary.cancelled {
                        "已中断".to_string()
                    } else {
                        format!(
                            "完成：{} 条结果，用时 {} ms",
                            summary.total_found,
                            summary.duration.as_millis()
                        )
                    };
                    self.summary = Some(summary);
                    self.error = None;
                }
                Evt::Error(msg) => {
                    self.scanning = false;
                    self.error = Some(msg);
                    self.status = "出错".to_string();
                }
            }
        }
    }

    /// Ensure the selected process exists within the current kind filter; if not,
    /// pick the heaviest instance in that filter (processes are sorted by usage).
    fn normalize_selection(&mut self) {
        let kind_filter = KIND_FILTERS[self.kind_filter_idx].1;
        let in_filter = |p: &ProcView| kind_filter.map_or(true, |k| p.kind == k);
        let valid = self
            .selected_pid
            .map(|pid| self.processes.iter().any(|p| p.pid == pid && in_filter(p)))
            .unwrap_or(false);
        if !valid {
            self.selected_pid = self.processes.iter().find(|p| in_filter(p)).map(|p| p.pid);
        }
    }

    fn request_refresh(&mut self) {
        let _ = self.cmd_tx.send(Cmd::Refresh);
        self.last_refresh = Instant::now();
    }

    fn build_first(&self) -> Result<FirstScanRequest, String> {
        let mut req = FirstScanRequest::default();
        req.value_type = TYPES[self.type_idx].1;
        req.option = FIRST_OPTS[self.opt_idx].1;
        req.encoding = ENCODINGS[self.enc_idx].1;
        req.value = self.value.clone();
        if req.option == ScanOption::ValueBetween {
            req.value2 = Some(self.value2.clone());
        }
        if req.value.trim().is_empty() && req.option != ScanOption::UnknownValue {
            return Err("请输入搜索内容".into());
        }
        req.case_insensitive = self.case_insensitive;
        req.wildcard = self.wildcard;
        req.signed = self.signed;
        req.hex = self.hex;
        if self.writable {
            req.filter.writable = TriState::Include;
        }
        req.max_results = parse_opt_usize(&self.max_results)?;
        Ok(req)
    }

    fn start_first_scan(&mut self) {
        let Some(pid) = self.selected_pid else {
            self.error = Some("请先在左侧选择一个进程".into());
            return;
        };
        match self.build_first() {
            Ok(req) => {
                self.error = None;
                self.scanning = true;
                self.progress = ScanProgress::default();
                self.status = "首次扫描中…（可点“停止”）".to_string();
                let _ = self.cmd_tx.send(Cmd::First {
                    pid,
                    req,
                    module_scope: self.module_scope,
                });
            }
            Err(e) => self.error = Some(e),
        }
    }

    fn start_next(&mut self, option: ScanOption, needs_value: bool, needs_two: bool) {
        if !self.session_active {
            self.error = Some("请先进行首次扫描".into());
            return;
        }
        let mut req = NextScanRequest {
            option,
            ..Default::default()
        };
        if needs_value {
            if self.next_value.trim().is_empty() {
                self.error = Some("请输入用于比较的数值".into());
                return;
            }
            req.value = Some(self.next_value.clone());
            if needs_two {
                if self.next_value2.trim().is_empty() {
                    self.error = Some("请输入区间上界".into());
                    return;
                }
                req.value2 = Some(self.next_value2.clone());
            }
        }
        self.error = None;
        self.scanning = true;
        self.progress = ScanProgress::default();
        self.status = format!("再次扫描（{option}）中…");
        let _ = self.cmd_tx.send(Cmd::Next(req));
    }

    fn process_panel(&mut self, root: &mut egui::Ui) {
        // Clone the small process list so we can mutate `selected_pid` afterwards.
        let processes = self.processes.clone();
        let selected = self.selected_pid;
        let kind_filter = KIND_FILTERS[self.kind_filter_idx].1;
        let filtered: Vec<ProcView> = processes
            .iter()
            .filter(|p| kind_filter.map_or(true, |k| p.kind == k))
            .cloned()
            .collect();
        let mut clicked = None;
        let mut refresh = false;
        let mut kind_changed = false;

        egui::Panel::left("processes")
            .frame(
                egui::Frame::new()
                    .fill(pal::panel())
                    .inner_margin(egui::Margin::symmetric(10, 8)),
            )
            .resizable(true)
            .default_size(340.0)
            .min_size(300.0)
            .max_size(520.0)
            .show(root, |ui| {
                ui.add_space(4.0);
                ui.label(
                    egui::RichText::new("微信进程")
                        .size(16.0)
                        .strong()
                        .color(pal::text()),
                );
                ui.label(
                    egui::RichText::new("按内存 / CPU 占用排序，自动选中最大的实例")
                        .size(10.5)
                        .color(pal::muted()),
                );
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("类型").color(pal::muted()).size(12.0));
                    egui::ComboBox::from_id_salt("kindfilter")
                        .selected_text(KIND_FILTERS[self.kind_filter_idx].0)
                        .width(ui.available_width() - 8.0)
                        .show_ui(ui, |ui| {
                            for (i, (name, _)) in KIND_FILTERS.iter().enumerate() {
                                if ui
                                    .selectable_value(&mut self.kind_filter_idx, i, *name)
                                    .changed()
                                {
                                    kind_changed = true;
                                }
                            }
                        });
                });
                let refresh_btn =
                    egui::Button::new(egui::RichText::new("⟳  刷新进程列表").size(12.5))
                        .fill(pal::card())
                        .corner_radius(8);
                if ui
                    .add_sized([ui.available_width(), 26.0], refresh_btn)
                    .clicked()
                {
                    refresh = true;
                }
                ui.add_space(4.0);

                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        if filtered.is_empty() {
                            ui.add_space(10.0);
                            ui.label(
                                egui::RichText::new(
                                    "未发现匹配的微信进程。\n请启动微信/小程序，或切换类型后刷新。",
                                )
                                .color(pal::muted()),
                            );
                            return;
                        }
                        let width = ui.available_width().max(240.0);
                        for p in &filtered {
                            let is_sel = selected == Some(p.pid);
                            let (rect, resp) = ui
                                .allocate_exact_size(egui::vec2(width, 54.0), egui::Sense::click());
                            let hovered = resp.hovered();
                            let bg = if is_sel {
                                pal::accent_dim()
                            } else if hovered {
                                pal::card_hover()
                            } else {
                                pal::card()
                            };
                            let painter = ui.painter().clone();
                            painter.rect_filled(rect, egui::CornerRadius::same(9), bg);
                            if is_sel {
                                let bar = egui::Rect::from_min_size(
                                    rect.left_top() + egui::vec2(0.0, 8.0),
                                    egui::vec2(3.0, rect.height() - 16.0),
                                );
                                painter.rect_filled(
                                    bar,
                                    egui::CornerRadius::same(2),
                                    pal::accent(),
                                );
                            }
                            let mb = p.working_set as f64 / 1048576.0;
                            painter.text(
                                rect.left_top() + egui::vec2(14.0, 8.0),
                                egui::Align2::LEFT_TOP,
                                truncate(&p.name, 20),
                                egui::FontId::proportional(13.5),
                                if is_sel { pal::accent() } else { pal::text() },
                            );
                            painter.text(
                                rect.left_top() + egui::vec2(14.0, 30.0),
                                egui::Align2::LEFT_TOP,
                                format!("#{}  {}", p.pid, p.kind_label),
                                egui::FontId::proportional(10.5),
                                pal::muted(),
                            );
                            painter.text(
                                rect.right_top() + egui::vec2(-14.0, 8.0),
                                egui::Align2::RIGHT_TOP,
                                format!("{:.1} MB", mb),
                                egui::FontId::monospace(13.0),
                                if is_sel { pal::accent() } else { pal::text() },
                            );
                            painter.text(
                                rect.right_top() + egui::vec2(-14.0, 30.0),
                                egui::Align2::RIGHT_TOP,
                                format!("CPU {:.1}%", p.cpu_percent),
                                egui::FontId::monospace(11.0),
                                pal::cpu(),
                            );
                            if resp.clicked() {
                                clicked = Some(p.pid);
                            }
                            ui.add_space(6.0);
                        }
                    });
            });

        if let Some(pid) = clicked {
            self.selected_pid = Some(pid);
        }
        if refresh {
            self.request_refresh();
        }
        if kind_changed {
            self.normalize_selection();
        }
    }

    fn header_panel(&mut self, root: &mut egui::Ui) {
        egui::Panel::top("header")
            .frame(
                egui::Frame::new()
                    .fill(pal::panel())
                    .inner_margin(egui::Margin::symmetric(16, 10)),
            )
            .show(root, |ui| {
                ui.horizontal(|ui| {
                    let (rect, _) =
                        ui.allocate_exact_size(egui::vec2(30.0, 30.0), egui::Sense::hover());
                    let painter = ui.painter().clone();
                    painter.circle_filled(rect.center(), 15.0, pal::accent());
                    painter.text(
                        rect.center(),
                        egui::Align2::CENTER_CENTER,
                        "W",
                        egui::FontId::proportional(19.0),
                        pal::on_accent(),
                    );
                    ui.add_space(8.0);
                    ui.vertical(|ui| {
                        ui.label(
                            egui::RichText::new("wxmemscan")
                                .size(21.0)
                                .strong()
                                .color(pal::text()),
                        );
                        ui.label(
                            egui::RichText::new("微信 / 小程序内存搜索 · 通用内核 memscan")
                                .size(11.0)
                                .color(pal::muted()),
                        );
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        // Single icon button: click to toggle light/dark.
                        let is_dark_now = self.applied_dark.unwrap_or(true);
                        let (icon, tip) = if is_dark_now {
                            ("☀", "切换到浅色")
                        } else {
                            ("🌙", "切换到深色")
                        };
                        let theme_btn = egui::Button::new(
                            egui::RichText::new(icon).size(18.0).color(pal::text()),
                        )
                        .fill(pal::card())
                        .corner_radius(8)
                        .min_size(egui::vec2(34.0, 30.0));
                        if ui.add(theme_btn).on_hover_text(tip).clicked() {
                            let next = if is_dark_now {
                                egui::ThemePreference::Light
                            } else {
                                egui::ThemePreference::Dark
                            };
                            self.theme_pref = next;
                            ui.ctx().set_theme(next);
                            self.applied_dark = None;
                        }
                        if let Some(pid) = self.selected_pid {
                            if let Some(p) = self.processes.iter().find(|x| x.pid == pid) {
                                let mb = p.working_set as f64 / 1048576.0;
                                ui.label(
                                    egui::RichText::new(format!(
                                        "{}  ·  PID {}  ·  {:.1} MB",
                                        truncate(&p.name, 22),
                                        p.pid,
                                        mb
                                    ))
                                    .color(pal::accent())
                                    .strong()
                                    .size(13.0),
                                );
                            }
                        } else {
                            ui.label(
                                egui::RichText::new("未选择进程")
                                    .color(pal::muted())
                                    .size(13.0),
                            );
                        }
                    });
                });
            });
    }

    fn status_panel(&mut self, root: &mut egui::Ui) {
        egui::Panel::bottom("status")
            .frame(
                egui::Frame::new()
                    .fill(pal::panel())
                    .inner_margin(egui::Margin::symmetric(14, 7)),
            )
            .show(root, |ui| {
                if self.scanning {
                    let p = self.progress;
                    let frac = p.fraction() as f32;
                    ui.add(
                        egui::ProgressBar::new(frac)
                            .fill(pal::accent())
                            .show_percentage()
                            .text(format!(
                                "已读 {:.1} MB / {:.1} MB   匹配 {}",
                                p.examined_bytes as f64 / 1048576.0,
                                p.total_bytes as f64 / 1048576.0,
                                p.matches
                            )),
                    );
                    if ui.small_button("停止扫描").clicked() {
                        self.control.cancel();
                    }
                } else {
                    ui.horizontal(|ui| {
                        if let Some(err) = &self.error {
                            ui.colored_label(pal::err(), format!("✖ {err}"));
                        } else {
                            ui.label(egui::RichText::new("●").color(pal::accent()));
                            ui.label(
                                egui::RichText::new(&self.status)
                                    .color(pal::muted())
                                    .size(12.5),
                            );
                        }
                        if let Some(s) = &self.summary {
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    ui.label(
                                        egui::RichText::new(format!("结果 {} 条", s.total_found))
                                            .color(pal::accent())
                                            .strong(),
                                    );
                                },
                            );
                        }
                    });
                }
            });
    }

    fn control_panel(&mut self, root: &mut egui::Ui) {
        egui::CentralPanel::default()
            .frame(
                egui::Frame::new()
                    .fill(pal::bg())
                    .inner_margin(egui::Margin::symmetric(16, 12)),
            )
            .show(root, |ui| {
                egui::Frame::new()
                    .fill(pal::card())
                    .corner_radius(12)
                    .inner_margin(egui::Margin::symmetric(14, 12))
                    .show(ui, |ui| {
                        ui.label(
                            egui::RichText::new("扫描参数")
                                .size(15.0)
                                .strong()
                                .color(pal::text()),
                        );
                        ui.add_space(6.0);
                        egui::Grid::new("scan_form")
                            .num_columns(4)
                            .spacing([10.0, 8.0])
                            .show(ui, |ui| {
                                ui.label("值类型");
                                egui::ComboBox::from_id_salt("type")
                                    .selected_text(TYPES[self.type_idx].0)
                                    .show_ui(ui, |ui| {
                                        for (i, (name, _)) in TYPES.iter().enumerate() {
                                            ui.selectable_value(&mut self.type_idx, i, *name);
                                        }
                                    });
                                ui.label("比较");
                                egui::ComboBox::from_id_salt("opt")
                                    .selected_text(FIRST_OPTS[self.opt_idx].0)
                                    .show_ui(ui, |ui| {
                                        for (i, (name, _)) in FIRST_OPTS.iter().enumerate() {
                                            ui.selectable_value(&mut self.opt_idx, i, *name);
                                        }
                                    });
                                ui.end_row();

                                ui.label("搜索内容");
                                ui.add(
                                    egui::TextEdit::singleline(&mut self.value)
                                        .hint_text("如 WeChat / 微信 / 57 65 ?? 或数值")
                                        .desired_width(260.0),
                                );
                                ui.label("编码");
                                egui::ComboBox::from_id_salt("enc")
                                    .selected_text(ENCODINGS[self.enc_idx].0)
                                    .show_ui(ui, |ui| {
                                        for (i, (name, _)) in ENCODINGS.iter().enumerate() {
                                            ui.selectable_value(&mut self.enc_idx, i, *name);
                                        }
                                    });
                                ui.end_row();

                                ui.label("区间上界");
                                ui.add(
                                    egui::TextEdit::singleline(&mut self.value2)
                                        .hint_text("仅“区间”时使用")
                                        .desired_width(160.0),
                                );
                                ui.label("最多结果");
                                ui.add(
                                    egui::TextEdit::singleline(&mut self.max_results)
                                        .hint_text("留空=不限")
                                        .desired_width(100.0),
                                );
                                ui.end_row();
                            });

                        ui.horizontal_wrapped(|ui| {
                            ui.checkbox(&mut self.writable, "仅可写区域");
                            ui.checkbox(&mut self.case_insensitive, "不区分大小写");
                            ui.checkbox(&mut self.wildcard, "? 通配");
                            ui.checkbox(&mut self.signed, "有符号");
                            ui.checkbox(&mut self.hex, "十六进制数值");
                            ui.checkbox(&mut self.module_scope, "仅微信模块范围");
                        });

                        ui.horizontal(|ui| {
                            let can_scan = !self.scanning && self.selected_pid.is_some();
                            let scan_btn = egui::Button::new(
                                egui::RichText::new("🔍  首次扫描")
                                    .size(14.0)
                                    .strong()
                                    .color(pal::on_accent()),
                            )
                            .fill(pal::accent())
                            .corner_radius(9)
                            .min_size(egui::vec2(120.0, 32.0));
                            if ui.add_enabled(can_scan, scan_btn).clicked() {
                                self.start_first_scan();
                            }
                            if self.scanning {
                                ui.spinner();
                            }
                            if let Some(pid) = self.selected_pid {
                                ui.label(
                                    egui::RichText::new(format!("目标 PID: {pid}"))
                                        .color(pal::muted()),
                                );
                            }
                        });
                    });
                ui.add_space(10.0);

                // ---- next scan (rescan) ----
                ui.add_enabled_ui(self.session_active && !self.scanning, |ui| {
                    ui.horizontal(|ui| {
                        ui.label("再次扫描:");
                        if ui.button("变化").clicked() {
                            self.start_next(ScanOption::Changed, false, false);
                        }
                        if ui.button("不变").clicked() {
                            self.start_next(ScanOption::Unchanged, false, false);
                        }
                        if ui.button("增大").clicked() {
                            self.start_next(ScanOption::IncreasedValue, false, false);
                        }
                        if ui.button("减小").clicked() {
                            self.start_next(ScanOption::DecreasedValue, false, false);
                        }
                    });
                    ui.horizontal(|ui| {
                        ui.add(
                            egui::TextEdit::singleline(&mut self.next_value)
                                .hint_text("数值")
                                .desired_width(110.0),
                        );
                        ui.add(
                            egui::TextEdit::singleline(&mut self.next_value2)
                                .hint_text("区间上界")
                                .desired_width(110.0),
                        );
                        if ui.button("等于").clicked() {
                            self.start_next(ScanOption::ExactValue, true, false);
                        }
                        if ui.button("大于").clicked() {
                            self.start_next(ScanOption::BiggerThan, true, false);
                        }
                        if ui.button("小于").clicked() {
                            self.start_next(ScanOption::SmallerThan, true, false);
                        }
                        if ui.button("区间").clicked() {
                            self.start_next(ScanOption::ValueBetween, true, true);
                        }
                    });
                });

                ui.add_space(10.0);
                // ---- results ----
                egui::Frame::new()
                    .fill(pal::card())
                    .corner_radius(12)
                    .inner_margin(egui::Margin::symmetric(14, 12))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(
                                egui::RichText::new("结果")
                                    .size(15.0)
                                    .strong()
                                    .color(pal::text()),
                            );
                            ui.label(
                                egui::RichText::new(format!("共 {} 条", self.results.len()))
                                    .color(pal::muted())
                                    .size(12.0),
                            );
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    ui.checkbox(&mut self.show_hex, "显示 Hex");
                                    if self.results.len() > 2000 {
                                        ui.label(
                                            egui::RichText::new("仅显示前 2000 条")
                                                .size(10.5)
                                                .color(pal::muted()),
                                        );
                                    }
                                },
                            );
                        });
                        ui.add_space(4.0);
                        ui.separator();
                        egui::ScrollArea::vertical()
                            .auto_shrink([false, false])
                            .show(ui, |ui| {
                                if self.results.is_empty() {
                                    ui.add_space(16.0);
                                    ui.label(
                                        egui::RichText::new(
                                            "尚无结果。选择左侧进程、输入搜索内容后点“首次扫描”。",
                                        )
                                        .color(pal::muted()),
                                    );
                                    return;
                                }
                                let n = self.results.len().min(2000);
                                egui::Grid::new("results_grid")
                                    .striped(true)
                                    .num_columns(3)
                                    .spacing([14.0, 3.0])
                                    .min_col_width(48.0)
                                    .show(ui, |ui| {
                                        ui.label(
                                            egui::RichText::new("序号")
                                                .size(10.5)
                                                .color(pal::muted()),
                                        );
                                        ui.label(
                                            egui::RichText::new("地址")
                                                .size(10.5)
                                                .color(pal::muted()),
                                        );
                                        ui.label(
                                            egui::RichText::new(if self.show_hex {
                                                "内容 / Hex"
                                            } else {
                                                "内容"
                                            })
                                            .size(10.5)
                                            .color(pal::muted()),
                                        );
                                        ui.end_row();
                                        for (i, r) in self.results.iter().take(n).enumerate() {
                                            ui.label(
                                                egui::RichText::new(format!("{}", i + 1))
                                                    .monospace()
                                                    .size(11.5)
                                                    .color(pal::muted()),
                                            );
                                            ui.label(
                                                egui::RichText::new(format!("0x{:X}", r.address))
                                                    .monospace()
                                                    .size(11.5)
                                                    .color(pal::accent()),
                                            );
                                            let text = if self.show_hex {
                                                r.hex.clone()
                                            } else {
                                                r.preview.clone()
                                            };
                                            ui.label(
                                                egui::RichText::new(text).monospace().size(11.5),
                                            );
                                            ui.end_row();
                                        }
                                    });
                            });
                    });
            });
    }
}

impl eframe::App for WxMemApp {
    fn ui(&mut self, root: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = root.ctx().clone();
        // Follow the effective theme (system by default, or manual override).
        let effective_dark = matches!(ctx.theme(), egui::Theme::Dark);
        if Some(effective_dark) != self.applied_dark {
            apply_theme(&ctx, effective_dark);
            self.applied_dark = Some(effective_dark);
        }
        self.drain_events();

        if self.scanning {
            self.progress = self.control.snapshot();
            ctx.request_repaint_after(Duration::from_millis(100));
        }
        // Periodic process refresh (also updates CPU%).
        if !self.scanning && self.last_refresh.elapsed() > Duration::from_secs(2) {
            self.request_refresh();
        }

        self.header_panel(root);
        self.status_panel(root);
        self.process_panel(root);
        self.control_panel(root);
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_opt_usize(text: &str) -> Result<Option<usize>, String> {
    let t = text.trim();
    if t.is_empty() {
        return Ok(None);
    }
    t.parse::<usize>()
        .map(Some)
        .map_err(|_| format!("无效的数字: '{t}'"))
}

fn truncate(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max_chars.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 3);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            s.push(' ');
        }
        s.push_str(&format!("{b:02X}"));
    }
    s
}

fn preview(bytes: &[u8], max_chars: usize) -> String {
    let text = String::from_utf8_lossy(bytes);
    let mut out = String::new();
    for ch in text.chars() {
        match ch {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push('.'),
            c => out.push(c),
        }
        if out.chars().count() >= max_chars {
            out.push_str("...");
            break;
        }
    }
    out
}

/// Apply the professional theme (colors, spacing, rounded widgets, fonts).
/// `dark` selects the palette; it is called again whenever the effective theme
/// changes (system theme change or manual override).
fn apply_theme(ctx: &egui::Context, dark: bool) {
    pal::set_dark(dark);
    setup_cjk_fonts(ctx);

    let theme = if dark {
        egui::Theme::Dark
    } else {
        egui::Theme::Light
    };
    let mut style = (*ctx.style_of(theme)).clone();
    let mut v = if dark {
        egui::Visuals::dark()
    } else {
        egui::Visuals::light()
    };
    v.override_text_color = Some(pal::text());
    v.panel_fill = pal::bg();
    v.window_fill = pal::panel();
    v.extreme_bg_color = pal::field();
    v.faint_bg_color = pal::card();
    v.selection.bg_fill = pal::accent_dim();
    v.hyperlink_color = pal::accent();
    v.window_corner_radius = egui::CornerRadius::same(12);
    v.menu_corner_radius = egui::CornerRadius::same(8);

    v.widgets.noninteractive.bg_fill = pal::card();
    v.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0, pal::border());
    v.widgets.noninteractive.corner_radius = egui::CornerRadius::same(8);

    v.widgets.inactive.bg_fill = pal::card();
    v.widgets.inactive.weak_bg_fill = pal::card();
    v.widgets.inactive.bg_stroke = egui::Stroke::new(1.0, pal::border());
    v.widgets.inactive.fg_stroke = egui::Stroke::new(1.0, pal::text());
    v.widgets.inactive.corner_radius = egui::CornerRadius::same(8);

    v.widgets.hovered.bg_fill = pal::card_hover();
    v.widgets.hovered.weak_bg_fill = pal::card_hover();
    v.widgets.hovered.bg_stroke = egui::Stroke::new(1.0, pal::accent());
    v.widgets.hovered.fg_stroke = egui::Stroke::new(1.0, pal::text());
    v.widgets.hovered.corner_radius = egui::CornerRadius::same(8);

    v.widgets.active.bg_fill = pal::accent_dim();
    v.widgets.active.weak_bg_fill = pal::accent_dim();
    v.widgets.active.bg_stroke = egui::Stroke::new(1.0, pal::accent());
    v.widgets.active.corner_radius = egui::CornerRadius::same(8);

    v.widgets.open.bg_fill = pal::card_hover();
    v.widgets.open.corner_radius = egui::CornerRadius::same(8);

    style.visuals = v;
    style.spacing.item_spacing = egui::vec2(8.0, 8.0);
    style.spacing.button_padding = egui::vec2(12.0, 6.0);
    style.text_styles = std::collections::BTreeMap::from([
        (egui::TextStyle::Heading, egui::FontId::proportional(22.0)),
        (egui::TextStyle::Body, egui::FontId::proportional(14.0)),
        (egui::TextStyle::Button, egui::FontId::proportional(14.0)),
        (egui::TextStyle::Small, egui::FontId::proportional(11.0)),
        (egui::TextStyle::Monospace, egui::FontId::monospace(12.5)),
    ]);
    ctx.set_style_of(theme, style);
}

/// Load a CJK font so Chinese labels render (egui's default fonts are Latin only).
fn setup_cjk_fonts(ctx: &egui::Context) {
    let candidates = [
        "C:\\Windows\\Fonts\\msyh.ttc",
        "C:\\Windows\\Fonts\\msyhbd.ttc",
        "C:\\Windows\\Fonts\\simhei.ttf",
        "C:\\Windows\\Fonts\\simsun.ttc",
        "/System/Library/Fonts/PingFang.ttc",
        "/System/Library/Fonts/STHeiti Light.ttc",
    ];
    for path in candidates {
        if let Ok(bytes) = std::fs::read(path) {
            let mut fonts = egui::FontDefinitions::default();
            fonts.font_data.insert(
                "cjk".to_owned(),
                Arc::new(egui::FontData::from_owned(bytes)),
            );
            fonts
                .families
                .entry(egui::FontFamily::Proportional)
                .or_default()
                .insert(0, "cjk".to_owned());
            fonts
                .families
                .entry(egui::FontFamily::Monospace)
                .or_default()
                .push("cjk".to_owned());
            ctx.set_fonts(fonts);
            return;
        }
    }
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1120.0, 760.0])
            .with_min_inner_size([920.0, 600.0])
            .with_title("wxmemscan — 微信内存搜索"),
        ..Default::default()
    };
    eframe::run_native(
        "wxmemscan",
        options,
        Box::new(|cc| Ok(Box::new(WxMemApp::new(cc)))),
    )
}
