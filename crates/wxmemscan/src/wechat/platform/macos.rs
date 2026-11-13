//! macOS WeChat process classification.
//!
//! macOS processes are **not** `.exe`. WeChat ships as `WeChat.app` (main process
//! name `WeChat`) and Weixin as `Weixin.app`; mini-program / web content runs in
//! Chromium-style helper processes such as:
//!   * `WeChat Helper`            (browser / utility helper)
//!   * `WeChat Helper (Renderer)` (web / mini-program renderer)
//!   * `WeChat Helper (GPU)`      (GPU helper)
//!
//! Classification is therefore best-effort by process name and image path
//! (`ProcessInfo.path`, populated by the macOS backend). This module compiles only
//! on macOS but is kept in-tree so the abstraction is real rather than aspirational.

use super::super::{WeChatClassifier, WeChatKind};

const HINTS: &[&str] = &[
    "WeChat",
    "Weixin",
    "WeChat Helper (Renderer)",
    "WeChat Helper (GPU)",
];

pub struct MacClassifier;

static INSTANCE: MacClassifier = MacClassifier;

pub fn classifier() -> &'static dyn WeChatClassifier {
    &INSTANCE
}

fn looks_wechat(hay: &str) -> bool {
    hay.contains("wechat") || hay.contains("weixin") || hay.contains("微信")
}

impl WeChatClassifier for MacClassifier {
    fn platform(&self) -> &'static str {
        "macos"
    }

    fn classify(&self, name: &str, path: Option<&str>) -> Option<WeChatKind> {
        let n = name.to_ascii_lowercase();
        let p = path.unwrap_or("").to_ascii_lowercase();
        if !looks_wechat(&n) && !looks_wechat(&p) {
            return None;
        }
        // App-service host (e.g. WeChatAppEx) runs mini programs directly.
        if n.contains("appex") {
            return Some(WeChatKind::AppEx);
        }
        // Chromium-style helper processes carry the mini-program / web content.
        if n.contains("helper") {
            if n.contains("renderer") || n.contains("gpu") || n.contains("plugin") {
                return Some(WeChatKind::AppEx);
            }
            return Some(WeChatKind::Browser);
        }
        // Weixin 4.x vs classic WeChat.
        if n == "weixin" || p.contains("weixin.app") {
            return Some(WeChatKind::Weixin);
        }
        // Anything else WeChat-branded is treated as the main client.
        Some(WeChatKind::Main)
    }

    fn classify_module(&self, module_name: &str) -> bool {
        let l = module_name.to_ascii_lowercase();
        looks_wechat(&l) || l.contains("wxapp") || l.ends_with(".dylib") && l.starts_with("libwx")
    }

    fn hints(&self) -> &'static [&'static str] {
        HINTS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_macos_names() {
        let c = MacClassifier;
        assert_eq!(c.classify("WeChat", None), Some(WeChatKind::Main));
        assert_eq!(
            c.classify("WeChat Helper (Renderer)", None),
            Some(WeChatKind::AppEx)
        );
        assert_eq!(
            c.classify("WeChat Helper (GPU)", None),
            Some(WeChatKind::AppEx)
        );
        assert_eq!(
            c.classify(
                "Weixin",
                Some("/Applications/Weixin.app/Contents/MacOS/Weixin")
            ),
            Some(WeChatKind::Weixin)
        );
        assert_eq!(c.classify("Safari", None), None);
    }
}
