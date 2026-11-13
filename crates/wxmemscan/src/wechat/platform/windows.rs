//! Windows WeChat process classification (matches `*.exe` image names).

use super::super::{WeChatClassifier, WeChatKind};

/// Mini-program / app-service host process.
pub const PROCESS_APP_EXE: &str = "WeChatAppEx.exe";
/// Built-in browser process.
pub const PROCESS_BROWSER: &str = "WechatBrowser.exe";
/// Classic WeChat main client (3.x).
pub const PROCESS_MAIN: &str = "WeChat.exe";
/// New Weixin 4.x main client.
pub const PROCESS_WEIXIN: &str = "Weixin.exe";

/// All process names we consider "WeChat" on Windows.
pub const ALL_PROCESS_NAMES: &[&str] = &[
    PROCESS_APP_EXE,
    PROCESS_BROWSER,
    PROCESS_MAIN,
    PROCESS_WEIXIN,
];

const HINTS: &[&str] = ALL_PROCESS_NAMES;

pub struct WindowsClassifier;

static INSTANCE: WindowsClassifier = WindowsClassifier;

pub fn classifier() -> &'static dyn WeChatClassifier {
    &INSTANCE
}

fn base_name(name_or_path: &str) -> &str {
    name_or_path
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(name_or_path)
}

impl WeChatClassifier for WindowsClassifier {
    fn platform(&self) -> &'static str {
        "windows"
    }

    fn classify(&self, name: &str, path: Option<&str>) -> Option<WeChatKind> {
        let candidate = if !name.is_empty() {
            name
        } else {
            path.unwrap_or("")
        };
        let base = base_name(candidate);
        if base.eq_ignore_ascii_case(PROCESS_APP_EXE) {
            Some(WeChatKind::AppEx)
        } else if base.eq_ignore_ascii_case(PROCESS_BROWSER) {
            Some(WeChatKind::Browser)
        } else if base.eq_ignore_ascii_case(PROCESS_MAIN) {
            Some(WeChatKind::Main)
        } else if base.eq_ignore_ascii_case(PROCESS_WEIXIN) {
            Some(WeChatKind::Weixin)
        } else {
            None
        }
    }

    fn classify_module(&self, module_name: &str) -> bool {
        let l = module_name.to_ascii_lowercase();
        l.contains("wechat") || l.contains("weixin") || l.starts_with("wx")
    }

    fn hints(&self) -> &'static [&'static str] {
        HINTS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_windows_names() {
        let c = WindowsClassifier;
        assert_eq!(c.classify("WeChatAppEx.exe", None), Some(WeChatKind::AppEx));
        assert_eq!(
            c.classify("WechatBrowser.exe", None),
            Some(WeChatKind::Browser)
        );
        assert_eq!(c.classify("WeChat.exe", None), Some(WeChatKind::Main));
        assert_eq!(c.classify("Weixin.exe", None), Some(WeChatKind::Weixin));
        assert_eq!(c.classify("notepad.exe", None), None);
        // path only
        assert_eq!(
            c.classify("", Some("C:\\Program Files\\Tencent\\WeChat\\WeChat.exe")),
            Some(WeChatKind::Main)
        );
    }
}
