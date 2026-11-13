//! Generic WeChat process classification for platforms without dedicated rules.
//!
//! Matches any process whose name or image path contains a WeChat-ish token. Used
//! on Linux / other Unix when a `memscan` backend becomes available.

use super::super::{WeChatClassifier, WeChatKind};

const HINTS: &[&str] = &["wechat", "weixin", "wxapp"];

pub struct GenericClassifier;

static INSTANCE: GenericClassifier = GenericClassifier;

pub fn classifier() -> &'static dyn WeChatClassifier {
    &INSTANCE
}

fn haystack(name: &str, path: Option<&str>) -> String {
    let mut s = name.to_ascii_lowercase();
    if let Some(p) = path {
        s.push(' ');
        s.push_str(&p.to_ascii_lowercase());
    }
    s
}

impl WeChatClassifier for GenericClassifier {
    fn platform(&self) -> &'static str {
        "generic"
    }

    fn classify(&self, name: &str, path: Option<&str>) -> Option<WeChatKind> {
        let hay = haystack(name, path);
        if !(hay.contains("wechat") || hay.contains("weixin") || hay.contains("wxapp")) {
            return None;
        }
        if hay.contains("appex") || hay.contains("renderer") || hay.contains("helper") {
            Some(WeChatKind::AppEx)
        } else if hay.contains("browser") {
            Some(WeChatKind::Browser)
        } else if hay.contains("weixin") {
            Some(WeChatKind::Weixin)
        } else {
            Some(WeChatKind::Main)
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
