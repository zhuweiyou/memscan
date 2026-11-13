//! Platform selection for WeChat process classification.
//!
//! The right classifier is chosen at compile time. Windows and macOS have
//! dedicated rules; everything else uses the generic substring matcher (which
//! still works on any OS whose `memscan` backend can enumerate processes).

use super::WeChatClassifier;

#[cfg(windows)]
mod windows;

#[cfg(target_os = "macos")]
mod macos;

#[allow(dead_code)]
mod generic;

/// Return the classifier for the current platform.
#[cfg(windows)]
pub fn current_classifier() -> &'static dyn WeChatClassifier {
    windows::classifier()
}

#[cfg(target_os = "macos")]
pub fn current_classifier() -> &'static dyn WeChatClassifier {
    macos::classifier()
}

#[cfg(not(any(windows, target_os = "macos")))]
pub fn current_classifier() -> &'static dyn WeChatClassifier {
    generic::classifier()
}

/// Expose the generic matcher for testing / explicit use on any platform.
#[allow(dead_code)]
pub fn generic_classifier() -> &'static dyn WeChatClassifier {
    generic::classifier()
}
