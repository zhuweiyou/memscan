//! Error types shared by the whole scanner.

use crate::address::Address;
use thiserror::Error;

/// Result alias used across the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur while enumerating, reading or scanning a process.
#[derive(Debug, Error)]
pub enum Error {
    #[error("no process matched the selector: {0}")]
    NoProcess(String),

    #[error("process not found: {0}")]
    ProcessNotFound(String),

    #[error("failed to open process {pid}: {source}")]
    OpenProcess {
        pid: u32,
        #[source]
        source: std::io::Error,
    },

    #[error("invalid AOB/byte pattern: {0}")]
    InvalidPattern(String),

    #[error("invalid scan value: {0}")]
    InvalidValue(String),

    #[error("invalid or unsupported scan request: {0}")]
    InvalidRequest(String),

    #[error("memory read failed at {addr}: {source}")]
    Read {
        addr: Address,
        #[source]
        source: std::io::Error,
    },

    #[error("the operation was cancelled by the caller")]
    Cancelled,

    #[error("this feature is unsupported on the current platform: {0}")]
    Unsupported(String),

    #[error("win32 call `{call}` failed with code {code}")]
    Win32 { call: &'static str, code: u32 },

    #[error("{0}")]
    Other(String),
}

impl Error {
    pub fn win32(call: &'static str) -> Self {
        // Kept for API compatibility; the portable backend no longer calls Win32
        // directly, so the OS error code is unavailable here.
        Error::Win32 { call, code: 0 }
    }

    pub fn other(msg: impl Into<String>) -> Self {
        Error::Other(msg.into())
    }
}
