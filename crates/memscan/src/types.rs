//! Core enumerations, deliberately mirroring Cheat Engine's `commontypedefs.pas`
//! (`TVariableType`, `TScanOption`, `TScanType`, `TRoundingType`, `TFastScanMethod`).

use std::fmt;
use std::str::FromStr;

use crate::error::{Error, Result};

/// Value type being scanned. Mirrors a subset of CE's `TVariableType` that is
/// meaningful for a CLI scanner.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum VariableType {
    Byte,
    Word,
    DWord,
    Qword,
    Single,
    Double,
    /// Raw bytes / AOB pattern (wildcards allowed).
    ByteArray,
    /// ANSI / UTF-8 byte string.
    String,
    /// UTF-16LE wide string.
    UnicodeString,
}

impl VariableType {
    /// Number of bytes a single scalar occupies, if this is a numeric type.
    pub const fn scalar_size(self) -> Option<usize> {
        match self {
            VariableType::Byte => Some(1),
            VariableType::Word => Some(2),
            VariableType::DWord => Some(4),
            VariableType::Qword => Some(8),
            VariableType::Single => Some(4),
            VariableType::Double => Some(8),
            _ => None,
        }
    }

    pub const fn is_float(self) -> bool {
        matches!(self, VariableType::Single | VariableType::Double)
    }

    pub const fn is_numeric(self) -> bool {
        self.scalar_size().is_some()
    }

    pub const fn is_string_like(self) -> bool {
        matches!(
            self,
            VariableType::String | VariableType::UnicodeString | VariableType::ByteArray
        )
    }

    /// Default fast-scan alignment for this type (CE aligns numeric scalars).
    pub const fn natural_alignment(self) -> usize {
        match self {
            VariableType::Word => 2,
            VariableType::DWord | VariableType::Single => 4,
            VariableType::Qword | VariableType::Double => 8,
            _ => 1,
        }
    }
}

impl fmt::Display for VariableType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            VariableType::Byte => "byte",
            VariableType::Word => "word",
            VariableType::DWord => "dword",
            VariableType::Qword => "qword",
            VariableType::Single => "float",
            VariableType::Double => "double",
            VariableType::ByteArray => "aob",
            VariableType::String => "string",
            VariableType::UnicodeString => "wstring",
        };
        f.write_str(s)
    }
}

impl FromStr for VariableType {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        let v = match s.to_ascii_lowercase().as_str() {
            "byte" | "u8" | "i8" | "1" => VariableType::Byte,
            "word" | "u16" | "i16" | "short" | "2" => VariableType::Word,
            "dword" | "u32" | "i32" | "int" | "4" => VariableType::DWord,
            "qword" | "u64" | "i64" | "long" | "8" => VariableType::Qword,
            "float" | "single" | "f32" => VariableType::Single,
            "double" | "f64" => VariableType::Double,
            "aob" | "bytes" | "bytearray" | "binary" | "array" => VariableType::ByteArray,
            "string" | "utf8" | "ascii" | "str" => VariableType::String,
            "wstring" | "utf16" | "utf16le" | "unicode" | "wide" => VariableType::UnicodeString,
            other => {
                return Err(Error::InvalidValue(format!("unknown value type '{other}'")));
            }
        };
        Ok(v)
    }
}

/// Comparison / scan option. Mirrors CE's `TScanOption`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ScanOption {
    UnknownValue,
    ExactValue,
    ValueBetween,
    BiggerThan,
    SmallerThan,
    IncreasedValue,
    IncreasedValueBy,
    DecreasedValue,
    DecreasedValueBy,
    Changed,
    Unchanged,
}

impl ScanOption {
    /// Whether this option is only meaningful during a *next* scan.
    pub const fn is_next_scan_only(self) -> bool {
        matches!(
            self,
            ScanOption::IncreasedValue
                | ScanOption::IncreasedValueBy
                | ScanOption::DecreasedValue
                | ScanOption::DecreasedValueBy
                | ScanOption::Changed
                | ScanOption::Unchanged
        )
    }

    /// Whether the option requires comparing against the previous value.
    pub const fn needs_previous(self) -> bool {
        matches!(
            self,
            ScanOption::IncreasedValue
                | ScanOption::IncreasedValueBy
                | ScanOption::DecreasedValue
                | ScanOption::DecreasedValueBy
                | ScanOption::Changed
                | ScanOption::Unchanged
        )
    }
}

impl fmt::Display for ScanOption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            ScanOption::UnknownValue => "unknown",
            ScanOption::ExactValue => "exact",
            ScanOption::ValueBetween => "between",
            ScanOption::BiggerThan => "bigger",
            ScanOption::SmallerThan => "smaller",
            ScanOption::IncreasedValue => "increased",
            ScanOption::IncreasedValueBy => "increased-by",
            ScanOption::DecreasedValue => "decreased",
            ScanOption::DecreasedValueBy => "decreased-by",
            ScanOption::Changed => "changed",
            ScanOption::Unchanged => "unchanged",
        };
        f.write_str(s)
    }
}

impl FromStr for ScanOption {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        let v = match s.to_ascii_lowercase().replace('_', "-").as_str() {
            "unknown" | "unknown-value" | "?" => ScanOption::UnknownValue,
            "exact" | "eq" | "=" | "==" => ScanOption::ExactValue,
            "between" | "range" => ScanOption::ValueBetween,
            "bigger" | "greater" | ">" | "gt" => ScanOption::BiggerThan,
            "smaller" | "less" | "<" | "lt" => ScanOption::SmallerThan,
            "increased" | "inc" | "+" => ScanOption::IncreasedValue,
            "increased-by" | "inc-by" => ScanOption::IncreasedValueBy,
            "decreased" | "dec" | "-" => ScanOption::DecreasedValue,
            "decreased-by" | "dec-by" => ScanOption::DecreasedValueBy,
            "changed" | "change" | "!=" => ScanOption::Changed,
            "unchanged" | "same" => ScanOption::Unchanged,
            other => {
                return Err(Error::InvalidValue(format!(
                    "unknown scan option '{other}'"
                )))
            }
        };
        Ok(v)
    }
}

/// Which scan phase produced / will produce a result. Mirrors `TScanType`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanType {
    NewScan,
    FirstScan,
    NextScan,
}

/// Float rounding mode. Kept for API compatibility with CE; integer scans ignore it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum RoundingType {
    #[default]
    Rounded,
    Extremerounded,
    Truncated,
}

/// Fast-scan alignment strategy. Mirrors `TFastScanMethod`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum FastScanMethod {
    #[default]
    NotAligned,
    /// Only addresses aligned to a configurable byte boundary are inspected.
    Aligned,
    /// Only addresses whose last N decimal digits match are inspected.
    LastDigits,
}

/// Three-state include/exclude switch, mirroring CE's `Tscanregionpreference`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum TriState {
    #[default]
    DontCare,
    Include,
    Exclude,
}

impl FromStr for TriState {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        let v = match s.to_ascii_lowercase().as_str() {
            "any" | "dontcare" | "dont-care" => TriState::DontCare,
            "include" | "only" | "yes" | "true" => TriState::Include,
            "exclude" | "no" | "false" => TriState::Exclude,
            other => return Err(Error::InvalidValue(format!("unknown tri-state '{other}'"))),
        };
        Ok(v)
    }
}

/// Text encoding used when turning user text into a byte/wide pattern.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum StringEncoding {
    /// UTF-8 / ANSI bytes (single byte per ASCII char).
    #[default]
    Utf8,
    /// UTF-16 little endian (two bytes per UTF-16 code unit) — the common case on Windows.
    Utf16Le,
    /// Use the value type's natural encoding (Utf8 for String, Utf16Le for UnicodeString).
    Auto,
}

impl FromStr for StringEncoding {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        let v = match s.to_ascii_lowercase().replace('_', "-").as_str() {
            "utf8" | "utf-8" | "ascii" | "ansi" | "mbcs" => StringEncoding::Utf8,
            "utf16" | "utf-16" | "utf16le" | "utf-16le" | "unicode" | "wide" => {
                StringEncoding::Utf16Le
            }
            "auto" => StringEncoding::Auto,
            other => {
                return Err(Error::InvalidValue(format!("unknown encoding '{other}'")));
            }
        };
        Ok(v)
    }
}
