//! Numeric value handling: parsing, reading from a byte buffer and comparing.

use std::cmp::Ordering;
use std::fmt;

use crate::error::{Error, Result};
use crate::types::VariableType;

/// A numeric value in a width-independent representation.
///
/// Integers are stored sign/zero extended into `i128`/`u128`; floats in `f64`.
/// Both sides of a comparison always originate from the same [`VariableType`], so
/// the variant is normally identical.
#[derive(Clone, Copy, Debug)]
pub enum NumericValue {
    Signed(i128),
    Unsigned(u128),
    Float(f64),
}

impl NumericValue {
    /// Parse a textual number for `ty` honoring `signed` and `hex`.
    pub fn parse(text: &str, ty: VariableType, signed: bool, hex: bool) -> Result<Self> {
        let text = text.trim();
        if text.is_empty() {
            return Err(Error::InvalidValue("empty numeric value".into()));
        }
        match ty {
            VariableType::Single | VariableType::Double => {
                let f: f64 = text
                    .parse()
                    .map_err(|_| Error::InvalidValue(format!("'{text}' is not a float")))?;
                Ok(NumericValue::Float(f))
            }
            _ if ty.is_numeric() => {
                let (negative, digits) = match text.strip_prefix('-') {
                    Some(rest) => (true, rest),
                    None => (false, text.strip_prefix('+').unwrap_or(text)),
                };
                let radix = if hex || digits.starts_with("0x") || digits.starts_with("0X") {
                    16
                } else {
                    10
                };
                let digits = digits
                    .trim_start_matches("0x")
                    .trim_start_matches("0X")
                    .trim_start_matches("0X");
                let magnitude = u128::from_str_radix(digits, radix)
                    .map_err(|_| Error::InvalidValue(format!("'{text}' is not a valid integer")))?;
                if signed {
                    let value = if negative {
                        -(magnitude as i128)
                    } else {
                        magnitude as i128
                    };
                    Ok(NumericValue::Signed(value))
                } else {
                    if negative {
                        return Err(Error::InvalidValue(format!(
                            "negative value '{text}' for unsigned type {ty}"
                        )));
                    }
                    Ok(NumericValue::Unsigned(magnitude))
                }
            }
            _ => Err(Error::InvalidRequest(format!("{ty} is not a numeric type"))),
        }
    }

    /// Read a scalar of `ty` from the start of `bytes`.
    pub fn read(bytes: &[u8], ty: VariableType, signed: bool) -> Option<Self> {
        match ty {
            VariableType::Byte => {
                let b = *bytes.first()?;
                Some(if signed {
                    NumericValue::Signed(b as i8 as i128)
                } else {
                    NumericValue::Unsigned(b as u128)
                })
            }
            VariableType::Word => {
                let b: [u8; 2] = bytes.get(0..2)?.try_into().ok()?;
                let v = u16::from_le_bytes(b);
                Some(if signed {
                    NumericValue::Signed(v as i16 as i128)
                } else {
                    NumericValue::Unsigned(v as u128)
                })
            }
            VariableType::DWord => {
                let b: [u8; 4] = bytes.get(0..4)?.try_into().ok()?;
                let v = u32::from_le_bytes(b);
                Some(if signed {
                    NumericValue::Signed(v as i32 as i128)
                } else {
                    NumericValue::Unsigned(v as u128)
                })
            }
            VariableType::Qword => {
                let b: [u8; 8] = bytes.get(0..8)?.try_into().ok()?;
                let v = u64::from_le_bytes(b);
                Some(if signed {
                    NumericValue::Signed(v as i64 as i128)
                } else {
                    NumericValue::Unsigned(v as u128)
                })
            }
            VariableType::Single => {
                let b: [u8; 4] = bytes.get(0..4)?.try_into().ok()?;
                Some(NumericValue::Float(f32::from_le_bytes(b) as f64))
            }
            VariableType::Double => {
                let b: [u8; 8] = bytes.get(0..8)?.try_into().ok()?;
                Some(NumericValue::Float(f64::from_le_bytes(b)))
            }
            _ => None,
        }
    }

    /// Compare two values of the same scan type.
    pub fn compare(&self, other: &NumericValue) -> Option<Ordering> {
        match (self, other) {
            (NumericValue::Signed(a), NumericValue::Signed(b)) => Some(a.cmp(b)),
            (NumericValue::Unsigned(a), NumericValue::Unsigned(b)) => Some(a.cmp(b)),
            (NumericValue::Float(a), NumericValue::Float(b)) => a.partial_cmp(b),
            // Mixed variants should not happen, but fall back to f64 comparison.
            _ => self.as_f64().partial_cmp(&other.as_f64()),
        }
    }

    pub fn as_f64(&self) -> f64 {
        match self {
            NumericValue::Signed(v) => *v as f64,
            NumericValue::Unsigned(v) => *v as f64,
            NumericValue::Float(v) => *v,
        }
    }

    /// `self - other` for the "increased/decreased by" comparisons.
    /// Returns `None` when the difference is not representable.
    pub fn difference(&self, other: &NumericValue) -> Option<i128> {
        match (self, other) {
            (NumericValue::Signed(a), NumericValue::Signed(b)) => Some(a - b),
            (NumericValue::Unsigned(a), NumericValue::Unsigned(b)) => {
                if a >= b {
                    Some((a - b) as i128)
                } else {
                    Some(-((b - a) as i128))
                }
            }
            _ => {
                let d = self.as_f64() - other.as_f64();
                if d.is_finite() {
                    Some(d as i128)
                } else {
                    None
                }
            }
        }
    }

    /// Little-endian byte representation for this value at width `ty`.
    pub fn to_le_bytes(&self, ty: VariableType) -> Option<Vec<u8>> {
        let bytes = match (ty, self) {
            (VariableType::Byte, NumericValue::Signed(v)) => vec![*v as i8 as u8],
            (VariableType::Byte, NumericValue::Unsigned(v)) => vec![*v as u8],
            (VariableType::Word, NumericValue::Signed(v)) => (*v as i16).to_le_bytes().to_vec(),
            (VariableType::Word, NumericValue::Unsigned(v)) => (*v as u16).to_le_bytes().to_vec(),
            (VariableType::DWord, NumericValue::Signed(v)) => (*v as i32).to_le_bytes().to_vec(),
            (VariableType::DWord, NumericValue::Unsigned(v)) => (*v as u32).to_le_bytes().to_vec(),
            (VariableType::Qword, NumericValue::Signed(v)) => (*v as i64).to_le_bytes().to_vec(),
            (VariableType::Qword, NumericValue::Unsigned(v)) => (*v as u64).to_le_bytes().to_vec(),
            (VariableType::Single, NumericValue::Float(v)) => (*v as f32).to_le_bytes().to_vec(),
            (VariableType::Double, NumericValue::Float(v)) => v.to_le_bytes().to_vec(),
            _ => return None,
        };
        Some(bytes)
    }
}

impl fmt::Display for NumericValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NumericValue::Signed(v) => write!(f, "{v}"),
            NumericValue::Unsigned(v) => write!(f, "{v}"),
            NumericValue::Float(v) => write!(f, "{v}"),
        }
    }
}
