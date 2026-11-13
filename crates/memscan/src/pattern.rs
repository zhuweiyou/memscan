//! Byte-pattern ("AOB") matching with nibble wildcards, mirroring Cheat Engine's
//! `vtByteArray` / `vtString` / `vtUnicodeString` matchers.
//!
//! A pattern is a sequence of bytes plus a per-byte mask describing which bits are
//! significant. This supports full wildcards (`??`), nibble wildcards (`5?`, `?A`)
//! as well as exact bytes. Case-insensitive matching folds ASCII letters.

use crate::address::Address;
use crate::error::{Error, Result};
use crate::types::StringEncoding;

/// A compiled byte pattern.
#[derive(Clone, Debug)]
pub struct AobPattern {
    bytes: Vec<u8>,
    masks: Vec<u8>,
    case_insensitive: bool,
    original: String,
}

impl AobPattern {
    /// Parse a textual AOB pattern such as `"48 8B ?? 5?"` or `"488B??5?"`.
    ///
    /// Whitespace is ignored; the remaining characters must be an even number of
    /// hex nibbles where `?` denotes an unknown nibble.
    pub fn parse(aob: &str, case_insensitive: bool) -> Result<Self> {
        let compact: String = aob.chars().filter(|c| !c.is_whitespace()).collect();
        if compact.is_empty() {
            return Err(Error::InvalidPattern("empty pattern".into()));
        }
        if compact.len() % 2 != 0 {
            return Err(Error::InvalidPattern(format!(
                "odd number of hex nibbles in '{aob}'"
            )));
        }
        let chars: Vec<char> = compact.chars().collect();
        let mut bytes = Vec::with_capacity(chars.len() / 2);
        let mut masks = Vec::with_capacity(chars.len() / 2);
        let mut i = 0;
        while i < chars.len() {
            let (hv, hk) = nibble(chars[i])?;
            let (lv, lk) = nibble(chars[i + 1])?;
            let mut val = (hv << 4) | lv;
            let mask = (if hk { 0xF0 } else { 0 }) | (if lk { 0x0F } else { 0 });
            if case_insensitive && mask == 0xFF {
                val = val.to_ascii_lowercase();
            }
            bytes.push(val);
            masks.push(mask);
            i += 2;
        }
        Ok(AobPattern {
            bytes,
            masks,
            case_insensitive,
            original: aob.to_string(),
        })
    }

    /// Build a pattern from an exact byte slice (used for exact numeric scans).
    pub fn from_bytes_exact(bytes: &[u8]) -> Self {
        AobPattern {
            bytes: bytes.to_vec(),
            masks: vec![0xFF; bytes.len()],
            case_insensitive: false,
            original: bytes
                .iter()
                .map(|b| format!("{b:02X}"))
                .collect::<Vec<_>>()
                .join(" "),
        }
    }

    /// Build a byte pattern from user text.
    ///
    /// * `encoding` selects UTF-8/ANSI byte semantics or UTF-16LE wide semantics.
    /// * `case_insensitive` folds ASCII letters.
    /// * `wildcard` treats a literal `?` in the text as a full-byte wildcard
    ///   (matching CE-style `?` wildcard syntax, e.g. `we?ha?`).
    pub fn from_text(
        text: &str,
        encoding: StringEncoding,
        case_insensitive: bool,
        wildcard: bool,
    ) -> Result<Self> {
        if text.is_empty() {
            return Err(Error::InvalidPattern("empty search text".into()));
        }
        let encoding = match encoding {
            StringEncoding::Auto => StringEncoding::Utf8,
            other => other,
        };
        let mut bytes = Vec::new();
        let mut masks = Vec::new();
        match encoding {
            StringEncoding::Utf8 => {
                for &b in text.as_bytes() {
                    if wildcard && b == b'?' {
                        bytes.push(0);
                        masks.push(0);
                    } else {
                        bytes.push(if case_insensitive {
                            b.to_ascii_lowercase()
                        } else {
                            b
                        });
                        masks.push(0xFF);
                    }
                }
            }
            StringEncoding::Utf16Le => {
                for ch in text.chars() {
                    if wildcard && ch == '?' {
                        // one full wildcard code unit
                        bytes.extend_from_slice(&[0, 0]);
                        masks.extend_from_slice(&[0, 0]);
                    } else {
                        let mut buf = [0u16; 2];
                        for unit in ch.encode_utf16(&mut buf) {
                            let le = unit.to_le_bytes();
                            let low = if case_insensitive && le[1] == 0 {
                                le[0].to_ascii_lowercase()
                            } else {
                                le[0]
                            };
                            bytes.push(low);
                            masks.push(0xFF);
                            bytes.push(le[1]);
                            masks.push(0xFF);
                        }
                    }
                }
            }
            StringEncoding::Auto => unreachable!(),
        }
        if bytes.is_empty() {
            return Err(Error::InvalidPattern("empty search text".into()));
        }
        Ok(AobPattern {
            bytes,
            masks,
            case_insensitive,
            original: text.to_string(),
        })
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    #[inline]
    pub fn case_insensitive(&self) -> bool {
        self.case_insensitive
    }

    pub fn has_wildcards(&self) -> bool {
        self.masks.iter().any(|&m| m != 0xFF)
    }

    pub fn original(&self) -> &str {
        &self.original
    }

    /// Render the pattern back to a canonical `"AA BB ??"` string.
    pub fn to_aob_string(&self) -> String {
        let mut parts = Vec::with_capacity(self.bytes.len());
        for (b, m) in self.bytes.iter().zip(self.masks.iter()) {
            match m {
                0 => parts.push("??".to_string()),
                0xFF => parts.push(format!("{b:02X}")),
                0xF0 => parts.push(format!("{:X}?", b >> 4)),
                0x0F => parts.push(format!("?{:X}", b & 0x0F)),
                _ => parts.push(format!("{b:02X}")),
            }
        }
        parts.join(" ")
    }

    /// Find every starting offset in `hay` where the pattern matches.
    ///
    /// `base` is the virtual address of `hay[0]` and is used to honor `align`
    /// (matches are only reported at addresses aligned to `align` when `align > 1`).
    /// Overlapping matches are reported, matching CE's byte-by-byte scan semantics.
    pub fn find_all(&self, hay: &[u8], base: Address, align: usize) -> Vec<usize> {
        let plen = self.bytes.len();
        if plen == 0 || hay.len() < plen {
            return Vec::new();
        }
        // Fold ASCII letters once if the pattern is case-insensitive.
        let folded;
        let hay: &[u8] = if self.case_insensitive {
            folded = hay.to_ascii_lowercase();
            &folded
        } else {
            hay
        };

        let max_start = hay.len() - plen;
        let aligned = |off: usize| align <= 1 || (base.0 + off) % align == 0;

        // Fast path: no wildcards -> use a SIMD substring search.
        if self.masks.iter().all(|&m| m == 0xFF) {
            let finder = memchr::memmem::Finder::new(&self.bytes);
            let mut out = Vec::new();
            let mut pos = 0usize;
            while pos <= max_start {
                match finder.find(&hay[pos..]) {
                    Some(rel) => {
                        let abs = pos + rel;
                        if abs > max_start {
                            break;
                        }
                        if aligned(abs) {
                            out.push(abs);
                        }
                        pos = abs + 1; // allow overlapping occurrences
                    }
                    None => break,
                }
            }
            return out;
        }

        // Wildcard path: anchor on a fully-known byte if possible.
        let mut out = Vec::new();
        match self.masks.iter().position(|&m| m == 0xFF) {
            Some(anchor) => {
                let anchor_byte = self.bytes[anchor];
                let mut search_from = 0usize;
                loop {
                    let hay_end = max_start + anchor; // last valid anchor position + 1
                    if search_from > hay_end || search_from >= hay.len() {
                        break;
                    }
                    match memchr::memchr(anchor_byte, &hay[search_from..]) {
                        Some(rel) => {
                            let byte_pos = search_from + rel;
                            if byte_pos > hay_end {
                                break;
                            }
                            if byte_pos < anchor {
                                // Anchor found before the pattern could start here.
                                search_from = byte_pos + 1;
                                continue;
                            }
                            let start = byte_pos - anchor;
                            if aligned(start) && self.matches_at(hay, start) {
                                out.push(start);
                            }
                            search_from = byte_pos + 1;
                        }
                        None => break,
                    }
                }
            }
            None => {
                // No fully-known byte: brute force every candidate start.
                for start in 0..=max_start {
                    if aligned(start) && self.matches_at(hay, start) {
                        out.push(start);
                    }
                }
            }
        }
        out
    }

    /// Check whether there is a match starting at `start`.
    #[inline]
    pub fn matches_at(&self, hay: &[u8], start: usize) -> bool {
        for i in 0..self.bytes.len() {
            let mask = self.masks[i];
            if mask == 0 {
                continue;
            }
            if (hay[start + i] & mask) != (self.bytes[i] & mask) {
                return false;
            }
        }
        true
    }

    /// Return the first matching offset, if any.
    pub fn find_first(&self, hay: &[u8], base: Address, align: usize) -> Option<usize> {
        self.find_all(hay, base, align).into_iter().next()
    }
}

#[inline]
fn nibble(c: char) -> Result<(u8, bool)> {
    match c {
        '?' => Ok((0, false)),
        _ => c
            .to_digit(16)
            .map(|d| (d as u8, true))
            .ok_or_else(|| Error::InvalidPattern(format!("invalid hex nibble '{c}'"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_search() {
        let p = AobPattern::parse("57 65 43 68 61 74", false).unwrap();
        let hay = b"Hello WeChat World";
        let m = p.find_all(hay, Address::new(0), 1);
        assert_eq!(m, vec![6]);
    }

    #[test]
    fn wildcard_search() {
        let p = AobPattern::parse("57 65 ?? 43", false).unwrap();
        let m = p.find_all(b"WeXChat", Address::new(0), 1);
        assert_eq!(m, vec![0]);
    }

    #[test]
    fn nibble_wildcard() {
        // "5?" matches 0x50..0x5F
        let p = AobPattern::parse("5?", false).unwrap();
        let m = p.find_all(&[0x50, 0x5F, 0x60], Address::new(0), 1);
        assert_eq!(m, vec![0, 1]);
    }

    #[test]
    fn case_insensitive_text() {
        let p = AobPattern::from_text("wechat", StringEncoding::Utf8, true, false).unwrap();
        assert_eq!(p.find_all(b"Hello WeChat!", Address::new(0), 1), vec![6]);
    }

    #[test]
    fn utf16_text() {
        let p = AobPattern::from_text("hi", StringEncoding::Utf16Le, false, false).unwrap();
        // "hi" in UTF-16LE: 68 00 69 00
        let hay = [0u8, 0x68, 0, 0x69, 0, 0x00, 0x00, 0x00];
        // note: constructed with a leading 0 so that hi starts at offset 1? keep simple
        let m = p.find_all(&hay, Address::new(0), 1);
        assert_eq!(m, vec![1]);
    }

    #[test]
    fn wildcard_anchor_not_at_zero() {
        // Anchor byte (0x41) also occurs before the pattern start; must not underflow.
        let p = AobPattern::parse("?? 41 42", false).unwrap();
        let m = p.find_all(&[0x41, 0x41, 0x42], Address::new(0), 1);
        assert_eq!(m, vec![0]);

        // No match when only an early anchor exists.
        let p2 = AobPattern::parse("?? 41", false).unwrap();
        assert!(p2.find_all(&[0x41], Address::new(0), 1).is_empty());
    }

    #[test]
    fn overlapping() {
        let p = AobPattern::parse("61 61", false).unwrap();
        let m = p.find_all(b"aaaa", Address::new(0), 1);
        assert_eq!(m, vec![0, 1, 2]);
    }

    #[test]
    fn alignment_filter() {
        let p = AobPattern::parse("00 00 00 00", false).unwrap();
        let hay = [0u8; 8];
        let m = p.find_all(&hay, Address::new(0x1000), 4);
        assert_eq!(m, vec![0, 4]);
    }
}
