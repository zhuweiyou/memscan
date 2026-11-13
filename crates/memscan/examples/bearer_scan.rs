//! Locate `Authorization: Bearer <token>` style secrets in process memory.
//!
//! Strategy: search for the anchor `Bearer` (case-insensitive) in both
//! UTF-8/ANSI and UTF-16LE, then extract the token characters that follow it.
//! You can also pass known token value(s) to search for literally.
//!
//! Usage:
//!   cargo run --example bearer_scan -p memscan
//!   cargo run --example bearer_scan -p memscan -- d5b425733abe3e2ff5f5cb23ee5df793312a8ab7

use std::collections::HashSet;

use memscan::{
    open_process, resolve_pid, scan_text_by_pid, Address, StringEncoding, TextScanOptions,
};

fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'+' | b'/' | b'=')
}

/// Extract tokens that follow "bearer" in an ASCII/UTF-8 buffer.
fn tokens_after_bearer_ascii(buf: &[u8]) -> Vec<String> {
    let lower = buf.to_ascii_lowercase();
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(pos) = find_sub(&lower, from, b"bearer") {
        let mut j = pos + b"bearer".len();
        while j < buf.len() && matches!(buf[j], b' ' | b'\t' | b':') {
            j += 1;
        }
        let start = j;
        while j < buf.len() && is_token_byte(buf[j]) {
            j += 1;
        }
        if j - start >= 16 {
            out.push(String::from_utf8_lossy(&buf[start..j]).into_owned());
        }
        from = pos + b"bearer".len();
    }
    out
}

/// Extract tokens that follow "bearer" in a UTF-16LE buffer at `offset`.
fn tokens_after_bearer_utf16(buf: &[u8], offset: usize) -> Vec<String> {
    let mut s = String::new();
    let mut i = offset;
    while i + 1 < buf.len() {
        let u = u16::from_le_bytes([buf[i], buf[i + 1]]);
        s.push(char::from_u32(u as u32).unwrap_or('\u{fffd}'));
        i += 2;
    }
    let lower = s.to_ascii_lowercase();
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(pos) = lower[from..].find("bearer").map(|p| p + from) {
        let rest: Vec<char> = s[pos + 6..].chars().collect();
        let mut k = 0;
        while k < rest.len() && matches!(rest[k], ' ' | '\t' | ':') {
            k += 1;
        }
        let start = k;
        let mut tok = String::new();
        while k < rest.len() && is_token_char(rest[k]) {
            tok.push(rest[k]);
            k += 1;
        }
        if k - start >= 16 {
            out.push(tok);
        }
        from = pos + 6;
    }
    out
}

fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+' | '/' | '=')
}

fn find_sub(hay: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    if from >= hay.len() {
        return None;
    }
    memchr::memmem::find(&hay[from..], needle).map(|p| p + from)
}

fn main() -> memscan::Result<()> {
    let direct: Vec<String> = std::env::args().skip(1).collect();
    let pid = resolve_pid("WeChatAppEx")?;
    let process = open_process(pid)?;
    println!("目标进程: WeChatAppEx pid = {pid}\n");

    let mut found_tokens: HashSet<String> = HashSet::new();

    // --- 1) Anchor on "Bearer" and extract the token that follows ---
    for (encoding, label) in [
        (StringEncoding::Utf8, "UTF-8/ANSI"),
        (StringEncoding::Utf16Le, "UTF-16LE"),
    ] {
        for writable_only in [true, false] {
            let scope = if writable_only { "可写" } else { "全可读" };
            let opts = TextScanOptions {
                writable_only,
                case_insensitive: true,
                encoding,
                max_results: Some(2000),
                ..Default::default()
            };
            let hits = scan_text_by_pid(pid, "Bearer", &opts)?;
            if hits.is_empty() {
                continue;
            }
            println!(
                "=== 锚点 'Bearer' [{}·{}] 命中 {} 处 ===",
                label,
                scope,
                hits.len()
            );
            for m in &hits {
                let addr = m.address.get();
                let start = addr.saturating_sub(8);
                let mut buf = vec![0u8; 320];
                let got = process
                    .read_memory(Address::new(start), &mut buf)
                    .unwrap_or(0);
                buf.truncate(got);
                let toks = if encoding == StringEncoding::Utf8 {
                    tokens_after_bearer_ascii(&buf)
                } else {
                    let mut t = tokens_after_bearer_utf16(&buf, (addr - start) % 2);
                    t.extend(tokens_after_bearer_utf16(&buf, ((addr - start) + 1) % 2));
                    t
                };
                for tok in toks {
                    if found_tokens.insert(tok.clone()) {
                        println!("  @ {}  Bearer → {}", m.address, tok);
                    }
                }
            }
            println!();
        }
    }

    // --- 2) Directly search known token value(s), if provided ---
    for token in &direct {
        println!("=== 直接搜索 token '{}' ===", token);
        let mut any = false;
        for encoding in [StringEncoding::Utf8, StringEncoding::Utf16Le] {
            for writable_only in [true, false] {
                let opts = TextScanOptions {
                    writable_only,
                    case_insensitive: false,
                    encoding,
                    max_results: Some(50),
                    ..Default::default()
                };
                let hits = scan_text_by_pid(pid, token, &opts)?;
                if !hits.is_empty() {
                    any = true;
                    let scope = if writable_only { "可写" } else { "全可读" };
                    println!(
                        "  [{:?}·{}] 命中 {} 处，例如 @ {}",
                        encoding,
                        scope,
                        hits.len(),
                        hits[0].address
                    );
                }
            }
        }
        if !any {
            println!("  （未找到；该 token 可能已释放/未进入该进程内存，或只在发包瞬间存在）");
        }
        println!();
    }

    println!("共抽取到 {} 个 Bearer token 候选", found_tokens.len());
    Ok(())
}
