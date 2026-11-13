//! Scan **all** WeChat/Weixin processes anchored on `Bearer` / `Authorization`
//! and extract the token that follows. Useful because the exact token is usually
//! transient and lives only in whichever process performed the HTTP request.
//!
//! Usage:
//!   cargo run --example bearer_all -p memscan

use std::collections::HashSet;

use memscan::{
    enumerate_processes, open_process, scan_text_by_pid, Address, StringEncoding, TextScanOptions,
};

fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'+' | b'/' | b'=')
}

fn find_sub(hay: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    if from >= hay.len() {
        return None;
    }
    memchr::memmem::find(&hay[from..], needle).map(|p| p + from)
}

fn tokens_via_ascii(buf: &[u8], anchor: &[u8]) -> Vec<String> {
    let lower = buf.to_ascii_lowercase();
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(pos) = find_sub(&lower, from, anchor) {
        let mut j = pos + anchor.len();
        while j < buf.len() && matches!(buf[j], b' ' | b'\t' | b':' | b'"' | b'\'') {
            j += 1;
        }
        let start = j;
        while j < buf.len() && is_token_byte(buf[j]) {
            j += 1;
        }
        if j - start >= 16 {
            out.push(String::from_utf8_lossy(&buf[start..j]).into_owned());
        }
        from = pos + anchor.len();
    }
    out
}

fn tokens_via_utf16(buf: &[u8], offset: usize, anchor: &str) -> Vec<String> {
    let mut s = String::new();
    let mut i = offset;
    while i + 1 < buf.len() {
        let u = u16::from_le_bytes([buf[i], buf[i + 1]]);
        s.push(char::from_u32(u as u32).unwrap_or('\u{fffd}'));
        i += 2;
    }
    let lower = s.to_ascii_lowercase();
    let alen = anchor.len();
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(pos) = lower[from..].find(anchor).map(|p| p + from) {
        let rest: Vec<char> = s[pos + alen..].chars().collect();
        let mut k = 0;
        while k < rest.len() && matches!(rest[k], ' ' | '\t' | ':' | '"' | '\'') {
            k += 1;
        }
        let start = k;
        let mut tok = String::new();
        while k < rest.len()
            && (rest[k].is_ascii_alphanumeric()
                || matches!(rest[k], '.' | '_' | '-' | '+' | '/' | '='))
        {
            tok.push(rest[k]);
            k += 1;
        }
        if k - start >= 16 {
            out.push(tok);
        }
        from = pos + alen;
    }
    out
}

fn main() -> memscan::Result<()> {
    let targets: Vec<_> = enumerate_processes()?
        .into_iter()
        .filter(|p| {
            let n = p.name.to_ascii_lowercase();
            n.contains("wechat") || n.contains("weixin")
        })
        .collect();
    println!(
        "扫描 {} 个微信相关进程，锚点 Bearer / Authorization\n",
        targets.len()
    );

    let mut seen: HashSet<String> = HashSet::new();
    let mut openings = 0usize;

    for p in &targets {
        let process = match open_process(p.pid) {
            Ok(x) => x,
            Err(_) => continue,
        };
        openings += 1;
        let mut proc_tokens: Vec<(String, String, String)> = Vec::new(); // (ctx, token, addr)

        for (encoding, lab) in [
            (StringEncoding::Utf8, "u8"),
            (StringEncoding::Utf16Le, "u16"),
        ] {
            let opts = TextScanOptions {
                writable_only: true,
                case_insensitive: true,
                encoding,
                max_results: Some(3000),
                ..Default::default()
            };
            for anchor in ["Bearer", "Authorization"] {
                let hits = match scan_text_by_pid(p.pid, anchor, &opts) {
                    Ok(h) => h,
                    Err(_) => continue,
                };
                for m in &hits {
                    let addr = m.address.get();
                    let start = addr.saturating_sub(16);
                    let mut buf = vec![0u8; 448];
                    let got = process
                        .read_memory(Address::new(start), &mut buf)
                        .unwrap_or(0);
                    buf.truncate(got);
                    let toks = if encoding == StringEncoding::Utf8 {
                        let mut t = tokens_via_ascii(&buf, b"bearer");
                        if t.is_empty() {
                            t = tokens_via_ascii(&buf, b"authorization");
                        }
                        t
                    } else {
                        let off = (addr - start) % 2;
                        let mut t = tokens_via_utf16(&buf, off, "bearer");
                        if t.is_empty() {
                            t = tokens_via_utf16(&buf, off, "authorization");
                        }
                        t.extend(tokens_via_utf16(&buf, (off + 1) % 2, "bearer"));
                        t
                    };
                    for tok in toks {
                        if seen.insert(tok.clone()) {
                            proc_tokens.push((
                                format!("{lab}/{anchor}"),
                                tok,
                                format!("{}", m.address),
                            ));
                        }
                    }
                }
            }
        }

        if !proc_tokens.is_empty() {
            println!("[{}] {}  ({} MB)", p.pid, p.name, p.working_set / 1048576);
            for (ctx, tok, addr) in proc_tokens {
                println!("   {:<16} @ {:<14}  {}", ctx, addr, tok);
            }
        }
    }

    println!(
        "\n扫描了 {} 个可打开的进程，去重后共 {} 个 token 候选。",
        openings,
        seen.len()
    );
    if seen.is_empty() {
        println!("未发现滞留的 Bearer token —— 通常是因为它只在发包瞬间短暂存在于可写堆。");
    }
    Ok(())
}
