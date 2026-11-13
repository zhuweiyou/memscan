//! Demo: fuzzy string search for a set of constant keywords (default:
//! appid/openid/unionid/token/access_token/refresh_token/sessionid/secret) in
//! WeChatAppEx memory, and print the printable content *around* each hit.
//!
//! Both UTF-8/ANSI and UTF-16LE are scanned; matching is case-insensitive and
//! supports `?` wildcards.
//!
//! Usage:
//!   cargo run --example search_context -p memscan --            # default keywords
//!   cargo run --example search_context -p memscan -- openid token # custom keywords

use std::collections::HashSet;

use memscan::{
    open_process, resolve_pid, scan_text_by_pid, Address, StringEncoding, TextScanOptions,
};

const DEFAULT_TERMS: &[&str] = &[
    "appid",
    "openid",
    "unionid",
    "token",
    "access_token",
    "refresh_token",
    "sessionid",
    "secret",
    "authorization",
];

fn printable_runs(bytes: &[u8]) -> Vec<String> {
    let mut runs = Vec::new();
    let mut cur = String::new();
    for &b in bytes {
        if (0x20..=0x7e).contains(&b) {
            cur.push(b as char);
        } else {
            if cur.len() >= 6 {
                runs.push(std::mem::take(&mut cur));
            } else {
                cur.clear();
            }
        }
    }
    if cur.len() >= 6 {
        runs.push(cur);
    }
    runs
}

fn utf16_runs(bytes: &[u8], offset: usize) -> Vec<String> {
    let mut runs = Vec::new();
    let mut cur = String::new();
    let mut i = offset;
    while i + 1 < bytes.len() {
        let u = u16::from_le_bytes([bytes[i], bytes[i + 1]]);
        let printable = (0x20..=0x7e).contains(&u) || (0x4e00..=0x9fff).contains(&u);
        if printable {
            cur.push(char::from_u32(u as u32).unwrap_or('.'));
        } else {
            if cur.chars().count() >= 4 {
                runs.push(std::mem::take(&mut cur));
            } else {
                cur.clear();
            }
        }
        i += 2;
    }
    if cur.chars().count() >= 4 {
        runs.push(cur);
    }
    runs
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(n).collect();
        out.push('…');
        out
    }
}

fn main() -> memscan::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let terms: Vec<String> = if args.is_empty() {
        DEFAULT_TERMS.iter().map(|s| s.to_string()).collect()
    } else {
        args
    };

    let pid = resolve_pid("WeChatAppEx")?;
    println!("目标进程: WeChatAppEx pid = {pid}");
    println!(
        "搜索词: {} (忽略大小写, UTF-8 + UTF-16LE)\n",
        terms.join(", ")
    );

    let process = open_process(pid)?;

    for term in &terms {
        let needle = term.to_lowercase();
        for (encoding, label) in [
            (StringEncoding::Utf8, "UTF-8/ANSI"),
            (StringEncoding::Utf16Le, "UTF-16LE"),
        ] {
            let mut used = TextScanOptions {
                writable_only: true,
                case_insensitive: true,
                encoding,
                max_results: Some(500),
                ..Default::default()
            };
            let mut scope = "可写区域";
            let mut hits = scan_text_by_pid(pid, term, &used)?;
            // Keywords like `authorization` often live in read-only module strings,
            // so fall back to scanning all readable regions if the heap had none.
            if hits.is_empty() {
                used.writable_only = false;
                scope = "全部可读区域";
                hits = scan_text_by_pid(pid, term, &used)?;
            }
            if hits.is_empty() {
                continue;
            }
            println!(
                "===== '{}' [{}·{}] 命中 {} 处 =====",
                term,
                label,
                scope,
                hits.len()
            );

            let mut seen: HashSet<String> = HashSet::new();
            let mut printed = 0usize;
            for m in &hits {
                let addr = m.address.get();
                let start = addr.saturating_sub(200);
                let len = 200 + m.data.len() + 320;
                let mut buf = vec![0u8; len];
                let got = process
                    .read_memory(Address::new(start), &mut buf)
                    .unwrap_or(0);
                buf.truncate(got);

                let mut cands = printable_runs(&buf);
                if encoding == StringEncoding::Utf16Le {
                    cands.extend(utf16_runs(&buf, 0));
                    cands.extend(utf16_runs(&buf, 1));
                }
                // Prefer snippets that look like key/value (contain ':' or '=').
                let mut chosen: Vec<(u8, usize, String)> = cands
                    .into_iter()
                    .filter(|s| s.to_lowercase().contains(&needle))
                    .map(|s| {
                        let kv = if s.contains(':') || s.contains('=') {
                            1u8
                        } else {
                            0
                        };
                        (kv, s.len(), s)
                    })
                    .collect();
                chosen.sort_by(|a, b| b.0.cmp(&a.0).then(b.1.cmp(&a.1)));
                for (_, _, best) in chosen {
                    let snippet = truncate(&best, 360);
                    if seen.insert(snippet.clone()) {
                        println!("  @ {}  ↓\n     {}", m.address, snippet);
                        printed += 1;
                        break; // one snippet per hit
                    }
                }
                if printed >= 6 {
                    break;
                }
            }

            // Fuzzy `?term?` form (only report the count, once per term).
            if encoding == StringEncoding::Utf8 {
                let fuzzy = format!("?{}?", term);
                let fh = scan_text_by_pid(pid, &fuzzy, &used)?;
                println!("  模糊 '?{term}?' 命中: {}", fh.len());
            }
            println!();
        }
    }

    Ok(())
}
