//! End-to-end engine test: scan our own process for markers we planted.
//!
//! This exercises the real platform backend (region enumeration, memory read,
//! pattern matching, result storage and the next-scan page cache) without needing
//! any external target process.

use memscan::{
    Address, FirstScanRequest, MemScan, NextScanRequest, RegionFilter, ScanControl, ScanOption,
    TriState, VariableType,
};

/// A page-aligned, stable scratch page. Restricting the scan to exactly this page
/// keeps the test deterministic: unlike scanning the whole heap/stack, no transient
/// copies of the markers can appear in worker buffers or reused stack slots.
#[repr(C, align(4096))]
struct AlignedPage([u8; 4096]);

#[test]
fn scans_own_process_for_string_and_aob() {
    let marker = format!(
        "MEMSCAN_SELFTEST_{}_{}_END",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let aob: [u8; 7] = [0xC0, 0xFF, 0xEE, 0x11, 0x22, 0x33, 0x44];

    // Plant the markers in one page-aligned allocation and scan only that page.
    let mut page = Box::new(AlignedPage([0u8; 4096]));
    page.0[0x100..0x100 + marker.len()].copy_from_slice(marker.as_bytes());
    page.0[0x200..0x200 + aob.len()].copy_from_slice(&aob);
    let base = page.0.as_ptr() as usize;
    let start = Address::new(base);
    let stop = Address::new(base + 4096);
    std::hint::black_box(&page);

    let pid = std::process::id();
    let mut scan = MemScan::attach(pid).expect("attach self");

    // Only private, writable regions (the heap page) where our markers live.
    let filter = RegionFilter {
        writable: TriState::Include,
        include_image: false,
        include_mapped: false,
        ..Default::default()
    };

    let control = ScanControl::new();

    let mut str_req = FirstScanRequest::default();
    str_req.value_type = VariableType::String;
    str_req.value = marker.clone();
    str_req.case_insensitive = false;
    str_req.wildcard = false;
    str_req.filter = filter.clone();
    str_req.start = start;
    str_req.stop = stop;
    let s1 = scan.first_scan(&str_req, &control).expect("string scan");
    assert_eq!(s1.matches, 1, "expected exactly the planted string marker");

    let mut aob_req = FirstScanRequest::default();
    aob_req.value_type = VariableType::ByteArray;
    aob_req.value = "C0 FF EE 11 22 33 44".to_string();
    aob_req.filter = filter;
    aob_req.start = start;
    aob_req.stop = stop;
    let s2 = scan.first_scan(&aob_req, &control).expect("aob scan");
    assert_eq!(s2.matches, 1, "expected exactly the planted AOB marker");

    // Nothing changed, so an "unchanged" rescan keeps the hit.
    let s3 = scan
        .next_scan(
            &NextScanRequest {
                option: ScanOption::Unchanged,
                ..Default::default()
            },
            &control,
        )
        .expect("rescan");
    assert_eq!(s3.total_found, s2.matches);
}

#[test]
fn scans_own_process_by_name() {
    // High-level API: process name + fuzzy string -> matches.
    let exe = std::env::current_exe().unwrap();
    let name = exe.file_name().unwrap().to_string_lossy().to_string();
    let marker = format!("MEMSCAN_API_{}_TOKEN", std::process::id());
    std::hint::black_box(&marker);

    let opts = memscan::TextScanOptions {
        writable_only: true,
        max_results: Some(100),
        ..Default::default()
    };
    let hits = memscan::scan_text_by_name(&name, &marker, &opts).expect("scan by name");
    assert!(
        hits.iter().any(|m| m.pid == std::process::id()),
        "expected to find our own marker via scan_text_by_name"
    );
}
