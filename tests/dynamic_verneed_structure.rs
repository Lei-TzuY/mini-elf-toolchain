include!("dynamic_verneed.rs");

fn verneed_file_offset(bytes: &[u8]) -> usize {
    let value_offset = dynamic_value_offset(bytes, 0x6fff_fffe);
    let address = read_u64(bytes, value_offset);
    for (segment_type, offset, virtual_address, file_size) in program_headers(bytes) {
        if segment_type != 1 {
            continue;
        }
        if address >= virtual_address && address + 16 <= virtual_address + file_size {
            return (offset + address - virtual_address) as usize;
        }
    }
    panic!("DT_VERNEED record should be file-backed")
}

#[test]
fn structural_checker_matches_gnu_fixture() {
    if !tool_available("as") || !tool_available("ld") || !tool_available("readelf") {
        return;
    }
    let dir = temp_dir("verneed-structure-gnu");
    let shared = build_versioned_consumer(&dir);
    let gnu = Command::new("readelf")
        .arg("-VW")
        .arg(&shared)
        .output()
        .unwrap();
    assert!(gnu.status.success());
    assert!(String::from_utf8_lossy(&gnu.stdout).contains("VERS_1"));

    let ours = Command::new(env!("CARGO_BIN_EXE_mini-elf-verneed-structure"))
        .arg(&shared)
        .output()
        .unwrap();
    assert!(
        ours.status.success(),
        "{}",
        String::from_utf8_lossy(&ours.stderr)
    );
    assert!(String::from_utf8_lossy(&ours.stdout).contains("forward and non-overlapping"));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn overlapping_vn_aux_is_rejected_atomically() {
    if !tool_available("as") || !tool_available("ld") {
        return;
    }
    let dir = temp_dir("verneed-structure-overlap");
    let good = build_versioned_consumer(&dir);
    let bad = dir.join("bad.so");
    let mut bytes = fs::read(&good).unwrap();
    let offset = verneed_file_offset(&bytes);
    bytes[offset + 8..offset + 12].copy_from_slice(&8_u32.to_le_bytes());
    fs::write(&bad, bytes).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-verneed-structure"))
        .arg(&good)
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty(), "stdout must remain atomic");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("vn_aux 8 overlaps"), "{stderr}");
    let _ = fs::remove_dir_all(dir);
}
