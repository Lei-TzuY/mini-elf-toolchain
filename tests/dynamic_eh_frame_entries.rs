use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const PT_GNU_EH_FRAME: u32 = 0x6474_e550;

fn temp_dir(label: &str) -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "mini-elf-toolchain-{label}-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&path).unwrap();
    path
}

fn tool_available(tool: &str) -> bool {
    Command::new(tool).arg("--version").output().is_ok()
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn read_i32(bytes: &[u8], offset: usize) -> i32 {
    i32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn program_header_offsets(bytes: &[u8]) -> Vec<usize> {
    let phoff = read_u64(bytes, 32) as usize;
    let phentsize = read_u16(bytes, 54) as usize;
    let phnum = read_u16(bytes, 56) as usize;
    (0..phnum).map(|index| phoff + index * phentsize).collect()
}

fn eh_frame_header(bytes: &[u8]) -> (usize, usize, u64) {
    let ph = program_header_offsets(bytes)
        .into_iter()
        .find(|offset| read_u32(bytes, *offset) == PT_GNU_EH_FRAME)
        .expect("fixture should contain PT_GNU_EH_FRAME");
    (
        ph,
        read_u64(bytes, ph + 8) as usize,
        read_u64(bytes, ph + 16),
    )
}

fn build_shared(dir: &std::path::Path) -> std::path::PathBuf {
    let assembly = dir.join("sample.s");
    let object = dir.join("sample.o");
    let shared = dir.join("libsample.so");
    fs::write(
        &assembly,
        ".text\n.globl alpha\n.type alpha,@function\nalpha:\n.cfi_startproc\n  nop\n  ret\n.cfi_endproc\n.globl beta\n.type beta,@function\nbeta:\n.cfi_startproc\n  nop\n  nop\n  ret\n.cfi_endproc\n",
    )
    .unwrap();
    let assembled = Command::new("as")
        .arg("--64")
        .arg("-o")
        .arg(&object)
        .arg(&assembly)
        .output()
        .unwrap();
    assert!(
        assembled.status.success(),
        "{}",
        String::from_utf8_lossy(&assembled.stderr)
    );
    let linked = Command::new("ld")
        .arg("-shared")
        .arg("--eh-frame-hdr")
        .arg("-o")
        .arg(&shared)
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        linked.status.success(),
        "{}",
        String::from_utf8_lossy(&linked.stderr)
    );
    shared
}

fn gnu_initial_locations(path: &std::path::Path) -> Vec<u64> {
    let frames = Command::new("readelf")
        .arg("-wf")
        .arg(path)
        .output()
        .unwrap();
    assert!(
        frames.status.success(),
        "{}",
        String::from_utf8_lossy(&frames.stderr)
    );
    String::from_utf8_lossy(&frames.stdout)
        .lines()
        .filter_map(|line| {
            let pc = line.split_whitespace().find(|field| field.starts_with("pc="))?;
            let start = pc.strip_prefix("pc=")?.split("..").next()?;
            u64::from_str_radix(start.trim_start_matches("0x"), 16).ok()
        })
        .collect()
}

fn ours_initial_locations(path: &std::path::Path) -> Vec<u64> {
    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-eh-frame"))
        .arg(path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            let initial = line.split_whitespace().find(|field| field.starts_with("initial="))?;
            u64::from_str_radix(initial.trim_start_matches("initial=0x"), 16).ok()
        })
        .collect()
}

#[test]
fn eh_frame_search_entries_match_gnu_fde_initial_locations() {
    if !tool_available("as") || !tool_available("ld") || !tool_available("readelf") {
        return;
    }
    let dir = temp_dir("eh-frame-entries-gnu");
    let shared = build_shared(&dir);
    let expected = gnu_initial_locations(&shared);
    let actual = ours_initial_locations(&shared);
    assert!(expected.len() >= 2, "fixture should contain multiple FDEs");
    assert_eq!(actual, expected);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn eh_frame_rejects_unsorted_search_entries() {
    if !tool_available("as") || !tool_available("ld") {
        return;
    }
    let dir = temp_dir("eh-frame-entries-order");
    let good = build_shared(&dir);
    let mut bytes = fs::read(&good).unwrap();
    let (_, data_offset, _) = eh_frame_header(&bytes);
    let count = read_u32(&bytes, data_offset + 8);
    assert!(count >= 2, "fixture should contain at least two entries");
    let first = read_i32(&bytes, data_offset + 12);
    bytes[data_offset + 20..data_offset + 24].copy_from_slice(&first.to_le_bytes());
    let malformed = dir.join("unsorted.so");
    fs::write(&malformed, bytes).unwrap();

    let result = Command::new(env!("CARGO_BIN_EXE_mini-elf-eh-frame"))
        .arg(&malformed)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("not strictly increasing"));
    assert!(result.stdout.is_empty());
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn eh_frame_rejects_entry_target_underflow_and_non_load_fde() {
    if !tool_available("as") || !tool_available("ld") {
        return;
    }
    let dir = temp_dir("eh-frame-entries-targets");
    let good = build_shared(&dir);
    let bytes = fs::read(&good).unwrap();
    let (_, data_offset, base) = eh_frame_header(&bytes);
    assert!(base < i32::MAX as u64);

    let mut underflow = bytes.clone();
    underflow[data_offset + 12..data_offset + 16].copy_from_slice(&i32::MIN.to_le_bytes());
    let underflow_path = dir.join("underflow.so");
    fs::write(&underflow_path, underflow).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_mini-elf-eh-frame"))
        .arg(&underflow_path)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("initial-location arithmetic overflows"));
    assert!(result.stdout.is_empty());

    let mut bad_fde = bytes;
    bad_fde[data_offset + 16..data_offset + 20].copy_from_slice(&i32::MAX.to_le_bytes());
    let bad_fde_path = dir.join("bad-fde.so");
    fs::write(&bad_fde_path, bad_fde).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_mini-elf-eh-frame"))
        .arg(&bad_fde_path)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("FDE address"));
    assert!(String::from_utf8_lossy(&result.stderr).contains("file-backed PT_LOAD"));
    assert!(result.stdout.is_empty());
    let _ = fs::remove_dir_all(dir);
}
