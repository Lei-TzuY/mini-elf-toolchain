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

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn program_header_offsets(bytes: &[u8]) -> Vec<usize> {
    let phoff = read_u64(bytes, 32) as usize;
    let phentsize = read_u16(bytes, 54) as usize;
    let phnum = read_u16(bytes, 56) as usize;
    (0..phnum).map(|index| phoff + index * phentsize).collect()
}

fn eh_frame_header_offset(bytes: &[u8]) -> usize {
    program_header_offsets(bytes)
        .into_iter()
        .find(|offset| read_u32(bytes, *offset) == PT_GNU_EH_FRAME)
        .expect("fixture should contain PT_GNU_EH_FRAME")
}

fn build_eh_frame_shared(dir: &std::path::Path) -> std::path::PathBuf {
    let assembly = dir.join("sample.s");
    let object = dir.join("sample.o");
    let shared = dir.join("libsample.so");
    fs::write(
        &assembly,
        ".text\n.globl exported\n.type exported,@function\nexported:\n.cfi_startproc\n  ret\n.cfi_endproc\n",
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
    let bytes = fs::read(&shared).unwrap();
    eh_frame_header_offset(&bytes);
    shared
}

fn parse_gnu_eh_frame_range(text: &str) -> (u64, u64) {
    let line = text
        .lines()
        .find(|line| line.trim_start().starts_with("GNU_EH_FRAME"))
        .expect("GNU readelf should report GNU_EH_FRAME");
    let fields = line.split_whitespace().collect::<Vec<_>>();
    assert!(fields.len() >= 6, "unexpected readelf line: {line}");
    let start = u64::from_str_radix(fields[2].trim_start_matches("0x"), 16).unwrap();
    let size = u64::from_str_radix(fields[5].trim_start_matches("0x"), 16).unwrap();
    (start, start.checked_add(size).unwrap())
}

#[test]
fn eh_frame_matches_gnu_readelf_program_header_range() {
    if !tool_available("as") || !tool_available("ld") || !tool_available("readelf") {
        return;
    }
    let dir = temp_dir("eh-frame-gnu");
    let shared = build_eh_frame_shared(&dir);
    let gnu = Command::new("readelf")
        .arg("-lW")
        .arg(&shared)
        .output()
        .unwrap();
    assert!(
        gnu.status.success(),
        "{}",
        String::from_utf8_lossy(&gnu.stderr)
    );
    let (start, end) = parse_gnu_eh_frame_range(&String::from_utf8_lossy(&gnu.stdout));

    let ours = Command::new(env!("CARGO_BIN_EXE_mini-elf-eh-frame"))
        .arg(&shared)
        .output()
        .unwrap();
    assert!(
        ours.status.success(),
        "{}",
        String::from_utf8_lossy(&ours.stderr)
    );
    let text = String::from_utf8_lossy(&ours.stdout);
    assert!(text.contains("Found 1 PT_GNU_EH_FRAME segment"), "{text}");
    assert!(text.contains("Header version: 1"), "{text}");
    assert!(
        text.contains(&format!("{start:#018x}..{end:#018x}")),
        "{text}"
    );
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn eh_frame_rejects_duplicate_segment_and_bad_header_version() {
    if !tool_available("as") || !tool_available("ld") {
        return;
    }
    let dir = temp_dir("eh-frame-malformed");
    let good = build_eh_frame_shared(&dir);
    let bytes = fs::read(&good).unwrap();
    let eh_ph = eh_frame_header_offset(&bytes);

    let mut duplicate = bytes.clone();
    let other = program_header_offsets(&duplicate)
        .into_iter()
        .find(|offset| *offset != eh_ph)
        .unwrap();
    duplicate[other..other + 4].copy_from_slice(&PT_GNU_EH_FRAME.to_le_bytes());
    let duplicate_path = dir.join("duplicate.so");
    fs::write(&duplicate_path, duplicate).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_mini-elf-eh-frame"))
        .arg(&duplicate_path)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("expected at most one"));
    assert!(result.stdout.is_empty());

    let mut bad_version = bytes;
    let data_offset = read_u64(&bad_version, eh_ph + 8) as usize;
    bad_version[data_offset] = 2;
    let bad_version_path = dir.join("bad-version.so");
    fs::write(&bad_version_path, bad_version).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_mini-elf-eh-frame"))
        .arg(&bad_version_path)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("unsupported .eh_frame_hdr version 2"));
    assert!(result.stdout.is_empty());
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn eh_frame_virtual_range_overflow_is_rejected() {
    if !tool_available("as") || !tool_available("ld") {
        return;
    }
    let dir = temp_dir("eh-frame-overflow");
    let good = build_eh_frame_shared(&dir);
    let malformed = dir.join("overflow.so");
    let mut bytes = fs::read(&good).unwrap();
    let ph = eh_frame_header_offset(&bytes);
    let memory_size = read_u64(&bytes, ph + 40);
    assert!(
        memory_size > 0,
        "fixture PT_GNU_EH_FRAME should be non-empty"
    );
    let overflowing_start = u64::MAX - memory_size + 1;
    bytes[ph + 16..ph + 24].copy_from_slice(&overflowing_start.to_le_bytes());
    fs::write(&malformed, bytes).unwrap();

    let result = Command::new(env!("CARGO_BIN_EXE_mini-elf-eh-frame"))
        .arg(&malformed)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("virtual memory range overflows u64"));
    assert!(result.stdout.is_empty());
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn load_bias_overflow_and_malformed_later_input_keep_stdout_atomic() {
    if !tool_available("as") || !tool_available("ld") {
        return;
    }
    let dir = temp_dir("eh-frame-atomic");
    let good = build_eh_frame_shared(&dir);

    let overflow = Command::new(env!("CARGO_BIN_EXE_mini-elf-eh-frame"))
        .arg("--load-bias")
        .arg(u64::MAX.to_string())
        .arg(&good)
        .output()
        .unwrap();
    assert!(!overflow.status.success());
    assert!(String::from_utf8_lossy(&overflow.stderr).contains("runtime start overflows u64"));
    assert!(overflow.stdout.is_empty());

    let malformed = dir.join("bad-version.so");
    let mut bytes = fs::read(&good).unwrap();
    let ph = eh_frame_header_offset(&bytes);
    let data_offset = read_u64(&bytes, ph + 8) as usize;
    bytes[data_offset] = 2;
    fs::write(&malformed, bytes).unwrap();

    let atomic = Command::new(env!("CARGO_BIN_EXE_mini-elf-eh-frame"))
        .arg(&good)
        .arg(&malformed)
        .output()
        .unwrap();
    assert!(!atomic.status.success());
    assert!(atomic.stdout.is_empty());
    assert!(String::from_utf8_lossy(&atomic.stderr).contains("unsupported .eh_frame_hdr version 2"));
    let _ = fs::remove_dir_all(dir);
}
