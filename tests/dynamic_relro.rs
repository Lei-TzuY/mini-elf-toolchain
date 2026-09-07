use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const PT_GNU_RELRO: u32 = 0x6474_e552;

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

fn relro_header_offset(bytes: &[u8]) -> usize {
    program_header_offsets(bytes)
        .into_iter()
        .find(|offset| read_u32(bytes, *offset) == PT_GNU_RELRO)
        .expect("fixture should contain PT_GNU_RELRO")
}

fn build_relro_shared(dir: &std::path::Path) -> std::path::PathBuf {
    let assembly = dir.join("sample.s");
    let object = dir.join("sample.o");
    let shared = dir.join("libsample.so");
    fs::write(
        &assembly,
        ".text\n.globl exported\n.type exported,@function\nexported:\n  ret\n.section .data.rel.ro,\"aw\",@progbits\n.globl protected_word\n.type protected_word,@object\n.size protected_word,8\nprotected_word:\n  .quad exported\n",
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
        .arg("-z")
        .arg("relro")
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
    relro_header_offset(&bytes);
    shared
}

fn parse_gnu_relro_range(text: &str) -> (u64, u64) {
    let line = text
        .lines()
        .find(|line| line.trim_start().starts_with("GNU_RELRO"))
        .expect("GNU readelf should report GNU_RELRO");
    let fields = line.split_whitespace().collect::<Vec<_>>();
    assert!(fields.len() >= 6, "unexpected readelf line: {line}");
    let start = u64::from_str_radix(fields[2].trim_start_matches("0x"), 16).unwrap();
    let size = u64::from_str_radix(fields[5].trim_start_matches("0x"), 16).unwrap();
    (start, start.checked_add(size).unwrap())
}

#[test]
fn relro_matches_gnu_readelf_program_header_range() {
    if !tool_available("as") || !tool_available("ld") || !tool_available("readelf") {
        return;
    }
    let dir = temp_dir("relro-gnu");
    let shared = build_relro_shared(&dir);
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
    let (start, end) = parse_gnu_relro_range(&String::from_utf8_lossy(&gnu.stdout));

    let ours = Command::new(env!("CARGO_BIN_EXE_mini-elf-relro"))
        .arg(&shared)
        .output()
        .unwrap();
    assert!(
        ours.status.success(),
        "{}",
        String::from_utf8_lossy(&ours.stderr)
    );
    let ours_text = String::from_utf8_lossy(&ours.stdout);
    assert!(
        ours_text.contains("Found 1 PT_GNU_RELRO segment(s)"),
        "{ours_text}"
    );
    assert!(
        ours_text.contains(&format!("{start:#018x}..{end:#018x}")),
        "ours={ours_text}"
    );
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn relro_load_bias_reports_runtime_range() {
    if !tool_available("as") || !tool_available("ld") {
        return;
    }
    let dir = temp_dir("relro-bias");
    let shared = build_relro_shared(&dir);
    let bytes = fs::read(&shared).unwrap();
    let ph = relro_header_offset(&bytes);
    let start = read_u64(&bytes, ph + 16);
    let size = read_u64(&bytes, ph + 40);
    let bias = 0x7000_0000_0000_u64;
    let runtime_start = bias + start;
    let runtime_end = runtime_start + size;

    let ours = Command::new(env!("CARGO_BIN_EXE_mini-elf-relro"))
        .arg("--load-bias")
        .arg(format!("{bias:#x}"))
        .arg(&shared)
        .output()
        .unwrap();
    assert!(
        ours.status.success(),
        "{}",
        String::from_utf8_lossy(&ours.stderr)
    );
    let ours_text = String::from_utf8_lossy(&ours.stdout);
    assert!(
        ours_text.contains(&format!("{runtime_start:#018x}..{runtime_end:#018x}")),
        "{ours_text}"
    );
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn relro_virtual_range_overflow_is_rejected() {
    if !tool_available("as") || !tool_available("ld") {
        return;
    }
    let dir = temp_dir("relro-overflow");
    let shared = build_relro_shared(&dir);
    let malformed = dir.join("overflow.so");
    let mut bytes = fs::read(&shared).unwrap();
    let ph = relro_header_offset(&bytes);
    bytes[ph + 16..ph + 24].copy_from_slice(&(u64::MAX - 3).to_le_bytes());
    bytes[ph + 40..ph + 48].copy_from_slice(&8_u64.to_le_bytes());
    fs::write(&malformed, bytes).unwrap();

    let ours = Command::new(env!("CARGO_BIN_EXE_mini-elf-relro"))
        .arg(&malformed)
        .output()
        .unwrap();
    assert!(!ours.status.success());
    assert!(
        String::from_utf8_lossy(&ours.stderr).contains("PT_GNU_RELRO segment")
            && String::from_utf8_lossy(&ours.stderr).contains("overflows u64"),
        "{}",
        String::from_utf8_lossy(&ours.stderr)
    );
    assert!(ours.stdout.is_empty());
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn relro_must_be_contained_in_load_memory_range() {
    if !tool_available("as") || !tool_available("ld") {
        return;
    }
    let dir = temp_dir("relro-containment");
    let shared = build_relro_shared(&dir);
    let malformed = dir.join("outside.so");
    let mut bytes = fs::read(&shared).unwrap();
    let ph = relro_header_offset(&bytes);
    bytes[ph + 16..ph + 24].copy_from_slice(&0x7000_0000_0000_u64.to_le_bytes());
    bytes[ph + 40..ph + 48].copy_from_slice(&8_u64.to_le_bytes());
    fs::write(&malformed, bytes).unwrap();

    let ours = Command::new(env!("CARGO_BIN_EXE_mini-elf-relro"))
        .arg(&malformed)
        .output()
        .unwrap();
    assert!(!ours.status.success());
    assert!(
        String::from_utf8_lossy(&ours.stderr)
            .contains("is not contained in a PT_LOAD memory range"),
        "{}",
        String::from_utf8_lossy(&ours.stderr)
    );
    assert!(ours.stdout.is_empty());
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn load_bias_overflow_and_malformed_later_input_keep_stdout_atomic() {
    if !tool_available("as") || !tool_available("ld") {
        return;
    }
    let dir = temp_dir("relro-atomic");
    let good = build_relro_shared(&dir);

    let overflow = Command::new(env!("CARGO_BIN_EXE_mini-elf-relro"))
        .arg("--load-bias")
        .arg(u64::MAX.to_string())
        .arg(&good)
        .output()
        .unwrap();
    assert!(!overflow.status.success());
    assert!(String::from_utf8_lossy(&overflow.stderr).contains("runtime start overflows u64"));
    assert!(overflow.stdout.is_empty());

    let malformed = dir.join("outside.so");
    let mut bytes = fs::read(&good).unwrap();
    let ph = relro_header_offset(&bytes);
    bytes[ph + 16..ph + 24].copy_from_slice(&0x7000_0000_0000_u64.to_le_bytes());
    bytes[ph + 40..ph + 48].copy_from_slice(&8_u64.to_le_bytes());
    fs::write(&malformed, bytes).unwrap();

    let atomic = Command::new(env!("CARGO_BIN_EXE_mini-elf-relro"))
        .arg(&good)
        .arg(&malformed)
        .output()
        .unwrap();
    assert!(!atomic.status.success());
    assert!(atomic.stdout.is_empty());
    assert!(String::from_utf8_lossy(&atomic.stderr)
        .contains("is not contained in a PT_LOAD memory range"));
    let _ = fs::remove_dir_all(dir);
}
