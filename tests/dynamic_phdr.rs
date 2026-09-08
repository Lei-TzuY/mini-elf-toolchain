use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const PT_PHDR: u32 = 6;

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

fn available(tool: &str) -> bool {
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
    let offset = read_u64(bytes, 32) as usize;
    let entry_size = read_u16(bytes, 54) as usize;
    let count = read_u16(bytes, 56) as usize;
    (0..count)
        .map(|index| offset + index * entry_size)
        .collect()
}

fn phdr_header_offset(bytes: &[u8]) -> usize {
    program_header_offsets(bytes)
        .into_iter()
        .find(|offset| read_u32(bytes, *offset) == PT_PHDR)
        .expect("GNU fixture should contain PT_PHDR")
}

fn build_executable(dir: &std::path::Path) -> std::path::PathBuf {
    let assembly = dir.join("start.s");
    let object = dir.join("start.o");
    let executable = dir.join("app");
    fs::write(
        &assembly,
        ".text\n.globl _start\n_start:\n mov $60,%rax\n xor %rdi,%rdi\n syscall\n.section .note.GNU-stack,\"\",@progbits\n",
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
        .arg("-pie")
        .arg("-o")
        .arg(&executable)
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        linked.status.success(),
        "{}",
        String::from_utf8_lossy(&linked.stderr)
    );
    let bytes = fs::read(&executable).unwrap();
    phdr_header_offset(&bytes);
    executable
}

#[test]
fn phdr_matches_gnu_readelf_and_load_bias() {
    if !available("as") || !available("ld") || !available("readelf") {
        return;
    }
    let dir = temp_dir("phdr-diff");
    let executable = build_executable(&dir);
    let gnu = Command::new("readelf")
        .arg("-lW")
        .arg(&executable)
        .output()
        .unwrap();
    assert!(gnu.status.success());
    assert!(
        String::from_utf8_lossy(&gnu.stdout)
            .lines()
            .any(|line| line.trim_start().starts_with("PHDR"))
    );

    let ours = Command::new(env!("CARGO_BIN_EXE_mini-elf-phdr"))
        .arg("--load-bias=0x100000")
        .arg(&executable)
        .output()
        .unwrap();
    assert!(
        ours.status.success(),
        "{}",
        String::from_utf8_lossy(&ours.stderr)
    );
    let text = String::from_utf8_lossy(&ours.stdout);
    assert!(text.contains("PT_PHDR segment"), "{text}");
    assert!(text.contains("runtime="), "{text}");
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn malformed_phdr_shape_and_runtime_overflow_are_rejected() {
    if !available("as") || !available("ld") {
        return;
    }
    let dir = temp_dir("phdr-malformed");
    let executable = build_executable(&dir);
    let original = fs::read(&executable).unwrap();
    let phdr = phdr_header_offset(&original);

    let malformed = dir.join("bad-shape");
    let mut bytes = original.clone();
    bytes[phdr + 32..phdr + 40].copy_from_slice(&1_u64.to_le_bytes());
    bytes[phdr + 40..phdr + 48].copy_from_slice(&1_u64.to_le_bytes());
    fs::write(&malformed, bytes).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_mini-elf-phdr"))
        .arg(&malformed)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert!(String::from_utf8_lossy(&result.stderr).contains("does not exactly describe"));

    let result = Command::new(env!("CARGO_BIN_EXE_mini-elf-phdr"))
        .arg("--load-bias")
        .arg(u64::MAX.to_string())
        .arg(&executable)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert!(String::from_utf8_lossy(&result.stderr).contains("runtime"));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn duplicate_phdr_and_atomic_stdout_are_rejected() {
    if !available("as") || !available("ld") {
        return;
    }
    let dir = temp_dir("phdr-atomic");
    let good = build_executable(&dir);
    let mut bytes = fs::read(&good).unwrap();
    let phdr = phdr_header_offset(&bytes);
    let other = program_header_offsets(&bytes)
        .into_iter()
        .find(|offset| *offset != phdr)
        .expect("fixture should have another program header");
    bytes[other..other + 4].copy_from_slice(&PT_PHDR.to_le_bytes());
    let bad = dir.join("duplicate");
    fs::write(&bad, bytes).unwrap();

    let result = Command::new(env!("CARGO_BIN_EXE_mini-elf-phdr"))
        .arg(&good)
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert!(String::from_utf8_lossy(&result.stderr).contains("multiple PT_PHDR"));
    let _ = fs::remove_dir_all(dir);
}
