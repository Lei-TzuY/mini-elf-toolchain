use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const PT_TLS: u32 = 7;

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

fn tls_header_offset(bytes: &[u8]) -> usize {
    program_header_offsets(bytes)
        .into_iter()
        .find(|offset| read_u32(bytes, *offset) == PT_TLS)
        .expect("GNU fixture should contain PT_TLS")
}

fn build_shared_object(dir: &std::path::Path) -> std::path::PathBuf {
    let assembly = dir.join("tls.s");
    let object = dir.join("tls.o");
    let shared = dir.join("libtls.so");
    fs::write(
        &assembly,
        ".section .tdata,\"awT\",@progbits\n.p2align 3\n.globl tls_init\ntls_init:\n .quad 0x1122334455667788\n.section .tbss,\"awT\",@nobits\n.p2align 3\n.globl tls_zero\ntls_zero:\n .zero 16\n.section .note.GNU-stack,\"\",@progbits\n",
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
    tls_header_offset(&bytes);
    shared
}

#[test]
fn tls_segment_matches_gnu_readelf_and_load_bias() {
    if !available("as") || !available("ld") || !available("readelf") {
        return;
    }
    let dir = temp_dir("tls-segment-diff");
    let shared = build_shared_object(&dir);
    let gnu = Command::new("readelf")
        .arg("-lW")
        .arg(&shared)
        .output()
        .unwrap();
    assert!(gnu.status.success());
    assert!(String::from_utf8_lossy(&gnu.stdout)
        .lines()
        .any(|line| line.trim_start().starts_with("TLS")));

    let ours = Command::new(env!("CARGO_BIN_EXE_mini-elf-tls-segment"))
        .arg("--load-bias=0x100000")
        .arg(&shared)
        .output()
        .unwrap();
    assert!(
        ours.status.success(),
        "{}",
        String::from_utf8_lossy(&ours.stderr)
    );
    let text = String::from_utf8_lossy(&ours.stdout);
    assert!(text.contains("PT_TLS segment"), "{text}");
    assert!(text.contains("runtime="), "{text}");
    assert!(text.contains("zero-fill=0x10"), "{text}");
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn malformed_alignment_and_congruence_are_rejected() {
    if !available("as") || !available("ld") {
        return;
    }
    let dir = temp_dir("tls-segment-malformed");
    let shared = build_shared_object(&dir);
    let original = fs::read(&shared).unwrap();
    let tls = tls_header_offset(&original);

    let bad_alignment = dir.join("bad-alignment");
    let mut bytes = original.clone();
    bytes[tls + 48..tls + 56].copy_from_slice(&3_u64.to_le_bytes());
    fs::write(&bad_alignment, bytes).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_mini-elf-tls-segment"))
        .arg(&bad_alignment)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert!(String::from_utf8_lossy(&result.stderr).contains("power of two"));

    let bad_congruence = dir.join("bad-congruence");
    let mut bytes = original;
    let offset = read_u64(&bytes, tls + 8);
    bytes[tls + 8..tls + 16].copy_from_slice(&(offset + 1).to_le_bytes());
    fs::write(&bad_congruence, bytes).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_mini-elf-tls-segment"))
        .arg(&bad_congruence)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert!(String::from_utf8_lossy(&result.stderr).contains("incongruent"));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn runtime_overflow_and_atomic_stdout_are_rejected() {
    if !available("as") || !available("ld") {
        return;
    }
    let dir = temp_dir("tls-segment-overflow");
    let good = build_shared_object(&dir);
    let result = Command::new(env!("CARGO_BIN_EXE_mini-elf-tls-segment"))
        .arg("--load-bias")
        .arg(u64::MAX.to_string())
        .arg(&good)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert!(String::from_utf8_lossy(&result.stderr).contains("runtime"));

    let mut bytes = fs::read(&good).unwrap();
    let tls = tls_header_offset(&bytes);
    bytes[tls + 48..tls + 56].copy_from_slice(&3_u64.to_le_bytes());
    let bad = dir.join("bad-later");
    fs::write(&bad, bytes).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_mini-elf-tls-segment"))
        .arg(&good)
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    let _ = fs::remove_dir_all(dir);
}
