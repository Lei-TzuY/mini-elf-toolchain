use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

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

fn build_shared(dir: &std::path::Path) -> std::path::PathBuf {
    let assembly = dir.join("sample.s");
    let object = dir.join("sample.o");
    let shared = dir.join("libsample.so");
    fs::write(&assembly, ".text\n.globl exported\nexported:\n  ret\n").unwrap();
    let assembled = Command::new("as")
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
        .arg("-soname")
        .arg("libsample.so")
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

fn dynamic_section_header(bytes: &[u8]) -> usize {
    let shoff = read_u64(bytes, 40) as usize;
    let shentsize = read_u16(bytes, 58) as usize;
    let shnum = read_u16(bytes, 60) as usize;
    (0..shnum)
        .find_map(|index| {
            let offset = shoff + index * shentsize;
            (read_u32(bytes, offset + 4) == 6).then_some(offset)
        })
        .expect("shared object should contain SHT_DYNAMIC")
}

#[test]
fn dynamic_core_facts_match_gnu_readelf() {
    if !tool_available("as") || !tool_available("ld") || !tool_available("readelf") {
        return;
    }
    let dir = temp_dir("dynamic-gnu");
    let shared = build_shared(&dir);
    let gnu = Command::new("readelf")
        .arg("-dW")
        .arg(&shared)
        .output()
        .unwrap();
    assert!(gnu.status.success());
    let gnu = String::from_utf8_lossy(&gnu.stdout);

    let ours = Command::new(env!("CARGO_BIN_EXE_mini-elf-dynamic"))
        .arg(&shared)
        .output()
        .unwrap();
    assert!(
        ours.status.success(),
        "{}",
        String::from_utf8_lossy(&ours.stderr)
    );
    let ours = String::from_utf8_lossy(&ours.stdout);
    for fact in ["SONAME", "libsample.so", "STRTAB", "SYMTAB"] {
        assert!(ours.contains(fact), "ours missing {fact}: {ours}");
        assert!(gnu.contains(fact), "GNU missing {fact}: {gnu}");
    }
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn malformed_later_dynamic_table_keeps_stdout_atomic() {
    if !tool_available("as") || !tool_available("ld") {
        return;
    }
    let dir = temp_dir("dynamic-atomic");
    let good = build_shared(&dir);
    let bad = dir.join("bad.so");
    let mut bytes = fs::read(&good).unwrap();
    let dynamic = dynamic_section_header(&bytes);
    bytes[dynamic + 56..dynamic + 64].copy_from_slice(&8u64.to_le_bytes());
    fs::write(&bad, bytes).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-dynamic"))
        .arg(&good)
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty(), "stdout must remain atomic");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("entry size 8"), "{stderr}");
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn overflowing_dynamic_section_range_is_rejected() {
    if !tool_available("as") || !tool_available("ld") {
        return;
    }
    let dir = temp_dir("dynamic-overflow");
    let shared = build_shared(&dir);
    let bad = dir.join("overflow.so");
    let mut bytes = fs::read(&shared).unwrap();
    let dynamic = dynamic_section_header(&bytes);
    bytes[dynamic + 24..dynamic + 32].copy_from_slice(&u64::MAX.to_le_bytes());
    bytes[dynamic + 32..dynamic + 40].copy_from_slice(&16u64.to_le_bytes());
    fs::write(&bad, bytes).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-dynamic"))
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("file range overflows u64"));
    let _ = fs::remove_dir_all(dir);
}
