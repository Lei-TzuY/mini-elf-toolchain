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

fn read_i64(bytes: &[u8], offset: usize) -> i64 {
    i64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn program_headers(bytes: &[u8]) -> Vec<(u32, u64, u64, u64)> {
    let phoff = read_u64(bytes, 32) as usize;
    let phentsize = read_u16(bytes, 54) as usize;
    let phnum = read_u16(bytes, 56) as usize;
    (0..phnum)
        .map(|index| {
            let offset = phoff + index * phentsize;
            (
                read_u32(bytes, offset),
                read_u64(bytes, offset + 8),
                read_u64(bytes, offset + 16),
                read_u64(bytes, offset + 32),
            )
        })
        .collect()
}

fn dynamic_entry_offset(bytes: &[u8], wanted_tag: i64) -> usize {
    let dynamic = program_headers(bytes)
        .into_iter()
        .find(|(segment_type, _, _, _)| *segment_type == 2)
        .expect("shared object should contain PT_DYNAMIC");
    let mut offset = dynamic.1 as usize;
    let end = (dynamic.1 + dynamic.3) as usize;
    while offset + 16 <= end {
        let tag = read_i64(bytes, offset);
        if tag == wanted_tag {
            return offset;
        }
        if tag == 0 {
            break;
        }
        offset += 16;
    }
    panic!("shared object should contain dynamic tag {wanted_tag}")
}

fn build_versioned_library(dir: &std::path::Path) -> std::path::PathBuf {
    let assembly = dir.join("lib.s");
    let object = dir.join("lib.o");
    let shared = dir.join("libversioned.so");
    let script = dir.join("versions.map");
    fs::write(
        &assembly,
        ".text\n.globl foo\n.type foo,@function\nfoo:\n  ret\n.size foo,.-foo\n",
    )
    .unwrap();
    fs::write(&script, "VERS_1 { global: foo; local: *; };\n").unwrap();
    let assembled = Command::new("as")
        .arg("-o")
        .arg(&object)
        .arg(&assembly)
        .output()
        .unwrap();
    assert!(assembled.status.success(), "{}", String::from_utf8_lossy(&assembled.stderr));
    let linked = Command::new("ld")
        .arg("-shared")
        .arg("--hash-style=sysv")
        .arg("--version-script")
        .arg(&script)
        .arg("-o")
        .arg(&shared)
        .arg(&object)
        .output()
        .unwrap();
    assert!(linked.status.success(), "{}", String::from_utf8_lossy(&linked.stderr));
    shared
}

#[test]
fn dynamic_versym_matches_gnu_readelf() {
    if !tool_available("as") || !tool_available("ld") || !tool_available("readelf") {
        return;
    }
    let dir = temp_dir("versym-gnu");
    let shared = build_versioned_library(&dir);
    let gnu = Command::new("readelf").arg("-VW").arg(&shared).output().unwrap();
    assert!(gnu.status.success());
    let gnu_text = String::from_utf8_lossy(&gnu.stdout);
    assert!(gnu_text.contains("Version symbols section"), "{gnu_text}");
    assert!(gnu_text.contains("VERS_1"), "{gnu_text}");

    let ours = Command::new(env!("CARGO_BIN_EXE_mini-elf-versym"))
        .arg(&shared)
        .output()
        .unwrap();
    assert!(ours.status.success(), "{}", String::from_utf8_lossy(&ours.stderr));
    let ours_text = String::from_utf8_lossy(&ours.stdout);
    assert!(ours_text.contains("DT_VERSYM"), "ours={ours_text}\ngnu={gnu_text}");
    assert!(ours_text.contains("index=2"), "ours={ours_text}\ngnu={gnu_text}");
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn duplicate_versym_tag_is_rejected() {
    if !tool_available("as") || !tool_available("ld") {
        return;
    }
    let dir = temp_dir("versym-duplicate");
    let shared = build_versioned_library(&dir);
    let bad = dir.join("duplicate.so");
    let mut bytes = fs::read(&shared).unwrap();
    let syment = dynamic_entry_offset(&bytes, 11);
    bytes[syment..syment + 8].copy_from_slice(&0x6fff_fff0_i64.to_le_bytes());
    fs::write(&bad, bytes).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-versym"))
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("duplicate DT_VERSYM"));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn overflowing_versym_virtual_range_is_rejected_atomically() {
    if !tool_available("as") || !tool_available("ld") {
        return;
    }
    let dir = temp_dir("versym-overflow");
    let good = build_versioned_library(&dir);
    let bad = dir.join("overflow.so");
    let mut bytes = fs::read(&good).unwrap();
    let versym = dynamic_entry_offset(&bytes, 0x6fff_fff0) + 8;
    bytes[versym..versym + 8].copy_from_slice(&(u64::MAX - 1).to_le_bytes());
    fs::write(&bad, bytes).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-versym"))
        .arg(&good)
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty(), "stdout must remain atomic");
    assert!(String::from_utf8_lossy(&output.stderr).contains("virtual range overflows u64"));
    let _ = fs::remove_dir_all(dir);
}
