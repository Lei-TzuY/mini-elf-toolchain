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
        .arg("-z")
        .arg("now")
        .arg("-z")
        .arg("origin")
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

fn dynamic_program_header(bytes: &[u8]) -> usize {
    let phoff = read_u64(bytes, 32) as usize;
    let phentsize = read_u16(bytes, 54) as usize;
    let phnum = read_u16(bytes, 56) as usize;
    (0..phnum)
        .find_map(|index| {
            let offset = phoff + index * phentsize;
            (read_u32(bytes, offset) == 2).then_some(offset)
        })
        .expect("shared object should contain PT_DYNAMIC")
}

#[test]
fn dynamic_flags_match_gnu_readelf_policy_names() {
    if !tool_available("as") || !tool_available("ld") || !tool_available("readelf") {
        return;
    }
    let dir = temp_dir("dynflags-gnu");
    let shared = build_shared(&dir);
    let gnu = Command::new("readelf")
        .arg("-dW")
        .arg(&shared)
        .output()
        .unwrap();
    assert!(gnu.status.success());
    let gnu = String::from_utf8_lossy(&gnu.stdout);
    let ours = Command::new(env!("CARGO_BIN_EXE_mini-elf-dynflags"))
        .arg(&shared)
        .output()
        .unwrap();
    assert!(
        ours.status.success(),
        "{}",
        String::from_utf8_lossy(&ours.stderr)
    );
    let ours = String::from_utf8_lossy(&ours.stdout);
    for fact in ["DT_FLAGS", "BIND_NOW", "ORIGIN", "DT_FLAGS_1", "NOW"] {
        assert!(ours.contains(fact), "ours missing {fact}: {ours}");
    }
    for fact in ["BIND_NOW", "ORIGIN", "NOW"] {
        assert!(gnu.contains(fact), "GNU missing {fact}: {gnu}");
    }
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn duplicate_dt_flags_in_later_input_keeps_stdout_atomic() {
    if !tool_available("as") || !tool_available("ld") {
        return;
    }
    let dir = temp_dir("dynflags-dup");
    let good = build_shared(&dir);
    let bad = dir.join("bad.so");
    let mut bytes = fs::read(&good).unwrap();
    let dynamic = dynamic_program_header(&bytes);
    let dynamic_offset = read_u64(&bytes, dynamic + 8) as usize;
    let dynamic_size = read_u64(&bytes, dynamic + 32) as usize;
    let mut first_flags = None;
    let mut victim = None;
    for offset in (dynamic_offset..dynamic_offset + dynamic_size).step_by(16) {
        let tag = read_u64(&bytes, offset);
        if tag == 30 {
            first_flags = Some(offset);
        } else if tag != 0 && tag != 0x6fff_fffb && victim.is_none() {
            victim = Some(offset);
        }
    }
    let source = first_flags.expect("ld -z now/origin should emit DT_FLAGS");
    let victim = victim.expect("dynamic table should contain another entry");
    let value = bytes[source + 8..source + 16].to_vec();
    bytes[victim..victim + 8].copy_from_slice(&30u64.to_le_bytes());
    bytes[victim + 8..victim + 16].copy_from_slice(&value);
    fs::write(&bad, bytes).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-dynflags"))
        .arg(&good)
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty(), "stdout must remain atomic");
    assert!(String::from_utf8_lossy(&output.stderr).contains("duplicate DT_FLAGS"));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn overflowing_dynamic_file_range_is_rejected() {
    if !tool_available("as") || !tool_available("ld") {
        return;
    }
    let dir = temp_dir("dynflags-overflow");
    let shared = build_shared(&dir);
    let bad = dir.join("overflow.so");
    let mut bytes = fs::read(&shared).unwrap();
    let dynamic = dynamic_program_header(&bytes);
    bytes[dynamic + 8..dynamic + 16].copy_from_slice(&u64::MAX.to_le_bytes());
    bytes[dynamic + 32..dynamic + 40].copy_from_slice(&16u64.to_le_bytes());
    bytes[dynamic + 40..dynamic + 48].copy_from_slice(&16u64.to_le_bytes());
    fs::write(&bad, bytes).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-dynflags"))
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("file range overflows u64"));
    let _ = fs::remove_dir_all(dir);
}
