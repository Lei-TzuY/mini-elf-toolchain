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
    fs::write(
        &assembly,
        ".text\n.globl init_hook\n.type init_hook,@function\ninit_hook:\n  ret\n.globl fini_hook\n.type fini_hook,@function\nfini_hook:\n  ret\n.section .init_array,\"aw\",@init_array\n.quad init_hook\n.section .fini_array,\"aw\",@fini_array\n.quad fini_hook\n",
    )
    .unwrap();
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

fn dynamic_entry_offset(bytes: &[u8], wanted_tag: u64) -> usize {
    let dynamic = dynamic_program_header(bytes);
    let dynamic_offset = read_u64(bytes, dynamic + 8) as usize;
    let dynamic_size = read_u64(bytes, dynamic + 32) as usize;
    (dynamic_offset..dynamic_offset + dynamic_size)
        .step_by(16)
        .find(|offset| read_u64(bytes, *offset) == wanted_tag)
        .unwrap_or_else(|| panic!("missing dynamic tag {wanted_tag}"))
}

#[test]
fn lifecycle_arrays_match_gnu_readelf_dynamic_tags() {
    if !tool_available("as") || !tool_available("ld") || !tool_available("readelf") {
        return;
    }
    let dir = temp_dir("dyninit-gnu");
    let shared = build_shared(&dir);
    let gnu = Command::new("readelf")
        .arg("-dW")
        .arg(&shared)
        .output()
        .unwrap();
    assert!(gnu.status.success());
    let gnu = String::from_utf8_lossy(&gnu.stdout);
    for fact in ["INIT_ARRAY", "INIT_ARRAYSZ", "FINI_ARRAY", "FINI_ARRAYSZ"] {
        assert!(gnu.contains(fact), "GNU missing {fact}: {gnu}");
    }

    let ours = Command::new(env!("CARGO_BIN_EXE_mini-elf-dyninit"))
        .arg(&shared)
        .output()
        .unwrap();
    assert!(
        ours.status.success(),
        "{}",
        String::from_utf8_lossy(&ours.stderr)
    );
    let ours = String::from_utf8_lossy(&ours.stdout);
    assert!(ours.contains("DT_INIT_ARRAY: address="), "{ours}");
    assert!(ours.contains("DT_FINI_ARRAY: address="), "{ours}");
    assert_eq!(ours.matches("entries=1").count(), 2, "{ours}");
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn malformed_init_array_size_in_later_input_keeps_stdout_atomic() {
    if !tool_available("as") || !tool_available("ld") {
        return;
    }
    let dir = temp_dir("dyninit-size");
    let good = build_shared(&dir);
    let bad = dir.join("bad.so");
    let mut bytes = fs::read(&good).unwrap();
    let size_entry = dynamic_entry_offset(&bytes, 27);
    bytes[size_entry + 8..size_entry + 16].copy_from_slice(&7u64.to_le_bytes());
    fs::write(&bad, bytes).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-dyninit"))
        .arg(&good)
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty(), "stdout must remain atomic");
    assert!(String::from_utf8_lossy(&output.stderr).contains("not a multiple of 8"));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn overflowing_init_array_virtual_range_is_rejected() {
    if !tool_available("as") || !tool_available("ld") {
        return;
    }
    let dir = temp_dir("dyninit-overflow");
    let shared = build_shared(&dir);
    let bad = dir.join("overflow.so");
    let mut bytes = fs::read(&shared).unwrap();
    let address_entry = dynamic_entry_offset(&bytes, 25);
    bytes[address_entry + 8..address_entry + 16].copy_from_slice(&(u64::MAX - 3).to_le_bytes());
    fs::write(&bad, bytes).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-dyninit"))
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("virtual range overflows u64"));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn missing_init_array_size_pair_is_rejected() {
    if !tool_available("as") || !tool_available("ld") {
        return;
    }
    let dir = temp_dir("dyninit-pair");
    let shared = build_shared(&dir);
    let bad = dir.join("pair.so");
    let mut bytes = fs::read(&shared).unwrap();
    let size_entry = dynamic_entry_offset(&bytes, 27);
    bytes[size_entry..size_entry + 8].copy_from_slice(&0x6000_000du64.to_le_bytes());
    fs::write(&bad, bytes).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-dyninit"))
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("must provide DT_INIT_ARRAY and DT_INIT_ARRAYSZ together"));
    let _ = fs::remove_dir_all(dir);
}
