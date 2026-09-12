use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const DT_NULL: i64 = 0;
const DT_VERNEED: i64 = 0x6fff_fffe;

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
        .find(|(segment_type, _, _, _)| *segment_type == PT_DYNAMIC)
        .expect("fixture should contain PT_DYNAMIC");
    let mut offset = dynamic.1 as usize;
    let end = (dynamic.1 + dynamic.3) as usize;
    while offset + 16 <= end {
        let tag = read_i64(bytes, offset);
        if tag == wanted_tag {
            return offset;
        }
        if tag == DT_NULL {
            break;
        }
        offset += 16;
    }
    panic!("fixture should contain dynamic tag {wanted_tag}")
}

fn virtual_to_file_offset(bytes: &[u8], address: u64) -> usize {
    for (segment_type, offset, virtual_address, file_size) in program_headers(bytes) {
        if segment_type != PT_LOAD {
            continue;
        }
        let end = virtual_address + file_size;
        if address >= virtual_address && address < end {
            return (offset + (address - virtual_address)) as usize;
        }
    }
    panic!("virtual address {address:#x} should be file-backed")
}

fn first_vernaux_offset(bytes: &[u8]) -> usize {
    let verneed_entry = dynamic_entry_offset(bytes, DT_VERNEED);
    let verneed_address = read_u64(bytes, verneed_entry + 8);
    let verneed_offset = virtual_to_file_offset(bytes, verneed_address);
    let aux_relative = read_u32(bytes, verneed_offset + 8) as usize;
    verneed_offset + aux_relative
}

fn build_versioned_dependency(dir: &std::path::Path) -> std::path::PathBuf {
    let provider_s = dir.join("provider.s");
    let provider_o = dir.join("provider.o");
    let provider_map = dir.join("provider.map");
    let provider_so = dir.join("libprovider.so");
    fs::write(
        &provider_s,
        ".text\n.globl foo\n.type foo,@function\nfoo:\n  ret\n.size foo,.-foo\n",
    )
    .unwrap();
    fs::write(&provider_map, "VERS_1 { global: foo; local: *; };\n").unwrap();
    let assembled = Command::new("as")
        .arg("--64")
        .arg("-o")
        .arg(&provider_o)
        .arg(&provider_s)
        .output()
        .unwrap();
    assert!(
        assembled.status.success(),
        "{}",
        String::from_utf8_lossy(&assembled.stderr)
    );
    let linked = Command::new("ld")
        .arg("-shared")
        .arg("--hash-style=gnu")
        .arg("--version-script")
        .arg(&provider_map)
        .arg("-soname")
        .arg("libprovider.so")
        .arg("-o")
        .arg(&provider_so)
        .arg(&provider_o)
        .output()
        .unwrap();
    assert!(
        linked.status.success(),
        "{}",
        String::from_utf8_lossy(&linked.stderr)
    );

    let consumer_s = dir.join("consumer.s");
    let consumer_o = dir.join("consumer.o");
    let consumer_so = dir.join("libconsumer.so");
    fs::write(
        &consumer_s,
        ".text\n.globl call_foo\n.type call_foo,@function\ncall_foo:\n  jmp foo@PLT\n.size call_foo,.-call_foo\n",
    )
    .unwrap();
    let assembled = Command::new("as")
        .arg("--64")
        .arg("-o")
        .arg(&consumer_o)
        .arg(&consumer_s)
        .output()
        .unwrap();
    assert!(
        assembled.status.success(),
        "{}",
        String::from_utf8_lossy(&assembled.stderr)
    );
    let linked = Command::new("ld")
        .arg("-shared")
        .arg("--hash-style=gnu")
        .arg("--no-as-needed")
        .arg("-o")
        .arg(&consumer_so)
        .arg(&consumer_o)
        .arg("-L")
        .arg(dir)
        .arg("-lprovider")
        .output()
        .unwrap();
    assert!(
        linked.status.success(),
        "{}",
        String::from_utf8_lossy(&linked.stderr)
    );
    consumer_so
}

#[test]
fn external_versym_names_match_gnu_readelf() {
    if !tool_available("as") || !tool_available("ld") || !tool_available("readelf") {
        return;
    }
    let dir = temp_dir("versym-needed-gnu");
    let shared = build_versioned_dependency(&dir);

    let gnu = Command::new("readelf")
        .arg("-VW")
        .arg(&shared)
        .output()
        .unwrap();
    assert!(gnu.status.success());
    let gnu_text = String::from_utf8_lossy(&gnu.stdout);
    assert!(gnu_text.contains("libprovider.so"), "{gnu_text}");
    assert!(gnu_text.contains("VERS_1"), "{gnu_text}");

    let ours = Command::new(env!("CARGO_BIN_EXE_mini-elf-versym-needed"))
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
        ours_text.contains("requirement=libprovider.so:VERS_1"),
        "ours={ours_text}\ngnu={gnu_text}"
    );
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn corrupted_verneed_hash_is_rejected_atomically() {
    if !tool_available("as") || !tool_available("ld") {
        return;
    }
    let dir = temp_dir("versym-needed-hash");
    let good = build_versioned_dependency(&dir);
    let bad = dir.join("bad-hash.so");
    let mut bytes = fs::read(&good).unwrap();
    let aux_offset = first_vernaux_offset(&bytes);
    let original = read_u32(&bytes, aux_offset);
    bytes[aux_offset..aux_offset + 4].copy_from_slice(&original.wrapping_add(1).to_le_bytes());
    fs::write(&bad, bytes).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-versym-needed"))
        .arg(&good)
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty(), "stdout must remain atomic");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("vna_hash"), "{stderr}");
    assert!(stderr.contains("VERS_1"), "{stderr}");
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn reserved_verneed_index_is_rejected_atomically() {
    if !tool_available("as") || !tool_available("ld") {
        return;
    }
    let dir = temp_dir("versym-needed-reserved");
    let good = build_versioned_dependency(&dir);
    let bad = dir.join("reserved.so");
    let mut bytes = fs::read(&good).unwrap();
    let aux_offset = first_vernaux_offset(&bytes);
    bytes[aux_offset + 6..aux_offset + 8].copy_from_slice(&1u16.to_le_bytes());
    fs::write(&bad, bytes).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-versym-needed"))
        .arg(&good)
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty(), "stdout must remain atomic");
    assert!(String::from_utf8_lossy(&output.stderr).contains("reserved version index 1"));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn overflowing_verneed_address_is_rejected_atomically() {
    if !tool_available("as") || !tool_available("ld") {
        return;
    }
    let dir = temp_dir("versym-needed-overflow");
    let good = build_versioned_dependency(&dir);
    let bad = dir.join("overflow.so");
    let mut bytes = fs::read(&good).unwrap();
    let verneed_value = dynamic_entry_offset(&bytes, DT_VERNEED) + 8;
    bytes[verneed_value..verneed_value + 8].copy_from_slice(&(u64::MAX - 7).to_le_bytes());
    fs::write(&bad, bytes).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-versym-needed"))
        .arg(&good)
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty(), "stdout must remain atomic");
    assert!(String::from_utf8_lossy(&output.stderr).contains("virtual range overflows u64"));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn weak_verneed_flag_is_accepted() {
    if !tool_available("as") || !tool_available("ld") {
        return;
    }
    let dir = temp_dir("versym-needed-weak-flag");
    let good = build_versioned_dependency(&dir);
    let weak = dir.join("weak.so");
    let mut bytes = fs::read(&good).unwrap();
    let aux_offset = first_vernaux_offset(&bytes);
    bytes[aux_offset + 4..aux_offset + 6].copy_from_slice(&2u16.to_le_bytes());
    fs::write(&weak, bytes).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-versym-needed"))
        .arg(&weak)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("requirement=libprovider.so:VERS_1"),
        "{stdout}"
    );
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn unknown_verneed_flags_are_rejected_atomically() {
    if !tool_available("as") || !tool_available("ld") {
        return;
    }
    let dir = temp_dir("versym-needed-unknown-flags");
    let good = build_versioned_dependency(&dir);
    let bad = dir.join("bad-flags.so");
    let mut bytes = fs::read(&good).unwrap();
    let aux_offset = first_vernaux_offset(&bytes);
    bytes[aux_offset + 4..aux_offset + 6].copy_from_slice(&0x8000u16.to_le_bytes());
    fs::write(&bad, bytes).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-versym-needed"))
        .arg(&good)
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty(), "stdout must remain atomic");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("vna_flags"), "{stderr}");
    assert!(stderr.contains("0x8000"), "{stderr}");
    let _ = fs::remove_dir_all(dir);
}
