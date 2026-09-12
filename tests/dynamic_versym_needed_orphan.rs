use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const DT_NULL: i64 = 0;
const DT_HASH: i64 = 4;
const DT_VERSYM: i64 = 0x6fff_fff0;
const VERSYM_INDEX_MASK: u16 = 0x7fff;

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
    assert!(Command::new("as")
        .arg("--64")
        .arg("-o")
        .arg(&provider_o)
        .arg(&provider_s)
        .status()
        .unwrap()
        .success());
    assert!(Command::new("ld")
        .arg("-shared")
        .arg("--hash-style=sysv")
        .arg("--version-script")
        .arg(&provider_map)
        .arg("-soname")
        .arg("libprovider.so")
        .arg("-o")
        .arg(&provider_so)
        .arg(&provider_o)
        .status()
        .unwrap()
        .success());

    let consumer_s = dir.join("consumer.s");
    let consumer_o = dir.join("consumer.o");
    let consumer_so = dir.join("libconsumer.so");
    fs::write(
        &consumer_s,
        ".text\n.globl call_foo\n.type call_foo,@function\ncall_foo:\n  jmp foo@PLT\n.size call_foo,.-call_foo\n",
    )
    .unwrap();
    assert!(Command::new("as")
        .arg("--64")
        .arg("-o")
        .arg(&consumer_o)
        .arg(&consumer_s)
        .status()
        .unwrap()
        .success());
    assert!(Command::new("ld")
        .arg("-shared")
        .arg("--hash-style=sysv")
        .arg("--no-as-needed")
        .arg("-o")
        .arg(&consumer_so)
        .arg(&consumer_o)
        .arg("-L")
        .arg(dir)
        .arg("-lprovider")
        .status()
        .unwrap()
        .success());
    consumer_so
}

#[test]
fn orphan_version_index_is_rejected_atomically() {
    if !tool_available("as") || !tool_available("ld") || !tool_available("readelf") {
        return;
    }
    let dir = temp_dir("versym-needed-orphan");
    let good = build_versioned_dependency(&dir);

    let gnu = Command::new("readelf")
        .arg("-VW")
        .arg(&good)
        .output()
        .unwrap();
    assert!(gnu.status.success());
    let gnu_text = String::from_utf8_lossy(&gnu.stdout);
    assert!(gnu_text.contains("libprovider.so"), "{gnu_text}");
    assert!(gnu_text.contains("VERS_1"), "{gnu_text}");

    let bad = dir.join("orphan.so");
    let mut bytes = fs::read(&good).unwrap();
    let hash_entry = dynamic_entry_offset(&bytes, DT_HASH);
    let hash_address = read_u64(&bytes, hash_entry + 8);
    let hash_offset = virtual_to_file_offset(&bytes, hash_address);
    let symbol_count = read_u32(&bytes, hash_offset + 4) as usize;
    let versym_entry = dynamic_entry_offset(&bytes, DT_VERSYM);
    let versym_address = read_u64(&bytes, versym_entry + 8);
    let versym_offset = virtual_to_file_offset(&bytes, versym_address);
    let versioned_symbol = (0..symbol_count)
        .find(|index| read_u16(&bytes, versym_offset + index * 2) & VERSYM_INDEX_MASK >= 2)
        .expect("fixture should contain a versioned symbol");
    bytes[versym_offset + versioned_symbol * 2..versym_offset + versioned_symbol * 2 + 2]
        .copy_from_slice(&0x1234u16.to_le_bytes());
    fs::write(&bad, bytes).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-versym-needed"))
        .arg(&good)
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty(), "stdout must remain atomic");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("orphan version index 4660"), "{stderr}");
    assert!(stderr.contains("DT_VERDEF or DT_VERNEED"), "{stderr}");
    let _ = fs::remove_dir_all(dir);
}
