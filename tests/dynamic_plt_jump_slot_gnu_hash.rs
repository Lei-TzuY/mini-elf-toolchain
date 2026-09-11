use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

const DT_HASH: i64 = 4;
const DT_GNU_HASH: i64 = 0x6fff_fef5;

fn temp_dir(label: &str) -> PathBuf {
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

fn dynamic_entries(bytes: &[u8]) -> Vec<(i64, u64)> {
    let dynamic = program_headers(bytes)
        .into_iter()
        .find(|(segment_type, _, _, _)| *segment_type == 2)
        .expect("shared object should contain PT_DYNAMIC");
    let mut entries = Vec::new();
    let mut offset = dynamic.1 as usize;
    let end = (dynamic.1 + dynamic.3) as usize;
    while offset + 16 <= end {
        let tag = read_i64(bytes, offset);
        let value = read_u64(bytes, offset + 8);
        entries.push((tag, value));
        if tag == 0 {
            break;
        }
        offset += 16;
    }
    entries
}

fn dynamic_value_offset(bytes: &[u8], wanted_tag: i64) -> usize {
    let dynamic = program_headers(bytes)
        .into_iter()
        .find(|(segment_type, _, _, _)| *segment_type == 2)
        .expect("shared object should contain PT_DYNAMIC");
    let mut offset = dynamic.1 as usize;
    let end = (dynamic.1 + dynamic.3) as usize;
    while offset + 16 <= end {
        let tag = read_i64(bytes, offset);
        if tag == wanted_tag {
            return offset + 8;
        }
        if tag == 0 {
            break;
        }
        offset += 16;
    }
    panic!("shared object should contain dynamic tag {wanted_tag}")
}

fn virtual_to_file(bytes: &[u8], address: u64) -> usize {
    for (segment_type, offset, virtual_address, file_size) in program_headers(bytes) {
        if segment_type != 1 {
            continue;
        }
        let end = virtual_address + file_size;
        if address >= virtual_address && address < end {
            return (offset + (address - virtual_address)) as usize;
        }
    }
    panic!("address {address:#x} should be file-backed by PT_LOAD")
}

fn build_shared(dir: &Path) -> PathBuf {
    let assembly = dir.join("sample.s");
    let object = dir.join("sample.o");
    let shared = dir.join("libsample.so");
    fs::write(
        &assembly,
        ".text\n.globl caller\n.type caller,@function\ncaller:\n  call external_function\n  ret\n.size caller,.-caller\n",
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
        .arg("--hash-style=gnu")
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

fn run_tool(input: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_mini-elf-dynplt-jump-slot"))
        .arg("--load-bias")
        .arg("0x70000000")
        .arg(input)
        .output()
        .unwrap()
}

#[test]
fn gnu_hash_only_jump_slot_matches_gnu_readelf() {
    if !tool_available("as") || !tool_available("ld") || !tool_available("readelf") {
        return;
    }
    let dir = temp_dir("dynplt-jump-slot-gnu-hash");
    let shared = build_shared(&dir);
    let bytes = fs::read(&shared).unwrap();
    let entries = dynamic_entries(&bytes);
    assert!(entries.iter().any(|(tag, _)| *tag == DT_GNU_HASH));
    assert!(!entries.iter().any(|(tag, _)| *tag == DT_HASH));

    let gnu = Command::new("readelf")
        .arg("-rW")
        .arg(&shared)
        .output()
        .unwrap();
    assert!(gnu.status.success());
    let gnu_text = String::from_utf8_lossy(&gnu.stdout);
    assert!(gnu_text.contains("R_X86_64_JUMP_SLOT"), "{gnu_text}");
    assert!(gnu_text.contains("external_function"), "{gnu_text}");

    let ours = run_tool(&shared);
    assert!(
        ours.status.success(),
        "{}",
        String::from_utf8_lossy(&ours.stderr)
    );
    let ours_text = String::from_utf8_lossy(&ours.stdout);
    assert!(ours_text.contains("R_X86_64_JUMP_SLOT"), "{ours_text}");
    assert!(ours_text.contains("external_function"), "{ours_text}");
    assert!(ours_text.contains("binding=external"), "{ours_text}");
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn malformed_gnu_hash_bloom_count_is_rejected_atomically() {
    if !tool_available("as") || !tool_available("ld") {
        return;
    }
    let dir = temp_dir("dynplt-jump-slot-gnu-hash-bloom");
    let shared = build_shared(&dir);
    let bad = dir.join("bad-bloom.so");
    let mut bytes = fs::read(&shared).unwrap();
    let hash_address = read_u64(&bytes, dynamic_value_offset(&bytes, DT_GNU_HASH));
    let hash_offset = virtual_to_file(&bytes, hash_address);
    bytes[hash_offset + 8..hash_offset + 12].copy_from_slice(&3u32.to_le_bytes());
    fs::write(&bad, bytes).unwrap();

    let output = run_tool(&bad);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("bloom count 3 must be a non-zero power of two")
    );
    let _ = fs::remove_dir_all(dir);
}
