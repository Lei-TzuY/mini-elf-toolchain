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

fn dynamic_entries(bytes: &[u8]) -> Vec<usize> {
    let dynamic = program_headers(bytes)
        .into_iter()
        .find(|(segment_type, _, _, _)| *segment_type == 2)
        .expect("shared object should contain PT_DYNAMIC");
    let mut offsets = Vec::new();
    let mut offset = dynamic.1 as usize;
    let end = (dynamic.1 + dynamic.3) as usize;
    while offset + 16 <= end {
        offsets.push(offset);
        if read_i64(bytes, offset) == 0 {
            break;
        }
        offset += 16;
    }
    offsets
}

fn dynamic_value_offset(bytes: &[u8], wanted_tag: i64) -> usize {
    dynamic_entries(bytes)
        .into_iter()
        .find(|offset| read_i64(bytes, *offset) == wanted_tag)
        .map(|offset| offset + 8)
        .unwrap_or_else(|| panic!("shared object should contain dynamic tag {wanted_tag}"))
}

fn virtual_to_file_offset(bytes: &[u8], address: u64, size: u64) -> usize {
    for (segment_type, offset, virtual_address, file_size) in program_headers(bytes) {
        if segment_type != 1 {
            continue;
        }
        let end = address.checked_add(size).unwrap();
        let load_end = virtual_address.checked_add(file_size).unwrap();
        if address >= virtual_address && end <= load_end {
            return (offset + (address - virtual_address)) as usize;
        }
    }
    panic!("virtual range is not file-backed");
}

fn build_rel_shared(dir: &std::path::Path) -> std::path::PathBuf {
    let assembly = dir.join("sample.s");
    let object = dir.join("sample.o");
    let shared = dir.join("libsample.so");
    fs::write(
        &assembly,
        ".data\n.globl ptr\n.type ptr,@object\n.size ptr,8\nptr:\n  .quad external_symbol\n",
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
        .arg("--hash-style=sysv")
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

    let mut bytes = fs::read(&shared).unwrap();
    for offset in dynamic_entries(&bytes) {
        match read_i64(&bytes, offset) {
            7 => bytes[offset..offset + 8].copy_from_slice(&17_i64.to_le_bytes()),
            8 => {
                bytes[offset..offset + 8].copy_from_slice(&18_i64.to_le_bytes());
                bytes[offset + 8..offset + 16].copy_from_slice(&16_u64.to_le_bytes());
            }
            9 => {
                bytes[offset..offset + 8].copy_from_slice(&19_i64.to_le_bytes());
                bytes[offset + 8..offset + 16].copy_from_slice(&16_u64.to_le_bytes());
            }
            _ => {}
        }
    }
    fs::write(&shared, bytes).unwrap();
    shared
}

#[test]
fn dynamic_rel_resolves_symbol_name_like_gnu_readelf() {
    if !tool_available("as") || !tool_available("ld") || !tool_available("readelf") {
        return;
    }
    let dir = temp_dir("dynrel-symbol-name");
    let shared = build_rel_shared(&dir);

    let gnu = Command::new("readelf")
        .arg("--use-dynamic")
        .arg("-rW")
        .arg(&shared)
        .output()
        .unwrap();
    assert!(
        gnu.status.success(),
        "{}",
        String::from_utf8_lossy(&gnu.stderr)
    );
    let gnu_text = String::from_utf8_lossy(&gnu.stdout);
    assert!(gnu_text.contains("external_symbol"), "{gnu_text}");

    let ours = Command::new(env!("CARGO_BIN_EXE_mini-elf-dynrel"))
        .arg(&shared)
        .output()
        .unwrap();
    assert!(
        ours.status.success(),
        "{}",
        String::from_utf8_lossy(&ours.stderr)
    );
    let ours_text = String::from_utf8_lossy(&ours.stdout);
    assert!(ours_text.contains("R_X86_64_64"), "{ours_text}");
    assert!(ours_text.contains("external_symbol"), "{ours_text}");
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn out_of_range_dt_rel_symbol_index_is_rejected() {
    if !tool_available("as") || !tool_available("ld") {
        return;
    }
    let dir = temp_dir("dynrel-symbol-bounds");
    let shared = build_rel_shared(&dir);
    let bad = dir.join("bad.so");
    let mut bytes = fs::read(&shared).unwrap();
    let rel_address = read_u64(&bytes, dynamic_value_offset(&bytes, 17));
    let rel_offset = virtual_to_file_offset(&bytes, rel_address, 16);
    let original_info = read_u64(&bytes, rel_offset + 8);
    let bad_info = (u64::from(u32::MAX) << 32) | u64::from(original_info as u32);
    bytes[rel_offset + 8..rel_offset + 16].copy_from_slice(&bad_info.to_le_bytes());
    fs::write(&bad, bytes).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-dynrel"))
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("outside dynamic symbol count"));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn malformed_dt_syment_is_rejected_before_symbol_lookup() {
    if !tool_available("as") || !tool_available("ld") {
        return;
    }
    let dir = temp_dir("dynrel-syment");
    let shared = build_rel_shared(&dir);
    let bad = dir.join("bad-syment.so");
    let mut bytes = fs::read(&shared).unwrap();
    let syment = dynamic_value_offset(&bytes, 11);
    bytes[syment..syment + 8].copy_from_slice(&16_u64.to_le_bytes());
    fs::write(&bad, bytes).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-dynrel"))
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("DT_SYMENT is 16"));
    let _ = fs::remove_dir_all(dir);
}
