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

fn build_shared(dir: &std::path::Path) -> std::path::PathBuf {
    let assembly = dir.join("sample.s");
    let object = dir.join("sample.o");
    let shared = dir.join("libsample.so");
    fs::write(
        &assembly,
        ".text\n.globl caller\n.type caller,@function\ncaller:\n  call external_function\n  ret\n.size caller,.-caller\n",
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
    shared
}

#[test]
fn dynamic_plt_matches_gnu_readelf() {
    if !tool_available("as") || !tool_available("ld") || !tool_available("readelf") {
        return;
    }
    let dir = temp_dir("dynplt-gnu");
    let shared = build_shared(&dir);
    let gnu = Command::new("readelf")
        .arg("-rW")
        .arg(&shared)
        .output()
        .unwrap();
    assert!(gnu.status.success());
    let gnu_text = String::from_utf8_lossy(&gnu.stdout);
    assert!(gnu_text.contains("R_X86_64_JUMP_SLOT"), "{gnu_text}");
    assert!(gnu_text.contains("external_function"), "{gnu_text}");

    let ours = Command::new(env!("CARGO_BIN_EXE_mini-elf-dynplt"))
        .arg(&shared)
        .output()
        .unwrap();
    assert!(
        ours.status.success(),
        "{}",
        String::from_utf8_lossy(&ours.stderr)
    );
    let ours_text = String::from_utf8_lossy(&ours.stdout);
    assert!(ours_text.contains("DT_JMPREL contains 1 entries"), "{ours_text}");
    assert!(ours_text.contains("R_X86_64_JUMP_SLOT"), "ours={ours_text}\ngnu={gnu_text}");
    assert!(ours_text.contains("external_function"), "ours={ours_text}\ngnu={gnu_text}");
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn non_rela_plt_encoding_is_rejected_atomically() {
    if !tool_available("as") || !tool_available("ld") {
        return;
    }
    let dir = temp_dir("dynplt-pltrel");
    let good = build_shared(&dir);
    let bad = dir.join("bad.so");
    let mut bytes = fs::read(&good).unwrap();
    let pltrel = dynamic_value_offset(&bytes, 20);
    bytes[pltrel..pltrel + 8].copy_from_slice(&17_u64.to_le_bytes());
    fs::write(&bad, bytes).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-dynplt"))
        .arg(&good)
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty(), "stdout must remain atomic");
    assert!(String::from_utf8_lossy(&output.stderr).contains("expected DT_RELA"));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn out_of_range_plt_symbol_index_is_rejected() {
    if !tool_available("as") || !tool_available("ld") {
        return;
    }
    let dir = temp_dir("dynplt-symbol-index");
    let shared = build_shared(&dir);
    let bad = dir.join("bad-symbol.so");
    let mut bytes = fs::read(&shared).unwrap();
    let jmprel_address = read_u64(&bytes, dynamic_value_offset(&bytes, 23));
    let jmprel_offset = virtual_to_file(&bytes, jmprel_address);
    let relocation_type = read_u64(&bytes, jmprel_offset + 8) as u32;
    let info = (u64::from(u32::MAX) << 32) | u64::from(relocation_type);
    bytes[jmprel_offset + 8..jmprel_offset + 16].copy_from_slice(&info.to_le_bytes());
    fs::write(&bad, bytes).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-dynplt"))
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("outside dynamic symbol count"));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn overflowing_dt_jmprel_virtual_range_is_rejected() {
    if !tool_available("as") || !tool_available("ld") {
        return;
    }
    let dir = temp_dir("dynplt-overflow");
    let shared = build_shared(&dir);
    let bad = dir.join("overflow.so");
    let mut bytes = fs::read(&shared).unwrap();
    let jmprel = dynamic_value_offset(&bytes, 23);
    bytes[jmprel..jmprel + 8].copy_from_slice(&(u64::MAX - 7).to_le_bytes());
    fs::write(&bad, bytes).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-dynplt"))
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("virtual range overflows u64"));
    let _ = fs::remove_dir_all(dir);
}
