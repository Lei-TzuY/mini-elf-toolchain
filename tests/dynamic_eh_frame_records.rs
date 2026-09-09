use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const PT_LOAD: u32 = 1;
const PT_GNU_EH_FRAME: u32 = 0x6474_e550;

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

fn read_i32(bytes: &[u8], offset: usize) -> i32 {
    i32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn program_headers(bytes: &[u8]) -> Vec<usize> {
    let phoff = read_u64(bytes, 32) as usize;
    let phentsize = read_u16(bytes, 54) as usize;
    let phnum = read_u16(bytes, 56) as usize;
    (0..phnum).map(|index| phoff + index * phentsize).collect()
}

fn eh_frame_header(bytes: &[u8]) -> (usize, u64) {
    let ph = program_headers(bytes)
        .into_iter()
        .find(|offset| read_u32(bytes, *offset) == PT_GNU_EH_FRAME)
        .expect("fixture should contain PT_GNU_EH_FRAME");
    (read_u64(bytes, ph + 8) as usize, read_u64(bytes, ph + 16))
}

fn map_vaddr(bytes: &[u8], address: u64) -> usize {
    for ph in program_headers(bytes) {
        if read_u32(bytes, ph) != PT_LOAD {
            continue;
        }
        let offset = read_u64(bytes, ph + 8);
        let vaddr = read_u64(bytes, ph + 16);
        let filesz = read_u64(bytes, ph + 32);
        if address >= vaddr && address < vaddr + filesz {
            return (offset + address - vaddr) as usize;
        }
    }
    panic!("address {address:#x} should map through PT_LOAD");
}

fn checked_add_i32(base: u64, displacement: i32) -> u64 {
    if displacement >= 0 {
        base.checked_add(displacement as u64).unwrap()
    } else {
        base.checked_sub(u64::from(displacement.unsigned_abs())).unwrap()
    }
}

fn first_fde(bytes: &[u8]) -> (u64, usize) {
    let (header_offset, header_vaddr) = eh_frame_header(bytes);
    let fde = checked_add_i32(header_vaddr, read_i32(bytes, header_offset + 16));
    (fde, map_vaddr(bytes, fde))
}

fn eh_frame_base(bytes: &[u8]) -> u64 {
    let (header_offset, header_vaddr) = eh_frame_header(bytes);
    checked_add_i32(header_vaddr + 4, read_i32(bytes, header_offset + 4))
}

fn build_shared(dir: &std::path::Path) -> std::path::PathBuf {
    let assembly = dir.join("sample.s");
    let object = dir.join("sample.o");
    let shared = dir.join("libsample.so");
    fs::write(
        &assembly,
        ".text\n.globl alpha\n.type alpha,@function\nalpha:\n.cfi_startproc\n  nop\n  ret\n.cfi_endproc\n.globl beta\n.type beta,@function\nbeta:\n.cfi_startproc\n  nop\n  nop\n  ret\n.cfi_endproc\n",
    )
    .unwrap();
    let assembled = Command::new("as")
        .arg("--64")
        .arg("-o")
        .arg(&object)
        .arg(&assembly)
        .output()
        .unwrap();
    assert!(assembled.status.success(), "{}", String::from_utf8_lossy(&assembled.stderr));
    let linked = Command::new("ld")
        .arg("-shared")
        .arg("--eh-frame-hdr")
        .arg("-o")
        .arg(&shared)
        .arg(&object)
        .output()
        .unwrap();
    assert!(linked.status.success(), "{}", String::from_utf8_lossy(&linked.stderr));
    shared
}

fn gnu_fde_addresses(path: &std::path::Path, bytes: &[u8]) -> Vec<u64> {
    let frames = Command::new("readelf").arg("-wf").arg(path).output().unwrap();
    assert!(frames.status.success(), "{}", String::from_utf8_lossy(&frames.stderr));
    let base = eh_frame_base(bytes);
    String::from_utf8_lossy(&frames.stdout)
        .lines()
        .filter(|line| line.contains(" FDE cie="))
        .map(|line| {
            let offset = line.split_whitespace().next().unwrap();
            base + u64::from_str_radix(offset, 16).unwrap()
        })
        .collect()
}

fn ours_fde_addresses(path: &std::path::Path) -> Vec<u64> {
    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-eh-frame-records"))
        .arg(path)
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            let field = line
                .split_whitespace()
                .find(|field| field.starts_with("address="))?;
            u64::from_str_radix(field.trim_start_matches("address=0x"), 16).ok()
        })
        .collect()
}

#[test]
fn indexed_fde_records_match_gnu_readelf_addresses() {
    if !tool_available("as") || !tool_available("ld") || !tool_available("readelf") {
        return;
    }
    let dir = temp_dir("eh-frame-records-gnu");
    let shared = build_shared(&dir);
    let bytes = fs::read(&shared).unwrap();
    let expected = gnu_fde_addresses(&shared, &bytes);
    let actual = ours_fde_addresses(&shared);
    assert!(expected.len() >= 2);
    assert_eq!(actual, expected);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn rejects_dwarf64_marker_and_record_past_load_boundary() {
    if !tool_available("as") || !tool_available("ld") {
        return;
    }
    let dir = temp_dir("eh-frame-records-length");
    let good = build_shared(&dir);
    let bytes = fs::read(&good).unwrap();
    let (_, fde_offset) = first_fde(&bytes);

    let mut dwarf64 = bytes.clone();
    dwarf64[fde_offset..fde_offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    let dwarf64_path = dir.join("dwarf64.so");
    fs::write(&dwarf64_path, dwarf64).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_mini-elf-eh-frame-records"))
        .arg(&dwarf64_path)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("unsupported DWARF64"));
    assert!(result.stdout.is_empty());

    let mut huge = bytes;
    huge[fde_offset..fde_offset + 4].copy_from_slice(&(u32::MAX - 1).to_le_bytes());
    let huge_path = dir.join("huge.so");
    fs::write(&huge_path, huge).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_mini-elf-eh-frame-records"))
        .arg(&huge_path)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("exceeds PT_LOAD"));
    assert!(result.stdout.is_empty());
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn rejects_cie_back_reference_underflow_and_non_cie_target() {
    if !tool_available("as") || !tool_available("ld") {
        return;
    }
    let dir = temp_dir("eh-frame-records-cie");
    let good = build_shared(&dir);
    let bytes = fs::read(&good).unwrap();
    let (fde_address, fde_offset) = first_fde(&bytes);

    let mut underflow = bytes.clone();
    underflow[fde_offset + 4..fde_offset + 8].copy_from_slice(&u32::MAX.to_le_bytes());
    let underflow_path = dir.join("cie-underflow.so");
    fs::write(&underflow_path, underflow).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_mini-elf-eh-frame-records"))
        .arg(&underflow_path)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("back-reference underflows"));
    assert!(result.stdout.is_empty());

    let cie_delta = u64::from(read_u32(&bytes, fde_offset + 4));
    let cie_address = (fde_address + 4).checked_sub(cie_delta).unwrap();
    let cie_offset = map_vaddr(&bytes, cie_address);
    let mut bad_cie = bytes;
    bad_cie[cie_offset + 4..cie_offset + 8].copy_from_slice(&1_u32.to_le_bytes());
    let bad_cie_path = dir.join("non-cie.so");
    fs::write(&bad_cie_path, bad_cie).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_mini-elf-eh-frame-records"))
        .arg(&bad_cie_path)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("is not a CIE record"));
    assert!(result.stdout.is_empty());
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn malformed_later_input_keeps_stdout_atomic() {
    if !tool_available("as") || !tool_available("ld") {
        return;
    }
    let dir = temp_dir("eh-frame-records-atomic");
    let good = build_shared(&dir);
    let mut bytes = fs::read(&good).unwrap();
    let (_, fde_offset) = first_fde(&bytes);
    bytes[fde_offset..fde_offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    let bad = dir.join("bad.so");
    fs::write(&bad, bytes).unwrap();

    let result = Command::new(env!("CARGO_BIN_EXE_mini-elf-eh-frame-records"))
        .arg(&good)
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert!(String::from_utf8_lossy(&result.stderr).contains("unsupported DWARF64"));
    let _ = fs::remove_dir_all(dir);
}
