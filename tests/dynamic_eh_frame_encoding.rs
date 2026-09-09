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

fn phdrs(bytes: &[u8]) -> Vec<usize> {
    let phoff = read_u64(bytes, 32) as usize;
    let entsize = read_u16(bytes, 54) as usize;
    let count = read_u16(bytes, 56) as usize;
    (0..count).map(|index| phoff + index * entsize).collect()
}

fn map_vaddr(bytes: &[u8], address: u64) -> usize {
    for ph in phdrs(bytes) {
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
    panic!("address should map through PT_LOAD");
}

fn checked_add_i32(base: u64, displacement: i32) -> u64 {
    if displacement >= 0 {
        base.checked_add(displacement as u64).unwrap()
    } else {
        base.checked_sub(u64::from(displacement.unsigned_abs()))
            .unwrap()
    }
}

fn first_cie(bytes: &[u8]) -> usize {
    let eh = phdrs(bytes)
        .into_iter()
        .find(|offset| read_u32(bytes, *offset) == PT_GNU_EH_FRAME)
        .unwrap();
    let header_offset = read_u64(bytes, eh + 8) as usize;
    let header_vaddr = read_u64(bytes, eh + 16);
    let fde = checked_add_i32(header_vaddr, read_i32(bytes, header_offset + 16));
    let fde_offset = map_vaddr(bytes, fde);
    let cie = (fde + 4)
        .checked_sub(u64::from(read_u32(bytes, fde_offset + 4)))
        .unwrap();
    map_vaddr(bytes, cie)
}

fn skip_leb(bytes: &[u8], mut cursor: usize, end: usize) -> usize {
    loop {
        assert!(cursor < end);
        let byte = bytes[cursor];
        cursor += 1;
        if byte & 0x80 == 0 {
            return cursor;
        }
    }
}

fn augmentation_payload(bytes: &[u8]) -> (usize, usize) {
    let cie = first_cie(bytes);
    let end = cie + 4 + read_u32(bytes, cie) as usize;
    let aug_start = cie + 9;
    let nul = bytes[aug_start..end].iter().position(|byte| *byte == 0).unwrap();
    assert_eq!(&bytes[aug_start..aug_start + nul], b"zR");
    let mut cursor = aug_start + nul + 1;
    cursor = skip_leb(bytes, cursor, end);
    cursor = skip_leb(bytes, cursor, end);
    cursor = skip_leb(bytes, cursor, end);
    let length_offset = cursor;
    cursor = skip_leb(bytes, cursor, end);
    (length_offset, cursor)
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
    assert!(Command::new("as")
        .arg("--64")
        .arg("-o")
        .arg(&object)
        .arg(&assembly)
        .status()
        .unwrap()
        .success());
    assert!(Command::new("ld")
        .arg("-shared")
        .arg("--eh-frame-hdr")
        .arg("-o")
        .arg(&shared)
        .arg(&object)
        .status()
        .unwrap()
        .success());
    shared
}

#[test]
fn fde_encoding_matches_gnu_readelf() {
    if !tool_available("as") || !tool_available("ld") || !tool_available("readelf") {
        return;
    }
    let dir = temp_dir("eh-frame-encoding-gnu");
    let shared = build_shared(&dir);
    let gnu = Command::new("readelf").arg("-wf").arg(&shared).output().unwrap();
    assert!(gnu.status.success());
    let gnu_stdout = String::from_utf8_lossy(&gnu.stdout);
    assert!(gnu_stdout.contains("Augmentation:     \"zR\""));
    assert!(gnu_stdout.contains("Augmentation data:    1b"));

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-eh-frame-encoding"))
        .arg(&shared)
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("augmentation=zR"));
    assert!(stdout.contains("fde_encoding=0x1b"));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn rejects_unsupported_encoding_and_oversized_payload() {
    if !tool_available("as") || !tool_available("ld") {
        return;
    }
    let dir = temp_dir("eh-frame-encoding-malformed");
    let good = build_shared(&dir);
    let bytes = fs::read(&good).unwrap();
    let (length_offset, payload_offset) = augmentation_payload(&bytes);

    let mut unsupported = bytes.clone();
    unsupported[payload_offset] = 0xff;
    let unsupported_path = dir.join("unsupported.so");
    fs::write(&unsupported_path, unsupported).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_mini-elf-eh-frame-encoding"))
        .arg(&unsupported_path)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("unsupported CIE-declared FDE encoding"));
    assert!(result.stdout.is_empty());

    let mut oversized = bytes;
    oversized[length_offset] = 0x7f;
    let oversized_path = dir.join("oversized.so");
    fs::write(&oversized_path, oversized).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_mini-elf-eh-frame-encoding"))
        .arg(&oversized_path)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("augmentation payload exceeds record boundary"));
    assert!(result.stdout.is_empty());
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn malformed_later_input_keeps_stdout_atomic() {
    if !tool_available("as") || !tool_available("ld") {
        return;
    }
    let dir = temp_dir("eh-frame-encoding-atomic");
    let good = build_shared(&dir);
    let mut bytes = fs::read(&good).unwrap();
    let (_, payload_offset) = augmentation_payload(&bytes);
    bytes[payload_offset] = 0xff;
    let bad = dir.join("bad.so");
    fs::write(&bad, bytes).unwrap();

    let result = Command::new(env!("CARGO_BIN_EXE_mini-elf-eh-frame-encoding"))
        .arg(&good)
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert!(String::from_utf8_lossy(&result.stderr).contains("unsupported CIE-declared FDE encoding"));
    let _ = fs::remove_dir_all(dir);
}
