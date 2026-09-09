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
        base.checked_sub(u64::from(displacement.unsigned_abs()))
            .unwrap()
    }
}

fn first_cie(bytes: &[u8]) -> (u64, usize) {
    let (header_offset, header_vaddr) = eh_frame_header(bytes);
    let fde_address = checked_add_i32(header_vaddr, read_i32(bytes, header_offset + 16));
    let fde_offset = map_vaddr(bytes, fde_address);
    let cie_delta = u64::from(read_u32(bytes, fde_offset + 4));
    let cie_address = (fde_address + 4).checked_sub(cie_delta).unwrap();
    (cie_address, map_vaddr(bytes, cie_address))
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
    assert!(
        assembled.status.success(),
        "{}",
        String::from_utf8_lossy(&assembled.stderr)
    );
    let linked = Command::new("ld")
        .arg("-shared")
        .arg("--eh-frame-hdr")
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

fn gnu_augmentation(path: &std::path::Path) -> String {
    let frames = Command::new("readelf")
        .arg("-wf")
        .arg(path)
        .output()
        .unwrap();
    assert!(
        frames.status.success(),
        "{}",
        String::from_utf8_lossy(&frames.stderr)
    );
    let line = String::from_utf8_lossy(&frames.stdout)
        .lines()
        .find(|line| line.trim_start().starts_with("Augmentation:"))
        .expect("GNU readelf should print a CIE augmentation")
        .trim()
        .to_owned();
    line.split_once(':')
        .unwrap()
        .1
        .trim()
        .trim_matches('"')
        .to_owned()
}

#[test]
fn cie_augmentation_matches_gnu_readelf() {
    if !tool_available("as") || !tool_available("ld") || !tool_available("readelf") {
        return;
    }
    let dir = temp_dir("eh-frame-cie-gnu");
    let shared = build_shared(&dir);
    let expected = gnu_augmentation(&shared);
    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-eh-frame-cie"))
        .arg(&shared)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("version=1"));
    assert!(stdout.contains(&format!("augmentation={expected}")));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn rejects_unsupported_cie_version_and_unterminated_augmentation() {
    if !tool_available("as") || !tool_available("ld") {
        return;
    }
    let dir = temp_dir("eh-frame-cie-malformed");
    let good = build_shared(&dir);
    let bytes = fs::read(&good).unwrap();
    let (_, cie_offset) = first_cie(&bytes);

    let mut version = bytes.clone();
    version[cie_offset + 8] = 2;
    let version_path = dir.join("version.so");
    fs::write(&version_path, version).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_mini-elf-eh-frame-cie"))
        .arg(&version_path)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("unsupported version 2"));
    assert!(result.stdout.is_empty());

    let mut unterminated = bytes;
    let cie_total = 4 + read_u32(&unterminated, cie_offset) as usize;
    unterminated[cie_offset + 9..cie_offset + cie_total].fill(b'A');
    let unterminated_path = dir.join("unterminated.so");
    fs::write(&unterminated_path, unterminated).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_mini-elf-eh-frame-cie"))
        .arg(&unterminated_path)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("unterminated augmentation"));
    assert!(result.stdout.is_empty());
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn malformed_later_input_keeps_stdout_atomic() {
    if !tool_available("as") || !tool_available("ld") {
        return;
    }
    let dir = temp_dir("eh-frame-cie-atomic");
    let good = build_shared(&dir);
    let mut bytes = fs::read(&good).unwrap();
    let (_, cie_offset) = first_cie(&bytes);
    bytes[cie_offset + 8] = 2;
    let bad = dir.join("bad.so");
    fs::write(&bad, bytes).unwrap();

    let result = Command::new(env!("CARGO_BIN_EXE_mini-elf-eh-frame-cie"))
        .arg(&good)
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert!(String::from_utf8_lossy(&result.stderr).contains("unsupported version 2"));
    let _ = fs::remove_dir_all(dir);
}
