use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PF_X: u32 = 1;
const DT_NULL: i64 = 0;
const DT_HASH: i64 = 4;
const DT_RELA: i64 = 7;
const R_X86_64_16: u32 = 12;

fn temp_dir(label: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "mini-elf-toolchain-{label}-{}-{stamp}",
        std::process::id()
    ));
    fs::create_dir_all(&path).unwrap();
    path
}

fn build_fixture(dir: &Path) -> PathBuf {
    let asm = dir.join("fixture.s");
    let obj = dir.join("fixture.o");
    let image = dir.join("fixture.so");
    fs::write(&asm, ".text\n.globl dummy\n.type dummy,@function\ndummy:\nret\n.size dummy, .-dummy\n.data\n.globl ptr\n.type ptr,@object\n.size ptr,8\nptr:\n.quad target\n.globl target\n.type target,@object\n.size target,8\ntarget:\n.quad 0x1122334455667788\n").unwrap();
    assert!(Command::new("as")
        .args(["-o", obj.to_str().unwrap(), asm.to_str().unwrap()])
        .status()
        .unwrap()
        .success());
    assert!(Command::new("ld")
        .args([
            "-shared",
            "--hash-style=sysv",
            "-o",
            image.to_str().unwrap(),
            obj.to_str().unwrap()
        ])
        .status()
        .unwrap()
        .success());

    let mut bytes = fs::read(&image).unwrap();
    let rela = dynamic_tag(&bytes, DT_RELA);
    let mut cursor = map_vaddr(&bytes, rela);
    loop {
        let info = read_u64(&bytes, cursor + 8);
        if info as u32 == 1 {
            let symbol = info >> 32;
            bytes[cursor + 8..cursor + 16]
                .copy_from_slice(&((symbol << 32) | u64::from(R_X86_64_16)).to_le_bytes());
            break;
        }
        cursor += 24;
    }
    fs::write(&image, bytes).unwrap();
    image
}

fn run_tool(inputs: &[&Path], bias: &str) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_mini-elf-dynrela-u16"));
    command.arg("--load-bias").arg(bias);
    for input in inputs {
        command.arg(input);
    }
    command.output().unwrap()
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

fn program_headers(bytes: &[u8]) -> Vec<(u32, u32, u64, u64, u64)> {
    let phoff = read_u64(bytes, 32) as usize;
    let phentsize = usize::from(read_u16(bytes, 54));
    let phnum = usize::from(read_u16(bytes, 56));
    (0..phnum)
        .map(|i| {
            let o = phoff + i * phentsize;
            (
                read_u32(bytes, o),
                read_u32(bytes, o + 4),
                read_u64(bytes, o + 8),
                read_u64(bytes, o + 16),
                read_u64(bytes, o + 32),
            )
        })
        .collect()
}

fn map_vaddr(bytes: &[u8], address: u64) -> usize {
    for (kind, _, offset, vaddr, filesz) in program_headers(bytes) {
        if kind == PT_LOAD && address >= vaddr && address < vaddr + filesz {
            return (offset + address - vaddr) as usize;
        }
    }
    panic!("address {address:#x} is not file backed");
}

fn dynamic_tag(bytes: &[u8], wanted: i64) -> u64 {
    let dynamic = program_headers(bytes)
        .into_iter()
        .find(|h| h.0 == PT_DYNAMIC)
        .unwrap();
    let mut cursor = dynamic.2 as usize;
    let end = (dynamic.2 + dynamic.4) as usize;
    while cursor + 16 <= end {
        let tag = read_i64(bytes, cursor);
        let value = read_u64(bytes, cursor + 8);
        if tag == wanted {
            return value;
        }
        if tag == DT_NULL {
            break;
        }
        cursor += 16;
    }
    panic!("missing dynamic tag {wanted}");
}

fn rela_offset(bytes: &[u8]) -> usize {
    let mut cursor = map_vaddr(bytes, dynamic_tag(bytes, DT_RELA));
    loop {
        if read_u64(bytes, cursor + 8) as u32 == R_X86_64_16 {
            return cursor;
        }
        cursor += 24;
    }
}

fn symbol_count(bytes: &[u8]) -> u64 {
    let hash = map_vaddr(bytes, dynamic_tag(bytes, DT_HASH));
    u64::from(read_u32(bytes, hash + 4))
}

fn executable_address(bytes: &[u8]) -> u64 {
    program_headers(bytes)
        .into_iter()
        .find(|h| h.0 == PT_LOAD && h.1 & PF_X != 0)
        .unwrap()
        .3
}

#[test]
fn validates_gnu_recognized_16_relocation() {
    let dir = temp_dir("u16-good");
    let image = build_fixture(&dir);
    let readelf = Command::new("readelf")
        .args(["-rW", image.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(readelf.status.success());
    let text = String::from_utf8(readelf.stdout).unwrap();
    assert!(text.contains("R_X86_64_16"), "{text}");
    let output = run_tool(&[&image], "0");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Validated R_X86_64_16 relocations"));
    assert!(stdout.contains(":target "));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn applies_negative_addend_with_unsigned_range_check() {
    let dir = temp_dir("u16-negative");
    let image = build_fixture(&dir);
    let mut bytes = fs::read(&image).unwrap();
    let rela = rela_offset(&bytes);
    bytes[rela + 16..rela + 24].copy_from_slice(&(-1_i64).to_le_bytes());
    let patched = dir.join("negative.so");
    fs::write(&patched, bytes).unwrap();
    let output = run_tool(&[&patched], "0");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("addend=-1"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rejects_invalid_symbol_index() {
    let dir = temp_dir("u16-index");
    let image = build_fixture(&dir);
    let mut bytes = fs::read(&image).unwrap();
    let rela = rela_offset(&bytes);
    let count = symbol_count(&bytes);
    bytes[rela + 8..rela + 16]
        .copy_from_slice(&((count << 32) | u64::from(R_X86_64_16)).to_le_bytes());
    let bad = dir.join("bad-index.so");
    fs::write(&bad, bytes).unwrap();
    let output = run_tool(&[&bad], "0");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid dynamic symbol index"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rejects_non_writable_target() {
    let dir = temp_dir("u16-target");
    let image = build_fixture(&dir);
    let mut bytes = fs::read(&image).unwrap();
    let rela = rela_offset(&bytes);
    let text = executable_address(&bytes);
    bytes[rela..rela + 8].copy_from_slice(&text.to_le_bytes());
    let bad = dir.join("bad-target.so");
    fs::write(&bad, bytes).unwrap();
    let output = run_tool(&[&bad], "0");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("target"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rejects_result_outside_unsigned_16_bits() {
    let dir = temp_dir("u16-overflow");
    let image = build_fixture(&dir);
    let output = run_tool(&[&image], "0x10000");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("does not fit unsigned 16 bits"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn malformed_later_input_keeps_stdout_atomic() {
    let dir = temp_dir("u16-atomic");
    let good = build_fixture(&dir);
    let mut bytes = fs::read(&good).unwrap();
    let rela = rela_offset(&bytes);
    let count = symbol_count(&bytes);
    bytes[rela + 8..rela + 16]
        .copy_from_slice(&((count << 32) | u64::from(R_X86_64_16)).to_le_bytes());
    let bad = dir.join("bad.so");
    fs::write(&bad, bytes).unwrap();
    let output = run_tool(&[&good, &bad], "0");
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    fs::remove_dir_all(dir).unwrap();
}
