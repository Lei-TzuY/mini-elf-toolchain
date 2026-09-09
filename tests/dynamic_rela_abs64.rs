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
const R_X86_64_64: u32 = 1;

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
    fs::write(
        &asm,
        ".text\n.globl dummy\n.type dummy,@function\ndummy:\nret\n.size dummy, .-dummy\n.data\n.globl ptr\n.type ptr,@object\n.size ptr,8\nptr:\n.quad target\n.globl target\n.type target,@object\n.size target,8\ntarget:\n.quad 0x1122334455667788\n",
    )
    .unwrap();
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
            obj.to_str().unwrap(),
        ])
        .status()
        .unwrap()
        .success());
    image
}

fn run_tool(inputs: &[&Path], bias: &str) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_mini-elf-dynrela-abs64"));
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

fn program_headers(bytes: &[u8]) -> Vec<(u32, u32, u64, u64, u64, u64)> {
    let phoff = read_u64(bytes, 32) as usize;
    let phentsize = usize::from(read_u16(bytes, 54));
    let phnum = usize::from(read_u16(bytes, 56));
    (0..phnum)
        .map(|index| {
            let offset = phoff + index * phentsize;
            (
                read_u32(bytes, offset),
                read_u32(bytes, offset + 4),
                read_u64(bytes, offset + 8),
                read_u64(bytes, offset + 16),
                read_u64(bytes, offset + 32),
                read_u64(bytes, offset + 40),
            )
        })
        .collect()
}

fn map_vaddr(bytes: &[u8], address: u64) -> usize {
    for (kind, _, offset, vaddr, filesz, _) in program_headers(bytes) {
        if kind == PT_LOAD && address >= vaddr && address < vaddr + filesz {
            return (offset + address - vaddr) as usize;
        }
    }
    panic!("address {address:#x} is not file backed");
}

fn dynamic_tag(bytes: &[u8], wanted: i64) -> u64 {
    let dynamic = program_headers(bytes)
        .into_iter()
        .find(|header| header.0 == PT_DYNAMIC)
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

fn abs64_rela_offset(bytes: &[u8]) -> usize {
    let rela = dynamic_tag(bytes, DT_RELA);
    let mut cursor = map_vaddr(bytes, rela);
    loop {
        let info = read_u64(bytes, cursor + 8);
        if info as u32 == R_X86_64_64 {
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
        .find(|header| header.0 == PT_LOAD && header.1 & PF_X != 0 && header.4 >= 8)
        .map(|header| header.3)
        .unwrap()
}

#[test]
fn validates_gnu_abs64_relocation() {
    let dir = temp_dir("abs64-good");
    let image = build_fixture(&dir);
    let readelf = Command::new("readelf")
        .args(["-rW", image.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(readelf.status.success());
    let relocations = String::from_utf8(readelf.stdout).unwrap();
    assert!(relocations.contains("R_X86_64_64"), "{relocations}");

    let output = run_tool(&[&image], "0x70000000");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Validated R_X86_64_64 relocations"));
    assert!(stdout.contains(":target "));
    assert!(stdout.contains("result="));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn applies_negative_rela_addend() {
    let dir = temp_dir("abs64-negative-addend");
    let image = build_fixture(&dir);
    let mut bytes = fs::read(&image).unwrap();
    let rela = abs64_rela_offset(&bytes);
    bytes[rela + 16..rela + 24].copy_from_slice(&(-1_i64).to_le_bytes());
    let patched = dir.join("negative-addend.so");
    fs::write(&patched, bytes).unwrap();

    let output = run_tool(&[&patched], "0x70000000");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("addend=-1"), "{stdout}");
    assert!(stdout.contains("result="), "{stdout}");
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rejects_out_of_range_dynamic_symbol_index() {
    let dir = temp_dir("abs64-symbol-index");
    let image = build_fixture(&dir);
    let mut bytes = fs::read(&image).unwrap();
    let rela = abs64_rela_offset(&bytes);
    let count = symbol_count(&bytes);
    bytes[rela + 8..rela + 16]
        .copy_from_slice(&((count << 32) | u64::from(R_X86_64_64)).to_le_bytes());
    let bad = dir.join("bad-index.so");
    fs::write(&bad, bytes).unwrap();
    let output = run_tool(&[&bad], "0x70000000");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid dynamic symbol index"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rejects_target_outside_writable_load() {
    let dir = temp_dir("abs64-target");
    let image = build_fixture(&dir);
    let mut bytes = fs::read(&image).unwrap();
    let rela = abs64_rela_offset(&bytes);
    let text = executable_address(&bytes);
    bytes[rela..rela + 8].copy_from_slice(&text.to_le_bytes());
    let bad = dir.join("bad-target.so");
    fs::write(&bad, bytes).unwrap();
    let output = run_tool(&[&bad], "0x70000000");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("target"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rejects_s_plus_a_overflow() {
    let dir = temp_dir("abs64-overflow");
    let image = build_fixture(&dir);
    let mut bytes = fs::read(&image).unwrap();
    let rela = abs64_rela_offset(&bytes);
    bytes[rela + 16..rela + 24].copy_from_slice(&i64::MAX.to_le_bytes());
    let bad = dir.join("bad-overflow.so");
    fs::write(&bad, bytes).unwrap();
    let output = run_tool(&[&bad], "0xffffffffffff0000");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("overflows u64"), "{stderr}");
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn malformed_later_input_keeps_stdout_atomic() {
    let dir = temp_dir("abs64-atomic");
    let good = build_fixture(&dir);
    let mut bytes = fs::read(&good).unwrap();
    let rela = abs64_rela_offset(&bytes);
    let count = symbol_count(&bytes);
    bytes[rela + 8..rela + 16]
        .copy_from_slice(&((count << 32) | u64::from(R_X86_64_64)).to_le_bytes());
    let bad = dir.join("bad.so");
    fs::write(&bad, bytes).unwrap();
    let output = run_tool(&[&good, &bad], "0x70000000");
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    fs::remove_dir_all(dir).unwrap();
}
