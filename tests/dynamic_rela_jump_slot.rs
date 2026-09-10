use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PF_X: u32 = 1;
const DT_NULL: i64 = 0;
const DT_HASH: i64 = 4;
const DT_GNU_HASH: i64 = 0x6fff_fef5;
const DT_PLTRELSZ: i64 = 2;
const DT_JMPREL: i64 = 23;
const R_X86_64_JUMP_SLOT: u32 = 7;

fn temp(label: &str) -> PathBuf {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let p = std::env::temp_dir().join(format!(
        "mini-elf-toolchain-{label}-{}-{n}",
        std::process::id()
    ));
    fs::create_dir_all(&p).unwrap();
    p
}

fn fixture(dir: &Path) -> PathBuf {
    let source = dir.join("jump.s");
    let object = dir.join("jump.o");
    let shared = dir.join("jump.so");
    fs::write(
        &source,
        ".text\n.globl call_external\n.type call_external,@function\ncall_external:\ncall external_target@PLT\nret\n",
    )
    .unwrap();
    assert!(Command::new("as")
        .args(["-o", object.to_str().unwrap(), source.to_str().unwrap()])
        .status()
        .unwrap()
        .success());
    assert!(Command::new("ld")
        .args([
            "-shared",
            "--hash-style=sysv",
            "-o",
            shared.to_str().unwrap(),
            object.to_str().unwrap(),
        ])
        .status()
        .unwrap()
        .success());
    shared
}

fn run(paths: &[&Path], bias: &str) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_mini-elf-dynrela-jump-slot"));
    command.arg("--load-bias").arg(bias);
    for path in paths {
        command.arg(path);
    }
    command.output().unwrap()
}

fn u16at(bytes: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(bytes[off..off + 2].try_into().unwrap())
}
fn u32at(bytes: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap())
}
fn u64at(bytes: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap())
}
fn i64at(bytes: &[u8], off: usize) -> i64 {
    i64::from_le_bytes(bytes[off..off + 8].try_into().unwrap())
}
fn ph(bytes: &[u8]) -> Vec<(u32, u32, u64, u64, u64, u64)> {
    let start = u64at(bytes, 32) as usize;
    let size = u16at(bytes, 54) as usize;
    let count = u16at(bytes, 56) as usize;
    (0..count)
        .map(|index| {
            let p = start + index * size;
            (
                u32at(bytes, p),
                u32at(bytes, p + 4),
                u64at(bytes, p + 8),
                u64at(bytes, p + 16),
                u64at(bytes, p + 32),
                u64at(bytes, p + 40),
            )
        })
        .collect()
}
fn map(bytes: &[u8], address: u64) -> usize {
    for (kind, _, off, va, filesz, _) in ph(bytes) {
        if kind == PT_LOAD && address >= va && address < va + filesz {
            return (off + address - va) as usize;
        }
    }
    panic!("unmapped virtual address {address:#x}")
}
fn tag(bytes: &[u8], wanted: i64) -> u64 {
    let dynamic = ph(bytes)
        .into_iter()
        .find(|entry| entry.0 == PT_DYNAMIC)
        .unwrap();
    let mut cursor = dynamic.2 as usize;
    let end = (dynamic.2 + dynamic.4) as usize;
    while cursor + 16 <= end {
        let tag = i64at(bytes, cursor);
        let value = u64at(bytes, cursor + 8);
        if tag == wanted {
            return value;
        }
        if tag == DT_NULL {
            break;
        }
        cursor += 16;
    }
    panic!("missing dynamic tag {wanted}")
}
fn jump_rela(bytes: &[u8]) -> usize {
    let start = map(bytes, tag(bytes, DT_JMPREL));
    let size = tag(bytes, DT_PLTRELSZ) as usize;
    for cursor in (start..start + size).step_by(24) {
        if u64at(bytes, cursor + 8) as u32 == R_X86_64_JUMP_SLOT {
            return cursor;
        }
    }
    panic!("missing JUMP_SLOT")
}
fn symbol_count(bytes: &[u8]) -> u64 {
    u32at(bytes, map(bytes, tag(bytes, DT_HASH)) + 4) as u64
}
fn executable_addr(bytes: &[u8]) -> u64 {
    ph(bytes)
        .into_iter()
        .find(|entry| entry.0 == PT_LOAD && entry.1 & PF_X != 0 && entry.4 > 0)
        .map(|entry| entry.3)
        .unwrap()
}

#[test]
fn validates_gnu_jump_slot() {
    let dir = temp("jump-slot-good");
    let shared = fixture(&dir);
    let readelf = Command::new("readelf")
        .args(["-rW", shared.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(readelf.status.success());
    let text = String::from_utf8_lossy(&readelf.stdout);
    assert!(text.contains("R_X86_64_JUMP_SLOT"), "{text}");

    let output = run(&[&shared], "0x70000000");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Validated R_X86_64_JUMP_SLOT"));
    assert!(stdout.contains("external_target"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rejects_bad_symbol_index() {
    let dir = temp("jump-slot-index");
    let shared = fixture(&dir);
    let mut bytes = fs::read(&shared).unwrap();
    let rela = jump_rela(&bytes);
    let count = symbol_count(&bytes);
    bytes[rela + 8..rela + 16]
        .copy_from_slice(&((count << 32) | R_X86_64_JUMP_SLOT as u64).to_le_bytes());
    let bad = dir.join("bad.so");
    fs::write(&bad, bytes).unwrap();
    let output = run(&[&bad], "0");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid dynamic symbol index"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rejects_nonwritable_target() {
    let dir = temp("jump-slot-target");
    let shared = fixture(&dir);
    let mut bytes = fs::read(&shared).unwrap();
    let rela = jump_rela(&bytes);
    let address = executable_addr(&bytes);
    bytes[rela..rela + 8].copy_from_slice(&address.to_le_bytes());
    let bad = dir.join("bad.so");
    fs::write(&bad, bytes).unwrap();
    let output = run(&[&bad], "0");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("target"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rejects_nonzero_addend() {
    let dir = temp("jump-slot-addend");
    let shared = fixture(&dir);
    let mut bytes = fs::read(&shared).unwrap();
    let rela = jump_rela(&bytes);
    bytes[rela + 16..rela + 24].copy_from_slice(&1i64.to_le_bytes());
    let bad = dir.join("bad.so");
    fs::write(&bad, bytes).unwrap();
    let output = run(&[&bad], "0");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("nonzero RELA addend"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rejects_runtime_target_overflow() {
    let dir = temp("jump-slot-runtime");
    let shared = fixture(&dir);
    let output = run(&[&shared], "0xffffffffffffffff");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("runtime target"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn malformed_later_input_keeps_stdout_atomic() {
    let dir = temp("jump-slot-atomic");
    let shared = fixture(&dir);
    let bad = dir.join("bad.so");
    fs::write(&bad, b"not an elf").unwrap();
    let output = run(&[&shared, &bad], "0");
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    fs::remove_dir_all(dir).unwrap();
}

fn gnu_hash_fixture(dir: &Path) -> PathBuf {
    let source = dir.join("jump-gnu-hash.s");
    let object = dir.join("jump-gnu-hash.o");
    let shared = dir.join("jump-gnu-hash.so");
    fs::write(
        &source,
        ".text\n.globl call_external\n.type call_external,@function\ncall_external:\ncall external_target@PLT\nret\n",
    )
    .unwrap();
    assert!(Command::new("as")
        .args(["-o", object.to_str().unwrap(), source.to_str().unwrap()])
        .status()
        .unwrap()
        .success());
    assert!(Command::new("ld")
        .args([
            "-shared",
            "--hash-style=gnu",
            "-o",
            shared.to_str().unwrap(),
            object.to_str().unwrap(),
        ])
        .status()
        .unwrap()
        .success());
    shared
}

#[test]
fn validates_gnu_hash_only_jump_slot() {
    let dir = temp("jump-slot-gnu-hash");
    let shared = gnu_hash_fixture(&dir);
    let dynamic = Command::new("readelf")
        .args(["-dW", shared.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(dynamic.status.success());
    let dynamic_text = String::from_utf8_lossy(&dynamic.stdout);
    assert!(dynamic_text.contains("GNU_HASH"), "{dynamic_text}");
    assert!(
        !dynamic_text.lines().any(|line| line.contains("(HASH)")),
        "{dynamic_text}"
    );
    let relocs = Command::new("readelf")
        .args(["-rW", shared.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(relocs.status.success());
    assert!(String::from_utf8_lossy(&relocs.stdout).contains("R_X86_64_JUMP_SLOT"));

    let output = run(&[&shared], "0x70000000");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("external_target"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rejects_malformed_gnu_hash_bloom_count() {
    let dir = temp("jump-slot-gnu-hash-bloom");
    let shared = gnu_hash_fixture(&dir);
    let mut bytes = fs::read(&shared).unwrap();
    let header = map(&bytes, tag(&bytes, DT_GNU_HASH));
    bytes[header + 8..header + 12].copy_from_slice(&0u32.to_le_bytes());
    let bad = dir.join("bad.so");
    fs::write(&bad, bytes).unwrap();
    let output = run(&[&bad], "0");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("bloom count"));
    fs::remove_dir_all(dir).unwrap();
}
