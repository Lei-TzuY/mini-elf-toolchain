use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_dir(label: &str) -> PathBuf {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let path = std::env::temp_dir().join(format!("mini-elf-toolchain-{label}-{}-{nonce}", std::process::id()));
    fs::create_dir_all(&path).unwrap();
    path
}

fn tool_available(tool: &str) -> bool {
    Command::new(tool).arg("--version").output().is_ok()
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 { u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap()) }
fn read_u32(bytes: &[u8], offset: usize) -> u32 { u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) }
fn read_u64(bytes: &[u8], offset: usize) -> u64 { u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap()) }
fn read_i64(bytes: &[u8], offset: usize) -> i64 { i64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap()) }

fn program_headers(bytes: &[u8]) -> Vec<(u32, u32, u64, u64, u64, u64)> {
    let phoff = read_u64(bytes, 32) as usize;
    let phentsize = read_u16(bytes, 54) as usize;
    let phnum = read_u16(bytes, 56) as usize;
    (0..phnum).map(|index| {
        let offset = phoff + index * phentsize;
        (read_u32(bytes, offset), read_u32(bytes, offset + 4), read_u64(bytes, offset + 8), read_u64(bytes, offset + 16), read_u64(bytes, offset + 32), read_u64(bytes, offset + 40))
    }).collect()
}

fn dynamic_value_offset(bytes: &[u8], wanted_tag: i64) -> usize {
    let dynamic = program_headers(bytes).into_iter().find(|h| h.0 == 2).unwrap();
    let mut offset = dynamic.2 as usize;
    let end = (dynamic.2 + dynamic.4) as usize;
    while offset + 16 <= end {
        let tag = read_i64(bytes, offset);
        if tag == wanted_tag { return offset + 8; }
        if tag == 0 { break; }
        offset += 16;
    }
    panic!("missing dynamic tag {wanted_tag}")
}

fn virtual_to_file(bytes: &[u8], address: u64) -> usize {
    for header in program_headers(bytes) {
        if header.0 != 1 { continue; }
        if address >= header.3 && address < header.3 + header.4 {
            return (header.2 + address - header.3) as usize;
        }
    }
    panic!("address {address:#x} not file-backed")
}

fn build_shared(dir: &Path) -> PathBuf {
    let assembly = dir.join("sample.s");
    let object = dir.join("sample.o");
    let shared = dir.join("libsample.so");
    fs::write(&assembly, ".data\n.local target\n.type target,@object\n.size target,8\ntarget:\n  .quad 0x1122334455667788\n.globl ptr\n.type ptr,@object\n.size ptr,8\nptr:\n  .quad target\n").unwrap();
    let assembled = Command::new("as").arg("-o").arg(&object).arg(&assembly).output().unwrap();
    assert!(assembled.status.success(), "{}", String::from_utf8_lossy(&assembled.stderr));
    let linked = Command::new("ld").arg("-shared").arg("-o").arg(&shared).arg(&object).output().unwrap();
    assert!(linked.status.success(), "{}", String::from_utf8_lossy(&linked.stderr));
    shared
}

fn rela_offset(bytes: &[u8]) -> usize {
    let rela_address = read_u64(bytes, dynamic_value_offset(bytes, 7));
    virtual_to_file(bytes, rela_address)
}

fn make_relative64(shared: &Path, output: &Path) -> Vec<u8> {
    let mut bytes = fs::read(shared).unwrap();
    let rela = rela_offset(&bytes);
    let symbol = read_u64(&bytes, rela + 8) >> 32;
    assert_eq!(symbol, 0, "fixture should begin with a symbol-free relative relocation");
    bytes[rela + 8..rela + 16].copy_from_slice(&38_u64.to_le_bytes());
    fs::write(output, &bytes).unwrap();
    bytes
}

fn run(path: &Path, bias: u64) -> Output {
    Command::new(env!("CARGO_BIN_EXE_mini-elf-dynrela-relative64"))
        .arg(format!("--load-bias={bias:#x}"))
        .arg(path)
        .output()
        .unwrap()
}

#[test]
fn relative64_matches_gnu_readelf_and_computes_bias_plus_addend() {
    if !tool_available("as") || !tool_available("ld") || !tool_available("readelf") { return; }
    let dir = temp_dir("dynrela-relative64-gnu");
    let shared = build_shared(&dir);
    let patched = dir.join("relative64.so");
    let bytes = make_relative64(&shared, &patched);
    let gnu = Command::new("readelf").arg("-rW").arg(&patched).output().unwrap();
    assert!(gnu.status.success());
    let gnu_text = String::from_utf8_lossy(&gnu.stdout);
    assert!(gnu_text.contains("R_X86_64_RELATIVE64"), "{gnu_text}");
    let addend = read_i64(&bytes, rela_offset(&bytes) + 16);
    assert!(addend >= 0);
    let bias = 0x7000_0000_u64;
    let expected = bias + addend as u64;
    let ours = run(&patched, bias);
    assert!(ours.status.success(), "{}", String::from_utf8_lossy(&ours.stderr));
    let text = String::from_utf8_lossy(&ours.stdout);
    assert!(text.contains("1 R_X86_64_RELATIVE64 relocations"), "{text}");
    assert!(text.contains(&format!("{expected:#018x}")), "{text}");
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn relative64_rejects_nonzero_symbol_index() {
    if !tool_available("as") || !tool_available("ld") { return; }
    let dir = temp_dir("dynrela-relative64-symbol");
    let shared = build_shared(&dir);
    let bad = dir.join("bad.so");
    let mut bytes = make_relative64(&shared, &bad);
    let rela = rela_offset(&bytes);
    bytes[rela + 8..rela + 16].copy_from_slice(&((1_u64 << 32) | 38).to_le_bytes());
    fs::write(&bad, bytes).unwrap();
    let output = run(&bad, 0x1000);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("non-zero symbol index 1"));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn relative64_rejects_non_writable_target() {
    if !tool_available("as") || !tool_available("ld") { return; }
    let dir = temp_dir("dynrela-relative64-target");
    let shared = build_shared(&dir);
    let bad = dir.join("bad.so");
    let mut bytes = make_relative64(&shared, &bad);
    let target = program_headers(&bytes).into_iter().find(|h| h.0 == 1 && h.1 & 2 == 0 && h.5 >= 8).expect("fixture should have a non-writable PT_LOAD").3;
    let rela = rela_offset(&bytes);
    bytes[rela..rela + 8].copy_from_slice(&target.to_le_bytes());
    fs::write(&bad, bytes).unwrap();
    let output = run(&bad, 0x1000);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("non-writable PT_LOAD"));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn relative64_rejects_bias_addend_overflow() {
    if !tool_available("as") || !tool_available("ld") { return; }
    let dir = temp_dir("dynrela-relative64-overflow");
    let shared = build_shared(&dir);
    let bad = dir.join("bad.so");
    let mut bytes = make_relative64(&shared, &bad);
    let rela = rela_offset(&bytes);
    bytes[rela + 16..rela + 24].copy_from_slice(&1_i64.to_le_bytes());
    fs::write(&bad, bytes).unwrap();
    let output = run(&bad, u64::MAX);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("value overflows u64"));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn malformed_later_input_keeps_stdout_atomic() {
    if !tool_available("as") || !tool_available("ld") { return; }
    let dir = temp_dir("dynrela-relative64-atomic");
    let shared = build_shared(&dir);
    let good = dir.join("good.so");
    let mut good_bytes = make_relative64(&shared, &good);
    let bad = dir.join("bad.so");
    let relaent = dynamic_value_offset(&good_bytes, 9);
    good_bytes[relaent..relaent + 8].copy_from_slice(&16_u64.to_le_bytes());
    fs::write(&bad, good_bytes).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-dynrela-relative64"))
        .arg("--load-bias=0x400000").arg(&good).arg(&bad).output().unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty(), "stdout must remain atomic");
    assert!(String::from_utf8_lossy(&output.stderr).contains("DT_RELAENT is 16"));
    let _ = fs::remove_dir_all(dir);
}
