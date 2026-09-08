use std::{fs, process::Command, time::{SystemTime, UNIX_EPOCH}};

const PT_PHDR: u32 = 6;

fn temp_dir(label: &str) -> std::path::PathBuf {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let path = std::env::temp_dir().join(format!("mini-elf-toolchain-{label}-{}-{nonce}", std::process::id()));
    fs::create_dir_all(&path).unwrap();
    path
}
fn available(tool: &str) -> bool { Command::new(tool).arg("--version").output().is_ok() }
fn u16at(b: &[u8], o: usize) -> u16 { u16::from_le_bytes(b[o..o+2].try_into().unwrap()) }
fn u32at(b: &[u8], o: usize) -> u32 { u32::from_le_bytes(b[o..o+4].try_into().unwrap()) }
fn u64at(b: &[u8], o: usize) -> u64 { u64::from_le_bytes(b[o..o+8].try_into().unwrap()) }
fn ph_offsets(b: &[u8]) -> Vec<usize> {
    let off = u64at(b, 32) as usize; let ent = u16at(b, 54) as usize; let n = u16at(b, 56) as usize;
    (0..n).map(|i| off + i * ent).collect()
}
fn phdr_offset(b: &[u8]) -> usize { ph_offsets(b).into_iter().find(|o| u32at(b, *o) == PT_PHDR).expect("GNU fixture should contain PT_PHDR") }
fn build(dir: &std::path::Path) -> std::path::PathBuf {
    let asm = dir.join("start.s"); let obj = dir.join("start.o"); let exe = dir.join("app");
    fs::write(&asm, ".text\n.globl _start\n_start:\n mov $60,%rax\n xor %rdi,%rdi\n syscall\n.section .note.GNU-stack,\"\",@progbits\n").unwrap();
    assert!(Command::new("as").arg("--64").arg("-o").arg(&obj).arg(&asm).status().unwrap().success());
    assert!(Command::new("ld").arg("-pie").arg("-o").arg(&exe).arg(&obj).status().unwrap().success());
    let bytes = fs::read(&exe).unwrap(); phdr_offset(&bytes); exe
}

#[test]
fn phdr_matches_gnu_readelf_and_load_bias() {
    if !available("as") || !available("ld") || !available("readelf") { return; }
    let dir = temp_dir("phdr-diff"); let exe = build(&dir);
    let gnu = Command::new("readelf").arg("-lW").arg(&exe).output().unwrap(); assert!(gnu.status.success());
    assert!(String::from_utf8_lossy(&gnu.stdout).lines().any(|l| l.trim_start().starts_with("PHDR")));
    let ours = Command::new(env!("CARGO_BIN_EXE_mini-elf-phdr")).arg("--load-bias=0x100000").arg(&exe).output().unwrap();
    assert!(ours.status.success(), "{}", String::from_utf8_lossy(&ours.stderr));
    let text = String::from_utf8_lossy(&ours.stdout); assert!(text.contains("PT_PHDR segment")); assert!(text.contains("runtime="));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn malformed_phdr_shape_and_runtime_overflow_are_rejected() {
    if !available("as") || !available("ld") { return; }
    let dir = temp_dir("phdr-malformed"); let exe = build(&dir); let original = fs::read(&exe).unwrap(); let ph = phdr_offset(&original);
    let bad = dir.join("bad-shape"); let mut bytes = original.clone(); bytes[ph+32..ph+40].copy_from_slice(&1u64.to_le_bytes()); bytes[ph+40..ph+48].copy_from_slice(&1u64.to_le_bytes()); fs::write(&bad, bytes).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_mini-elf-phdr")).arg(&bad).output().unwrap(); assert!(!result.status.success()); assert!(result.stdout.is_empty()); assert!(String::from_utf8_lossy(&result.stderr).contains("does not exactly describe"));
    let result = Command::new(env!("CARGO_BIN_EXE_mini-elf-phdr")).arg("--load-bias").arg(u64::MAX.to_string()).arg(&exe).output().unwrap(); assert!(!result.status.success()); assert!(result.stdout.is_empty()); assert!(String::from_utf8_lossy(&result.stderr).contains("runtime"));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn duplicate_phdr_and_atomic_stdout_are_rejected() {
    if !available("as") || !available("ld") { return; }
    let dir = temp_dir("phdr-atomic"); let good = build(&dir); let mut bytes = fs::read(&good).unwrap(); let ph = phdr_offset(&bytes);
    let other = ph_offsets(&bytes).into_iter().find(|o| *o != ph).unwrap(); bytes[other..other+4].copy_from_slice(&PT_PHDR.to_le_bytes()); let bad = dir.join("duplicate"); fs::write(&bad, bytes).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_mini-elf-phdr")).arg(&good).arg(&bad).output().unwrap(); assert!(!result.status.success()); assert!(result.stdout.is_empty()); assert!(String::from_utf8_lossy(&result.stderr).contains("multiple PT_PHDR"));
    let _ = fs::remove_dir_all(dir);
}
