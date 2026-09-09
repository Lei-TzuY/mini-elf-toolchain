use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

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
        ".section .text\n.globl fixture_fn\n.type fixture_fn,@function\nfixture_fn:\nret\n.size fixture_fn, .-fixture_fn\n.section .gcc_except_table,\"a\",@progbits\n.byte 0xff, 0x9b, 0x0d, 0x01, 0x04\n.byte 0x02, 0x03, 0x05, 0x01\n.byte 0x01, 0x00, 0x00\n.long type_slot - .\n.section .rodata,\"a\",@progbits\n.globl type_target\n.hidden type_target\n.type type_target,@object\ntype_target:\n.byte 0x42\n.size type_target, .-type_target\n.section .data,\"aw\",@progbits\n.globl type_slot\n.hidden type_slot\n.type type_slot,@object\ntype_slot:\n.quad type_target\n.size type_slot, .-type_slot\n",
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
            "-o",
            image.to_str().unwrap(),
            obj.to_str().unwrap()
        ])
        .status()
        .unwrap()
        .success());
    image
}

fn run_tool(inputs: &[&Path]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_mini-elf-lsda-relative"));
    for input in inputs {
        command.arg(input);
    }
    command.output().unwrap()
}

fn read_u16(file: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(file[offset..offset + 2].try_into().unwrap())
}

fn read_u32(file: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(file[offset..offset + 4].try_into().unwrap())
}

fn read_u64(file: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(file[offset..offset + 8].try_into().unwrap())
}

fn section_header(file: &[u8], wanted: &[u8]) -> usize {
    let shoff = read_u64(file, 40) as usize;
    let shentsize = usize::from(read_u16(file, 58));
    let shnum = usize::from(read_u16(file, 60));
    let shstrndx = usize::from(read_u16(file, 62));
    let shstr = shoff + shstrndx * shentsize;
    let strings_start = read_u64(file, shstr + 24) as usize;
    let strings_size = read_u64(file, shstr + 32) as usize;
    let strings = &file[strings_start..strings_start + strings_size];
    for index in 0..shnum {
        let header = shoff + index * shentsize;
        let name = read_u32(file, header) as usize;
        let end = name + strings[name..].iter().position(|byte| *byte == 0).unwrap();
        if &strings[name..end] == wanted {
            return header;
        }
    }
    panic!("missing section {}", String::from_utf8_lossy(wanted));
}

fn section(file: &[u8], wanted: &[u8]) -> (usize, usize, u64) {
    let header = section_header(file, wanted);
    (
        read_u64(file, header + 24) as usize,
        read_u64(file, header + 32) as usize,
        read_u64(file, header + 16),
    )
}

fn symbol_address(image: &Path, symbol: &str) -> u64 {
    let output = Command::new("readelf")
        .args(["-sW", image.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    for line in text.lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.last() == Some(&symbol) && fields.len() >= 2 {
            return u64::from_str_radix(fields[1], 16).unwrap();
        }
    }
    panic!("missing symbol {symbol} in readelf output:\n{text}");
}

fn readelf_relocations(image: &Path) -> String {
    let output = Command::new("readelf")
        .args(["-rW", image.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn resolves_et_dyn_relative_type_slot_against_gnu_relocation() {
    let dir = temp_dir("lsda-relative-good");
    let image = build_fixture(&dir);
    let relocations = readelf_relocations(&image);
    assert!(
        relocations.contains("R_X86_64_RELATIVE"),
        "unexpected GNU readelf relocation dump:\n{relocations}"
    );
    let output = run_tool(&[&image]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let slot = symbol_address(&image, "type_slot");
    let target = symbol_address(&image, "type_target");
    assert!(stdout.contains("max-type-index=1"));
    assert!(stdout.contains(&format!("slot={slot:#018x}")));
    assert!(stdout.contains(&format!("target=B+{target:#018x}")));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rejects_wrong_relocation_type_for_slot() {
    let dir = temp_dir("lsda-relative-type");
    let image = build_fixture(&dir);
    let mut file = fs::read(&image).unwrap();
    let (rela_offset, rela_size, _) = section(&file, b".rela.dyn");
    assert!(rela_size >= 24);
    let info = read_u64(&file, rela_offset + 8);
    let wrong = (info & !0xffff_ffff) | 1;
    file[rela_offset + 8..rela_offset + 16].copy_from_slice(&wrong.to_le_bytes());
    let malformed = dir.join("wrong-type.so");
    fs::write(&malformed, file).unwrap();
    let output = run_tool(&[&malformed]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("expected R_X86_64_RELATIVE"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rejects_nonzero_relative_symbol_index() {
    let dir = temp_dir("lsda-relative-symbol");
    let image = build_fixture(&dir);
    let mut file = fs::read(&image).unwrap();
    let (rela_offset, rela_size, _) = section(&file, b".rela.dyn");
    assert!(rela_size >= 24);
    let info = (1_u64 << 32) | 8;
    file[rela_offset + 8..rela_offset + 16].copy_from_slice(&info.to_le_bytes());
    let malformed = dir.join("bad-symbol.so");
    fs::write(&malformed, file).unwrap();
    let output = run_tool(&[&malformed]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("nonzero symbol index"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rejects_negative_relative_addend() {
    let dir = temp_dir("lsda-relative-negative");
    let image = build_fixture(&dir);
    let mut file = fs::read(&image).unwrap();
    let (rela_offset, rela_size, _) = section(&file, b".rela.dyn");
    assert!(rela_size >= 24);
    file[rela_offset + 16..rela_offset + 24].copy_from_slice(&(-1_i64).to_le_bytes());
    let malformed = dir.join("negative-addend.so");
    fs::write(&malformed, file).unwrap();
    let output = run_tool(&[&malformed]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("addend is negative"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rejects_relative_target_outside_file_backed_loads() {
    let dir = temp_dir("lsda-relative-target");
    let image = build_fixture(&dir);
    let mut file = fs::read(&image).unwrap();
    let (rela_offset, rela_size, _) = section(&file, b".rela.dyn");
    assert!(rela_size >= 24);
    file[rela_offset + 16..rela_offset + 24].copy_from_slice(&i64::MAX.to_le_bytes());
    let malformed = dir.join("unmapped-target.so");
    fs::write(&malformed, file).unwrap();
    let output = run_tool(&[&malformed]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("relative target"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rejects_truncated_rela_dyn_entry_envelope() {
    let dir = temp_dir("lsda-relative-rela-size");
    let image = build_fixture(&dir);
    let mut file = fs::read(&image).unwrap();
    let header = section_header(&file, b".rela.dyn");
    file[header + 32..header + 40].copy_from_slice(&23_u64.to_le_bytes());
    let malformed = dir.join("truncated-rela.so");
    fs::write(&malformed, file).unwrap();
    let output = run_tool(&[&malformed]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("whole number of RELA entries"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn malformed_later_input_keeps_stdout_atomic() {
    let dir = temp_dir("lsda-relative-atomic");
    let good = build_fixture(&dir);
    let mut file = fs::read(&good).unwrap();
    let (rela_offset, _, _) = section(&file, b".rela.dyn");
    file[rela_offset + 16..rela_offset + 24].copy_from_slice(&(-1_i64).to_le_bytes());
    let malformed = dir.join("malformed.so");
    fs::write(&malformed, file).unwrap();
    let output = run_tool(&[&good, &malformed]);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    fs::remove_dir_all(dir).unwrap();
}
