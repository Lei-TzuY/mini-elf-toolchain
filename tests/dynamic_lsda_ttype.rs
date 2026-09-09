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
    let image = dir.join("fixture");
    fs::write(
        &asm,
        ".section .text\n.globl fixture_fn\n.type fixture_fn,@function\nfixture_fn:\n.cfi_startproc\n.cfi_lsda 0x1b, lsda\nnop\nret\n.cfi_endproc\n.size fixture_fn, .-fixture_fn\n.section .gcc_except_table,\"a\",@progbits\n.globl lsda\n.hidden lsda\n.type lsda,@object\nlsda:\n.byte 0xff, 0x9b, 0x0d, 0x01, 0x04\n.byte 0x02, 0x03, 0x05, 0x01\n.byte 0x01, 0x00, 0x00\n.long type_slot - .\n.size lsda, .-lsda\n.section .rodata,\"a\",@progbits\n.globl type_target\n.hidden type_target\n.type type_target,@object\ntype_target:\n.byte 0x42\n.size type_target, .-type_target\n.section .data,\"aw\",@progbits\n.globl type_slot\n.hidden type_slot\n.type type_slot,@object\ntype_slot:\n.quad type_target\n.size type_slot, .-type_slot\n",
    )
    .unwrap();
    assert!(Command::new("as")
        .args(["-o", obj.to_str().unwrap(), asm.to_str().unwrap()])
        .status()
        .unwrap()
        .success());
    assert!(Command::new("ld")
        .args([
            "--eh-frame-hdr",
            "-e",
            "fixture_fn",
            "-o",
            image.to_str().unwrap(),
            obj.to_str().unwrap(),
        ])
        .status()
        .unwrap()
        .success());
    image
}

fn run_tool(inputs: &[&Path]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_mini-elf-lsda-ttype"));
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

fn section(file: &[u8], wanted: &[u8]) -> (usize, usize, u64) {
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
            return (
                read_u64(file, header + 24) as usize,
                read_u64(file, header + 32) as usize,
                read_u64(file, header + 16),
            );
        }
    }
    panic!("missing section {}", String::from_utf8_lossy(wanted));
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

fn readelf_hex(image: &Path) -> String {
    let output = Command::new("readelf")
        .args(["-x", ".gcc_except_table", image.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn resolves_indirect_type_target_against_gnu_symbols() {
    let dir = temp_dir("lsda-ttype-target-good");
    let image = build_fixture(&dir);
    let output = run_tool(&[&image]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let slot = symbol_address(&image, "type_slot");
    let target = symbol_address(&image, "type_target");
    assert!(stdout.contains("ttype-encoding=0x9b ttype-base=0x10 max-type-index=1"));
    assert!(stdout.contains("type-entry=[0xc,0x10)"));
    assert!(stdout.contains(&format!("slot={slot:#018x} target={target:#018x}")));
    let dump = readelf_hex(&image);
    assert!(
        dump.contains("ff9b0d01 04020305 01010000"),
        "unexpected readelf dump:\n{dump}"
    );
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rejects_pc_relative_pointer_slot_underflow() {
    let dir = temp_dir("lsda-ttype-slot-underflow");
    let image = build_fixture(&dir);
    let mut file = fs::read(&image).unwrap();
    let (offset, _, _) = section(&file, b".gcc_except_table");
    file[offset + 12..offset + 16].copy_from_slice(&i32::MIN.to_le_bytes());
    let malformed = dir.join("slot-underflow");
    fs::write(&malformed, file).unwrap();
    let output = run_tool(&[&malformed]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("pointer-slot address overflows u64"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rejects_pointer_slot_outside_file_backed_loads() {
    let dir = temp_dir("lsda-ttype-slot-unmapped");
    let image = build_fixture(&dir);
    let mut file = fs::read(&image).unwrap();
    let (offset, _, _) = section(&file, b".gcc_except_table");
    file[offset + 12..offset + 16].copy_from_slice(&i32::MAX.to_le_bytes());
    let malformed = dir.join("slot-unmapped");
    fs::write(&malformed, file).unwrap();
    let output = run_tool(&[&malformed]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("indirect pointer slot"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rejects_indirect_target_outside_file_backed_loads() {
    let dir = temp_dir("lsda-ttype-target-unmapped");
    let image = build_fixture(&dir);
    let mut file = fs::read(&image).unwrap();
    let (data_offset, data_size, _) = section(&file, b".data");
    assert!(data_size >= 8);
    file[data_offset..data_offset + 8].copy_from_slice(&u64::MAX.to_le_bytes());
    let malformed = dir.join("target-unmapped");
    fs::write(&malformed, file).unwrap();
    let output = run_tool(&[&malformed]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("indirect target"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rejects_type_table_base_past_section() {
    let dir = temp_dir("lsda-ttype-base");
    let image = build_fixture(&dir);
    let mut file = fs::read(&image).unwrap();
    let (offset, _, _) = section(&file, b".gcc_except_table");
    file[offset + 2] = 0x7f;
    let malformed = dir.join("bad-base");
    fs::write(&malformed, file).unwrap();
    let output = run_tool(&[&malformed]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("type-table base"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rejects_positive_index_that_overlaps_call_site_table() {
    let dir = temp_dir("lsda-ttype-index");
    let image = build_fixture(&dir);
    let mut file = fs::read(&image).unwrap();
    let (offset, _, _) = section(&file, b".gcc_except_table");
    file[offset + 9] = 0x02;
    let malformed = dir.join("bad-index");
    fs::write(&malformed, file).unwrap();
    let output = run_tool(&[&malformed]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("overlapping"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rejects_negative_type_filter_without_exception_spec_semantics() {
    let dir = temp_dir("lsda-ttype-negative");
    let image = build_fixture(&dir);
    let mut file = fs::read(&image).unwrap();
    let (offset, _, _) = section(&file, b".gcc_except_table");
    file[offset + 9] = 0x7f;
    let malformed = dir.join("negative");
    fs::write(&malformed, file).unwrap();
    let output = run_tool(&[&malformed]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("negative type filter"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn malformed_later_input_keeps_stdout_atomic() {
    let dir = temp_dir("lsda-ttype-atomic");
    let good = build_fixture(&dir);
    let mut file = fs::read(&good).unwrap();
    let (data_offset, _, _) = section(&file, b".data");
    file[data_offset..data_offset + 8].copy_from_slice(&u64::MAX.to_le_bytes());
    let malformed = dir.join("malformed");
    fs::write(&malformed, file).unwrap();
    let output = run_tool(&[&good, &malformed]);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    fs::remove_dir_all(dir).unwrap();
}
