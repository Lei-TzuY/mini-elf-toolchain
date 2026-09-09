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
        ".section .text\n.globl fixture_fn\n.type fixture_fn,@function\nfixture_fn:\n.cfi_startproc\n.cfi_lsda 0x1b, lsda\nnop\nret\n.cfi_endproc\n.size fixture_fn, .-fixture_fn\n.section .gcc_except_table,\"a\",@progbits\n.globl lsda\n.hidden lsda\n.type lsda,@object\nlsda:\n.byte 0xff, 0xff, 0x01, 0x04\n.byte 0x02, 0x03, 0x05, 0x01\n.byte 0x00, 0x00\n.zero 7\n.size lsda, .-lsda\n",
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
            "--eh-frame-hdr",
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
    let mut command = Command::new(env!("CARGO_BIN_EXE_mini-elf-lsda-header"));
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

fn lsda_offset(file: &[u8]) -> usize {
    let shoff = read_u64(file, 40) as usize;
    let shentsize = usize::from(read_u16(file, 58));
    let shnum = usize::from(read_u16(file, 60));
    let shstrndx = usize::from(read_u16(file, 62));
    let shstr = shoff + shstrndx * shentsize;
    let str_off = read_u64(file, shstr + 24) as usize;
    let str_size = read_u64(file, shstr + 32) as usize;
    let strings = &file[str_off..str_off + str_size];
    for index in 0..shnum {
        let header = shoff + index * shentsize;
        let name = read_u32(file, header) as usize;
        let end = strings[name..].iter().position(|byte| *byte == 0).unwrap() + name;
        if &strings[name..end] == b".gcc_except_table" {
            return read_u64(file, header + 24) as usize;
        }
    }
    panic!("missing .gcc_except_table");
}

fn write_filter_variant(dir: &Path, image: &Path, byte: u8, name: &str) -> PathBuf {
    let mut file = fs::read(image).unwrap();
    let offset = lsda_offset(&file);
    file[offset + 8] = byte;
    let malformed = dir.join(name);
    fs::write(&malformed, file).unwrap();
    malformed
}

#[test]
fn accepts_cleanup_filter_with_omitted_type_table_against_gnu_readelf() {
    let dir = temp_dir("lsda-filter-cleanup");
    let image = build_fixture(&dir);
    let output = run_tool(&[&image]);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("action[0]: offset=1 type-filter=0 next=0"));

    let readelf = Command::new("readelf")
        .args(["-x", ".gcc_except_table", image.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(readelf.status.success());
    let dump = String::from_utf8(readelf.stdout).unwrap();
    assert!(dump.contains("ffff0104 02030501 0000"), "unexpected readelf dump:\n{dump}");
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rejects_positive_handler_filter_when_type_table_is_omitted() {
    let dir = temp_dir("lsda-filter-positive");
    let image = build_fixture(&dir);
    let malformed = write_filter_variant(&dir, &image, 0x01, "positive.so");
    let output = run_tool(&[&malformed]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("type filter 1 requires a type table"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rejects_negative_exception_spec_filter_when_type_table_is_omitted() {
    let dir = temp_dir("lsda-filter-negative");
    let image = build_fixture(&dir);
    let malformed = write_filter_variant(&dir, &image, 0x7f, "negative.so");
    let output = run_tool(&[&malformed]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("type filter -1 requires a type table"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn malformed_later_filter_keeps_multi_input_stdout_atomic() {
    let dir = temp_dir("lsda-filter-atomic");
    let image = build_fixture(&dir);
    let malformed = write_filter_variant(&dir, &image, 0x01, "positive.so");
    let output = run_tool(&[&image, &malformed]);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    fs::remove_dir_all(dir).unwrap();
}
