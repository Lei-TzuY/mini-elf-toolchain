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
        ".section .text\n.globl fixture_fn\n.type fixture_fn,@function\nfixture_fn:\n.cfi_startproc\n.cfi_lsda 0x1b, lsda\nnop\nret\n.cfi_endproc\n.size fixture_fn, .-fixture_fn\n.section .gcc_except_table,\"a\",@progbits\n.globl lsda\n.hidden lsda\n.type lsda,@object\nlsda:\n.byte 0xff, 0x9b, 0x0d, 0x01, 0x04\n.byte 0x02, 0x03, 0x05, 0x01\n.byte 0x01, 0x00, 0x00\n.long 0x11223344\n.size lsda, .-lsda\n",
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

fn lsda_section(file: &[u8]) -> (usize, usize) {
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
        if &strings[name..end] == b".gcc_except_table" {
            return (
                read_u64(file, header + 24) as usize,
                read_u64(file, header + 32) as usize,
            );
        }
    }
    panic!("missing .gcc_except_table");
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
fn validates_positive_type_index_against_gnu_readelf_bytes() {
    let dir = temp_dir("lsda-ttype-good");
    let image = build_fixture(&dir);
    let output = run_tool(&[&image]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("ttype-encoding=0x9b ttype-base=0x10 max-type-index=1"));
    assert!(stdout.contains(
        "action[0]: offset=1 type-index=1 type-entry=[0xc,0x10) raw-sdata4=287454020 next=0"
    ));
    let dump = readelf_hex(&image);
    assert!(
        dump.contains("ff9b0d01 04020305 01010000 44332211"),
        "unexpected readelf dump:\n{dump}"
    );
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rejects_type_table_base_past_section() {
    let dir = temp_dir("lsda-ttype-base");
    let image = build_fixture(&dir);
    let mut file = fs::read(&image).unwrap();
    let (offset, _) = lsda_section(&file);
    file[offset + 2] = 0x7f;
    let malformed = dir.join("bad-base.so");
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
    let (offset, _) = lsda_section(&file);
    file[offset + 9] = 0x02;
    let malformed = dir.join("bad-index.so");
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
    let (offset, _) = lsda_section(&file);
    file[offset + 9] = 0x7f;
    let malformed = dir.join("negative.so");
    fs::write(&malformed, file).unwrap();
    let output = run_tool(&[&malformed]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("negative type filter"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rejects_action_record_overlapping_type_entries() {
    let dir = temp_dir("lsda-ttype-action-overlap");
    let image = build_fixture(&dir);
    let mut file = fs::read(&image).unwrap();
    let (offset, size) = lsda_section(&file);
    assert_eq!(size, 16);
    file[offset + 10] = 0x02;
    file[offset + 12] = 0x01;
    file[offset + 13] = 0x00;
    let malformed = dir.join("action-overlap.so");
    fs::write(&malformed, file).unwrap();
    let output = run_tool(&[&malformed]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("overlap type-table"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn malformed_later_input_keeps_stdout_atomic() {
    let dir = temp_dir("lsda-ttype-atomic");
    let good = build_fixture(&dir);
    let mut file = fs::read(&good).unwrap();
    let (offset, _) = lsda_section(&file);
    file[offset + 2] = 0x7f;
    let malformed = dir.join("malformed.so");
    fs::write(&malformed, file).unwrap();
    let output = run_tool(&[&good, &malformed]);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    fs::remove_dir_all(dir).unwrap();
}
