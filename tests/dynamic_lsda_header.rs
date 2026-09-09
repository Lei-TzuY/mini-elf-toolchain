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
        ".section .text\n.globl fixture_fn\n.type fixture_fn,@function\nfixture_fn:\n.cfi_startproc\n.cfi_lsda 0x1b, lsda\nnop\nret\n.cfi_endproc\n.size fixture_fn, .-fixture_fn\n.section .gcc_except_table,\"a\",@progbits\n.globl lsda\n.hidden lsda\n.type lsda,@object\nlsda:\n.byte 0xff, 0xff, 0x01, 0x04\n.byte 0x02, 0x03, 0x05, 0x01\n.zero 9\n.size lsda, .-lsda\n",
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

fn lsda_section(file: &[u8]) -> (usize, usize, u64) {
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
            return (
                read_u64(file, header + 24) as usize,
                read_u64(file, header + 32) as usize,
                read_u64(file, header + 16),
            );
        }
    }
    panic!("missing .gcc_except_table");
}

fn readelf_lsda_address(image: &Path) -> u64 {
    let output = Command::new("readelf")
        .args(["-SW", image.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    for line in text.lines() {
        if line.contains(".gcc_except_table") {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            let name_index = fields
                .iter()
                .position(|field| *field == ".gcc_except_table")
                .unwrap();
            return u64::from_str_radix(fields[name_index + 2], 16).unwrap();
        }
    }
    panic!("readelf did not report .gcc_except_table");
}

fn readelf_lsda_hex(image: &Path) -> String {
    let output = Command::new("readelf")
        .args(["-x", ".gcc_except_table", image.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn validates_gnu_lsda_call_site_entries_against_readelf() {
    let dir = temp_dir("lsda-header-good");
    let image = build_fixture(&dir);
    let output = run_tool(&[&image]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let address = readelf_lsda_address(&image);
    assert!(stdout.contains(&format!("address={address:#018x}")));
    assert!(stdout.contains("call-site-encoding=0x01 call-site-table-bytes=4 call-site-entries=1"));
    assert!(stdout.contains(
        "call-site[0]: start=0x2 length=0x3 end=0x5 landing-pad=0x5 action=1 action-records=1"
    ));
    assert!(stdout.contains("action[0]: offset=1 type-filter=0 next=0"));
    let readelf_hex = readelf_lsda_hex(&image);
    assert!(
        readelf_hex.contains("ffff0104 02030501"),
        "unexpected readelf dump:\n{readelf_hex}"
    );
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rejects_unsupported_lpstart_encoding() {
    let dir = temp_dir("lsda-header-lpstart");
    let image = build_fixture(&dir);
    let mut file = fs::read(&image).unwrap();
    let (offset, _, _) = lsda_section(&file);
    file[offset] = 0;
    let malformed = dir.join("lpstart.so");
    fs::write(&malformed, file).unwrap();
    let output = run_tool(&[&malformed]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("LPStart encoding"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rejects_unsupported_type_table_encoding() {
    let dir = temp_dir("lsda-header-ttype");
    let image = build_fixture(&dir);
    let mut file = fs::read(&image).unwrap();
    let (offset, _, _) = lsda_section(&file);
    file[offset + 1] = 0;
    let malformed = dir.join("ttype.so");
    fs::write(&malformed, file).unwrap();
    let output = run_tool(&[&malformed]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("type-table encoding"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rejects_call_site_table_length_past_section() {
    let dir = temp_dir("lsda-header-length");
    let image = build_fixture(&dir);
    let mut file = fs::read(&image).unwrap();
    let (offset, size, _) = lsda_section(&file);
    assert!(size >= 17);
    file[offset + 3] = 0x7f;
    let malformed = dir.join("length.so");
    fs::write(&malformed, file).unwrap();
    let output = run_tool(&[&malformed]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("call-site table declares"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rejects_truncated_call_site_entry_inside_declared_table() {
    let dir = temp_dir("lsda-header-entry-truncated");
    let image = build_fixture(&dir);
    let mut file = fs::read(&image).unwrap();
    let (offset, _, _) = lsda_section(&file);
    file[offset + 3] = 3;
    let malformed = dir.join("entry-truncated.so");
    fs::write(&malformed, file).unwrap();
    let output = run_tool(&[&malformed]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("entry 0 action"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rejects_call_site_interval_overflow() {
    let dir = temp_dir("lsda-header-entry-overflow");
    let image = build_fixture(&dir);
    let mut file = fs::read(&image).unwrap();
    let (offset, size, _) = lsda_section(&file);
    assert!(size >= 17);
    file[offset + 3] = 13;
    file[offset + 4..offset + 14]
        .copy_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]);
    file[offset + 14] = 1;
    file[offset + 15] = 0;
    file[offset + 16] = 0;
    let malformed = dir.join("entry-overflow.so");
    fs::write(&malformed, file).unwrap();
    let output = run_tool(&[&malformed]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("start+length overflows u64"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rejects_action_offset_outside_action_table() {
    let dir = temp_dir("lsda-action-outside");
    let image = build_fixture(&dir);
    let mut file = fs::read(&image).unwrap();
    let (offset, _, _) = lsda_section(&file);
    file[offset + 7] = 0x20;
    let malformed = dir.join("action-outside.so");
    fs::write(&malformed, file).unwrap();
    let output = run_tool(&[&malformed]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("outside the action table"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rejects_action_offset_arithmetic_overflow() {
    let dir = temp_dir("lsda-action-overflow");
    let image = build_fixture(&dir);
    let mut file = fs::read(&image).unwrap();
    let (offset, size, _) = lsda_section(&file);
    assert!(size >= 17);
    file[offset + 3] = 13;
    file[offset + 4] = 0;
    file[offset + 5] = 0;
    file[offset + 6] = 0;
    file[offset + 7..offset + 17]
        .copy_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]);
    let malformed = dir.join("action-overflow.so");
    fs::write(&malformed, file).unwrap();
    let output = run_tool(&[&malformed]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("action offset overflows usize")
            || stderr.contains("action offset does not fit usize")
    );
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rejects_truncated_action_record_sleb() {
    let dir = temp_dir("lsda-action-truncated");
    let image = build_fixture(&dir);
    let mut file = fs::read(&image).unwrap();
    let (offset, size, _) = lsda_section(&file);
    assert_eq!(size, 17);
    file[offset + 7] = 9;
    file[offset + 16] = 0x80;
    let malformed = dir.join("action-truncated.so");
    fs::write(&malformed, file).unwrap();
    let output = run_tool(&[&malformed]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("type filter SLEB128"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rejects_action_next_displacement_outside_action_table() {
    let dir = temp_dir("lsda-action-next-outside");
    let image = build_fixture(&dir);
    let mut file = fs::read(&image).unwrap();
    let (offset, _, _) = lsda_section(&file);
    file[offset + 8] = 0;
    file[offset + 9] = 0x20;
    let malformed = dir.join("action-next-outside.so");
    fs::write(&malformed, file).unwrap();
    let output = run_tool(&[&malformed]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("leaves the action table"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rejects_action_chain_cycle() {
    let dir = temp_dir("lsda-action-cycle");
    let image = build_fixture(&dir);
    let mut file = fs::read(&image).unwrap();
    let (offset, _, _) = lsda_section(&file);
    file[offset + 8] = 0;
    file[offset + 9] = 0x7f;
    let malformed = dir.join("action-cycle.so");
    fs::write(&malformed, file).unwrap();
    let output = run_tool(&[&malformed]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("action chain contains a cycle"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn malformed_later_input_keeps_stdout_atomic() {
    let dir = temp_dir("lsda-header-atomic");
    let good = build_fixture(&dir);
    let mut file = fs::read(&good).unwrap();
    let (offset, _, _) = lsda_section(&file);
    file[offset + 9] = 0x20;
    let bad = dir.join("bad.so");
    fs::write(&bad, file).unwrap();
    let output = run_tool(&[&good, &bad]);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("leaves the action table"));
    fs::remove_dir_all(dir).unwrap();
}
