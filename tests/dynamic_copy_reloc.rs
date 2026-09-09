use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

const SHT_RELA: u32 = 4;
const R_X86_64_COPY: u32 = 5;
const PF_X: u32 = 1;

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
    let data_asm = dir.join("data.s");
    let data_obj = dir.join("data.o");
    let library = dir.join("libdata.so");
    fs::write(
        &data_asm,
        ".data\n.globl shared_data\n.type shared_data,@object\n.size shared_data,8\nshared_data:\n.quad 0x1122334455667788\n",
    )
    .unwrap();
    assert!(Command::new("as")
        .args(["-o", data_obj.to_str().unwrap(), data_asm.to_str().unwrap()])
        .status()
        .unwrap()
        .success());
    assert!(Command::new("ld")
        .args([
            "-shared",
            "-soname",
            "libdata.so",
            "-o",
            library.to_str().unwrap(),
            data_obj.to_str().unwrap(),
        ])
        .status()
        .unwrap()
        .success());

    let main_asm = dir.join("main.s");
    let main_obj = dir.join("main.o");
    let image = dir.join("copy-app");
    fs::write(
        &main_asm,
        ".text\n.globl _start\n.type _start,@function\n_start:\nmov shared_data(%rip), %rax\nret\n.size _start, .-_start\n",
    )
    .unwrap();
    assert!(Command::new("as")
        .args(["-o", main_obj.to_str().unwrap(), main_asm.to_str().unwrap()])
        .status()
        .unwrap()
        .success());
    assert!(Command::new("ld")
        .args([
            "--hash-style=sysv",
            "-dynamic-linker",
            "/lib64/ld-linux-x86-64.so.2",
            "-o",
            image.to_str().unwrap(),
            main_obj.to_str().unwrap(),
            "-L",
            dir.to_str().unwrap(),
            "-ldata",
        ])
        .status()
        .unwrap()
        .success());
    image
}

fn run_tool(inputs: &[&Path]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_mini-elf-copy-reloc"));
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

fn section_headers(bytes: &[u8]) -> Vec<(u32, u32, u64, u64, u32, u64)> {
    let shoff = read_u64(bytes, 40) as usize;
    let shentsize = usize::from(read_u16(bytes, 58));
    let shnum = usize::from(read_u16(bytes, 60));
    (0..shnum)
        .map(|index| {
            let offset = shoff + index * shentsize;
            (
                read_u32(bytes, offset),
                read_u32(bytes, offset + 4),
                read_u64(bytes, offset + 24),
                read_u64(bytes, offset + 32),
                read_u32(bytes, offset + 40),
                read_u64(bytes, offset + 56),
            )
        })
        .collect()
}

fn section_name_table(bytes: &[u8]) -> &[u8] {
    let headers = section_headers(bytes);
    let index = usize::from(read_u16(bytes, 62));
    let section = headers[index];
    &bytes[section.2 as usize..(section.2 + section.3) as usize]
}

fn section_name<'a>(strings: &'a [u8], offset: u32) -> &'a str {
    let tail = &strings[offset as usize..];
    let end = tail.iter().position(|byte| *byte == 0).unwrap();
    std::str::from_utf8(&tail[..end]).unwrap()
}

fn rela_dyn_header(bytes: &[u8]) -> (usize, (u32, u32, u64, u64, u32, u64)) {
    let headers = section_headers(bytes);
    let strings = section_name_table(bytes);
    headers
        .into_iter()
        .enumerate()
        .find(|(_, header)| header.1 == SHT_RELA && section_name(strings, header.0) == ".rela.dyn")
        .unwrap()
}

fn copy_rela_offset(bytes: &[u8]) -> usize {
    let (_, header) = rela_dyn_header(bytes);
    let start = header.2 as usize;
    let end = (header.2 + header.3) as usize;
    let mut cursor = start;
    while cursor + 24 <= end {
        if read_u64(bytes, cursor + 8) as u32 == R_X86_64_COPY {
            return cursor;
        }
        cursor += 24;
    }
    panic!("missing R_X86_64_COPY");
}

fn copy_symbol_index(bytes: &[u8]) -> usize {
    (read_u64(bytes, copy_rela_offset(bytes) + 8) >> 32) as usize
}

fn dynsym_header(bytes: &[u8]) -> (u32, u32, u64, u64, u32, u64) {
    let (_, rela) = rela_dyn_header(bytes);
    section_headers(bytes)[rela.4 as usize]
}

fn symbol_entry_offset(bytes: &[u8], index: usize) -> usize {
    let header = dynsym_header(bytes);
    header.2 as usize + index * 24
}

fn executable_address(bytes: &[u8]) -> u64 {
    let phoff = read_u64(bytes, 32) as usize;
    let phentsize = usize::from(read_u16(bytes, 54));
    let phnum = usize::from(read_u16(bytes, 56));
    for index in 0..phnum {
        let offset = phoff + index * phentsize;
        if read_u32(bytes, offset) == 1 && read_u32(bytes, offset + 4) & PF_X != 0 {
            return read_u64(bytes, offset + 16);
        }
    }
    panic!("missing executable PT_LOAD");
}

#[test]
fn validates_gnu_copy_relocation() {
    let dir = temp_dir("copy-good");
    let image = build_fixture(&dir);
    let readelf = Command::new("readelf")
        .args(["-rW", image.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(readelf.status.success());
    let relocations = String::from_utf8(readelf.stdout).unwrap();
    assert!(relocations.contains("R_X86_64_COPY"), "{relocations}");

    let output = run_tool(&[&image]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("R_X86_64_COPY"));
    assert!(stdout.contains(":shared_data "));
    assert!(stdout.contains("size=8"));
    assert!(stdout.contains("source=external"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rejects_invalid_dynamic_symbol_index() {
    let dir = temp_dir("copy-index");
    let image = build_fixture(&dir);
    let mut bytes = fs::read(&image).unwrap();
    let rela = copy_rela_offset(&bytes);
    let dynsym = dynsym_header(&bytes);
    let count = dynsym.3 / dynsym.5;
    bytes[rela + 8..rela + 16]
        .copy_from_slice(&((count << 32) | u64::from(R_X86_64_COPY)).to_le_bytes());
    let bad = dir.join("bad-index");
    fs::write(&bad, bytes).unwrap();
    let output = run_tool(&[&bad]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid dynamic symbol index"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rejects_nonzero_copy_addend() {
    let dir = temp_dir("copy-addend");
    let image = build_fixture(&dir);
    let mut bytes = fs::read(&image).unwrap();
    let rela = copy_rela_offset(&bytes);
    bytes[rela + 16..rela + 24].copy_from_slice(&1_i64.to_le_bytes());
    let bad = dir.join("bad-addend");
    fs::write(&bad, bytes).unwrap();
    let output = run_tool(&[&bad]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("nonzero RELA addend"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rejects_destination_outside_writable_load() {
    let dir = temp_dir("copy-target");
    let image = build_fixture(&dir);
    let mut bytes = fs::read(&image).unwrap();
    let rela = copy_rela_offset(&bytes);
    let symbol = copy_symbol_index(&bytes);
    let entry = symbol_entry_offset(&bytes, symbol);
    let executable = executable_address(&bytes);
    bytes[rela..rela + 8].copy_from_slice(&executable.to_le_bytes());
    bytes[entry + 8..entry + 16].copy_from_slice(&executable.to_le_bytes());
    let bad = dir.join("bad-target");
    fs::write(&bad, bytes).unwrap();
    let output = run_tool(&[&bad]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("writable PT_LOAD"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rejects_zero_sized_copy_destination() {
    let dir = temp_dir("copy-zero-size");
    let image = build_fixture(&dir);
    let mut bytes = fs::read(&image).unwrap();
    let symbol = copy_symbol_index(&bytes);
    let entry = symbol_entry_offset(&bytes, symbol);
    bytes[entry + 16..entry + 24].copy_from_slice(&0_u64.to_le_bytes());
    let bad = dir.join("bad-size");
    fs::write(&bad, bytes).unwrap();
    let output = run_tool(&[&bad]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("zero-sized"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn malformed_later_input_produces_no_stdout() {
    let dir = temp_dir("copy-atomic");
    let good = build_fixture(&dir);
    let mut bytes = fs::read(&good).unwrap();
    let rela = copy_rela_offset(&bytes);
    bytes[rela + 16..rela + 24].copy_from_slice(&1_i64.to_le_bytes());
    let bad = dir.join("bad-later");
    fs::write(&bad, bytes).unwrap();
    let output = run_tool(&[&good, &bad]);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    fs::remove_dir_all(dir).unwrap();
}
