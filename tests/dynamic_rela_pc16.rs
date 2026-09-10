use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PF_X: u32 = 1;
const DT_NULL: i64 = 0;
const DT_HASH: i64 = 4;
const DT_SYMTAB: i64 = 6;
const DT_RELA: i64 = 7;
const R_X86_64_PC16: u32 = 13;

fn temp(label: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "mini-elf-pc16-{label}-{}-{stamp}",
        std::process::id()
    ));
    fs::create_dir_all(&path).unwrap();
    path
}

fn fixture(dir: &Path) -> PathBuf {
    let source = dir.join("fixture.s");
    let object = dir.join("fixture.o");
    let image = dir.join("fixture.so");
    fs::write(
        &source,
        ".text\n.globl dummy\ndummy:\nret\n.data\n.globl slot\nslot:\n.short external - .\n",
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
            image.to_str().unwrap(),
            object.to_str().unwrap(),
        ])
        .status()
        .unwrap()
        .success());
    image
}

fn run(inputs: &[&Path]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_mini-elf-dynrela-pc16"));
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
    let offset = read_u64(bytes, 32) as usize;
    let entry_size = usize::from(read_u16(bytes, 54));
    let count = usize::from(read_u16(bytes, 56));
    (0..count)
        .map(|index| {
            let start = offset + index * entry_size;
            (
                read_u32(bytes, start),
                read_u32(bytes, start + 4),
                read_u64(bytes, start + 8),
                read_u64(bytes, start + 16),
                read_u64(bytes, start + 32),
                read_u64(bytes, start + 40),
            )
        })
        .collect()
}

fn map_vaddr(bytes: &[u8], address: u64) -> usize {
    for header in program_headers(bytes) {
        if header.0 == PT_LOAD && address >= header.3 && address < header.3 + header.4 {
            return (header.2 + address - header.3) as usize;
        }
    }
    panic!("address {address:#x} is not file-backed");
}

fn dynamic_tag(bytes: &[u8], wanted: i64) -> u64 {
    let header = program_headers(bytes)
        .into_iter()
        .find(|header| header.0 == PT_DYNAMIC)
        .unwrap();
    let mut offset = header.2 as usize;
    let end = (header.2 + header.4) as usize;
    while offset + 16 <= end {
        let tag = read_i64(bytes, offset);
        let value = read_u64(bytes, offset + 8);
        if tag == wanted {
            return value;
        }
        if tag == DT_NULL {
            break;
        }
        offset += 16;
    }
    panic!("missing dynamic tag {wanted}");
}

fn rela_offset(bytes: &[u8]) -> usize {
    let mut offset = map_vaddr(bytes, dynamic_tag(bytes, DT_RELA));
    loop {
        if read_u64(bytes, offset + 8) as u32 == R_X86_64_PC16 {
            return offset;
        }
        offset += 24;
    }
}

fn symbol_count(bytes: &[u8]) -> u64 {
    let hash = map_vaddr(bytes, dynamic_tag(bytes, DT_HASH));
    u64::from(read_u32(bytes, hash + 4))
}

fn executable_address(bytes: &[u8]) -> u64 {
    program_headers(bytes)
        .into_iter()
        .find(|header| header.0 == PT_LOAD && header.1 & PF_X != 0 && header.4 >= 1)
        .unwrap()
        .3
}

fn make_same_image(bytes: &mut [u8], rela: usize, addend: i64) {
    let info = read_u64(bytes, rela + 8);
    let symbol_index = info >> 32;
    let target = read_u64(bytes, rela);
    let symtab = map_vaddr(bytes, dynamic_tag(bytes, DT_SYMTAB));
    let symbol = symtab + usize::try_from(symbol_index).unwrap() * 24;
    bytes[symbol + 6..symbol + 8].copy_from_slice(&1_u16.to_le_bytes());
    bytes[symbol + 8..symbol + 16].copy_from_slice(&target.to_le_bytes());
    bytes[rela + 16..rela + 24].copy_from_slice(&addend.to_le_bytes());
}

#[test]
fn validates_gnu_pc16_external_relocation() {
    let dir = temp("good");
    let image = fixture(&dir);
    let readelf = Command::new("readelf")
        .args(["-rW", image.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(readelf.status.success());
    assert!(
        String::from_utf8_lossy(&readelf.stdout).contains("R_X86_64_PC16"),
        "{}",
        String::from_utf8_lossy(&readelf.stdout)
    );
    let output = run(&[&image]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Validated R_X86_64_PC16 relocations"));
    assert!(stdout.contains("binding=external"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn validates_negative_same_image_result() {
    let dir = temp("negative");
    let image = fixture(&dir);
    let mut bytes = fs::read(&image).unwrap();
    let rela = rela_offset(&bytes);
    make_same_image(&mut bytes, rela, -1);
    let patched = dir.join("negative.so");
    fs::write(&patched, bytes).unwrap();
    let output = run(&[&patched]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("binding=same-image"));
    assert!(stdout.contains("result=-1"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rejects_invalid_symbol_index() {
    let dir = temp("index");
    let image = fixture(&dir);
    let mut bytes = fs::read(&image).unwrap();
    let rela = rela_offset(&bytes);
    let count = symbol_count(&bytes);
    bytes[rela + 8..rela + 16]
        .copy_from_slice(&((count << 32) | u64::from(R_X86_64_PC16)).to_le_bytes());
    let bad = dir.join("bad-index.so");
    fs::write(&bad, bytes).unwrap();
    let output = run(&[&bad]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid symbol index"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rejects_nonwritable_target() {
    let dir = temp("target");
    let image = fixture(&dir);
    let mut bytes = fs::read(&image).unwrap();
    let rela = rela_offset(&bytes);
    let text = executable_address(&bytes);
    bytes[rela..rela + 8].copy_from_slice(&text.to_le_bytes());
    let bad = dir.join("bad-target.so");
    fs::write(&bad, bytes).unwrap();
    let output = run(&[&bad]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("PC16 target"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rejects_result_outside_signed_16_bits() {
    let dir = temp("overflow");
    let image = fixture(&dir);
    let mut bytes = fs::read(&image).unwrap();
    let rela = rela_offset(&bytes);
    make_same_image(&mut bytes, rela, 32768);
    let bad = dir.join("overflow.so");
    fs::write(&bad, bytes).unwrap();
    let output = run(&[&bad]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("does not fit i16"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn malformed_later_input_keeps_stdout_atomic() {
    let dir = temp("atomic");
    let good = fixture(&dir);
    let mut bytes = fs::read(&good).unwrap();
    let rela = rela_offset(&bytes);
    let count = symbol_count(&bytes);
    bytes[rela + 8..rela + 16]
        .copy_from_slice(&((count << 32) | u64::from(R_X86_64_PC16)).to_le_bytes());
    let bad = dir.join("bad.so");
    fs::write(&bad, bytes).unwrap();
    let output = run(&[&good, &bad]);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    fs::remove_dir_all(dir).unwrap();
}
