use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

const PT_LOAD: u32 = 1;
const PT_GNU_EH_FRAME: u32 = 0x6474_e550;

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
        ".section .text\n.hidden personality\n.type personality,@function\npersonality:\nret\n.size personality, .-personality\n.globl fixture_fn\n.type fixture_fn,@function\nfixture_fn:\n.cfi_startproc\n.cfi_personality 0x1b, personality\n.cfi_lsda 0x1b, lsda\nnop\nret\n.cfi_endproc\n.size fixture_fn, .-fixture_fn\n.section .gcc_except_table,\"a\",@progbits\n.globl lsda\n.hidden lsda\n.type lsda,@object\nlsda:\n.byte 0x42\n.size lsda, .-lsda\n",
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
    let mut command = Command::new(env!("CARGO_BIN_EXE_mini-elf-eh-frame-lsda"));
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

fn read_i32(file: &[u8], offset: usize) -> i32 {
    i32::from_le_bytes(file[offset..offset + 4].try_into().unwrap())
}

fn read_u64(file: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(file[offset..offset + 8].try_into().unwrap())
}

fn program_headers(file: &[u8]) -> Vec<(usize, u32, u64, u64, u64)> {
    let phoff = read_u64(file, 32) as usize;
    let phentsize = usize::from(read_u16(file, 54));
    let phnum = usize::from(read_u16(file, 56));
    (0..phnum)
        .map(|index| {
            let offset = phoff + index * phentsize;
            (
                offset,
                read_u32(file, offset),
                read_u64(file, offset + 8),
                read_u64(file, offset + 16),
                read_u64(file, offset + 32),
            )
        })
        .collect()
}

fn map_vaddr(file: &[u8], address: u64) -> usize {
    for (_, kind, offset, vaddr, filesz) in program_headers(file) {
        if kind == PT_LOAD && address >= vaddr && address < vaddr + filesz {
            return (offset + address - vaddr) as usize;
        }
    }
    panic!("address {address:#x} is not file-backed");
}

fn map_offset_to_vaddr(file: &[u8], offset: usize) -> u64 {
    for (_, kind, file_offset, vaddr, filesz) in program_headers(file) {
        if kind == PT_LOAD
            && offset as u64 >= file_offset
            && (offset as u64) < file_offset + filesz
        {
            return vaddr + offset as u64 - file_offset;
        }
    }
    panic!("offset {offset:#x} is not file-backed");
}

fn first_fde_address(file: &[u8]) -> u64 {
    let (_, _, eh_offset, eh_vaddr, _) = program_headers(file)
        .into_iter()
        .find(|(_, kind, _, _, _)| *kind == PT_GNU_EH_FRAME)
        .expect("GNU EH frame segment");
    let table = eh_offset as usize + 12;
    let displacement = read_i32(file, table + 4);
    if displacement >= 0 {
        eh_vaddr + displacement as u64
    } else {
        eh_vaddr - u64::from(displacement.unsigned_abs())
    }
}

fn skip_leb(file: &[u8], mut cursor: usize) -> usize {
    loop {
        let byte = file[cursor];
        cursor += 1;
        if byte & 0x80 == 0 {
            return cursor;
        }
    }
}

fn zplr_payload(file: &[u8]) -> (usize, usize) {
    let fde = first_fde_address(file);
    let fde_offset = map_vaddr(file, fde);
    let cie_delta = u64::from(read_u32(file, fde_offset + 4));
    let cie = fde + 4 - cie_delta;
    let cie_offset = map_vaddr(file, cie);
    assert_eq!(read_u32(file, cie_offset + 4), 0);
    assert_eq!(file[cie_offset + 8], 1);
    let aug_start = cie_offset + 9;
    let nul = file[aug_start..]
        .iter()
        .position(|byte| *byte == 0)
        .expect("augmentation terminator");
    assert_eq!(&file[aug_start..aug_start + nul], b"zPLR");
    let mut cursor = aug_start + nul + 1;
    cursor = skip_leb(file, cursor);
    cursor = skip_leb(file, cursor);
    cursor = skip_leb(file, cursor);
    let length_offset = cursor;
    cursor = skip_leb(file, cursor);
    (length_offset, cursor)
}

fn fde_lsda_payload(file: &[u8]) -> (usize, usize) {
    let fde = first_fde_address(file);
    let fde_offset = map_vaddr(file, fde);
    let length_offset = fde_offset + 16;
    let payload = skip_leb(file, length_offset);
    (length_offset, payload)
}

fn readelf_symbol(image: &Path, symbol: &str) -> u64 {
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
    panic!("GNU readelf did not report {symbol} symbol");
}

#[test]
fn validates_gnu_zplr_lsda_against_readelf_symbol() {
    let dir = temp_dir("eh-lsda-good");
    let image = build_fixture(&dir);
    let output = run_tool(&[&image]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let personality = readelf_symbol(&image, "personality");
    let lsda = readelf_symbol(&image, "lsda");
    assert!(stdout.contains(&format!("personality={personality:#018x}")));
    assert!(stdout.contains(&format!("lsda={lsda:#018x}")));

    let readelf = Command::new("readelf")
        .args(["-wf", image.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(readelf.status.success());
    let frames = String::from_utf8(readelf.stdout).unwrap();
    assert!(frames.lines().any(|line| {
        line.trim_start()
            .strip_prefix("Augmentation:")
            .is_some_and(|value| value.trim() == "\"zPLR\"")
    }));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rejects_unsupported_lsda_encoding() {
    let dir = temp_dir("eh-lsda-encoding");
    let image = build_fixture(&dir);
    let mut file = fs::read(&image).unwrap();
    let (_, payload) = zplr_payload(&file);
    file[payload + 5] = 0;
    let malformed = dir.join("encoding.so");
    fs::write(&malformed, file).unwrap();

    let output = run_tool(&[&malformed]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("LSDA encoding is not pcrel/sdata4"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rejects_lsda_pointer_arithmetic_underflow() {
    let dir = temp_dir("eh-lsda-underflow");
    let image = build_fixture(&dir);
    let mut file = fs::read(&image).unwrap();
    let (_, payload) = fde_lsda_payload(&file);
    file[payload..payload + 4].copy_from_slice(&i32::MIN.to_le_bytes());
    let malformed = dir.join("underflow.so");
    fs::write(&malformed, file).unwrap();

    let output = run_tool(&[&malformed]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("LSDA pointer arithmetic overflows u64"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rejects_lsda_target_outside_file_backed_loads() {
    let dir = temp_dir("eh-lsda-unmapped");
    let image = build_fixture(&dir);
    let mut file = fs::read(&image).unwrap();
    let (_, payload) = fde_lsda_payload(&file);
    let field_vaddr = map_offset_to_vaddr(&file, payload);
    let displacement = i32::try_from(field_vaddr)
        .ok()
        .and_then(|value| value.checked_neg())
        .expect("fixture address fits signed 32-bit displacement");
    file[payload..payload + 4].copy_from_slice(&displacement.to_le_bytes());
    let malformed = dir.join("unmapped.so");
    fs::write(&malformed, file).unwrap();

    let output = run_tool(&[&malformed]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("LSDA target 0x0 is not file-backed PT_LOAD data"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rejects_malformed_fde_lsda_payload_length() {
    let dir = temp_dir("eh-lsda-length");
    let image = build_fixture(&dir);
    let mut file = fs::read(&image).unwrap();
    let (length_offset, _) = fde_lsda_payload(&file);
    file[length_offset] = 5;
    let malformed = dir.join("length.so");
    fs::write(&malformed, file).unwrap();

    let output = run_tool(&[&malformed]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("zPLR augmentation payload has unsupported length 5"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn multi_input_failure_keeps_stdout_atomic() {
    let dir = temp_dir("eh-lsda-atomic");
    let good = build_fixture(&dir);
    let mut file = fs::read(&good).unwrap();
    let (_, payload) = zplr_payload(&file);
    file[payload + 5] = 0;
    let malformed = dir.join("bad.so");
    fs::write(&malformed, file).unwrap();

    let output = run_tool(&[&good, &malformed]);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    fs::remove_dir_all(dir).unwrap();
}
