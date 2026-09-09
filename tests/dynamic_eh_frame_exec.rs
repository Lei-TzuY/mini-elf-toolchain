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
        ".section .text\n.globl fixture_fn\n.type fixture_fn,@function\nfixture_fn:\n.cfi_startproc\nnop\nret\n.cfi_endproc\n.size fixture_fn, .-fixture_fn\n",
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
    let mut command = Command::new(env!("CARGO_BIN_EXE_mini-elf-eh-frame-exec"));
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

fn program_headers(file: &[u8]) -> Vec<(usize, u32, u32, u64, u64, u64)> {
    let phoff = read_u64(file, 32) as usize;
    let phentsize = usize::from(read_u16(file, 54));
    let phnum = usize::from(read_u16(file, 56));
    (0..phnum)
        .map(|index| {
            let offset = phoff + index * phentsize;
            (
                offset,
                read_u32(file, offset),
                read_u32(file, offset + 4),
                read_u64(file, offset + 8),
                read_u64(file, offset + 16),
                read_u64(file, offset + 32),
            )
        })
        .collect()
}

fn map_vaddr(file: &[u8], address: u64) -> usize {
    for (_, kind, _, offset, vaddr, filesz) in program_headers(file) {
        if kind == PT_LOAD && address >= vaddr && address < vaddr + filesz {
            return (offset + address - vaddr) as usize;
        }
    }
    panic!("address {address:#x} is not file-backed");
}

fn first_fde_offset(file: &[u8]) -> usize {
    let (_, _, _, eh_offset, eh_vaddr, _) = program_headers(file)
        .into_iter()
        .find(|(_, kind, _, _, _, _)| *kind == PT_GNU_EH_FRAME)
        .expect("GNU EH frame segment");
    let table = eh_offset as usize + 12;
    let fde = if read_i32(file, table + 4) >= 0 {
        eh_vaddr + read_i32(file, table + 4) as u64
    } else {
        eh_vaddr - u64::from(read_i32(file, table + 4).unsigned_abs())
    };
    map_vaddr(file, fde)
}

fn readelf_ranges(image: &Path) -> Vec<(u64, u64)> {
    let output = Command::new("readelf")
        .args(["-wf", image.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    text.lines()
        .filter_map(|line| {
            let marker = line.find("pc=")?;
            let range = line[marker + 3..].split_whitespace().next()?;
            let (start, end) = range.split_once("..")?;
            Some((
                u64::from_str_radix(start, 16).ok()?,
                u64::from_str_radix(end, 16).ok()?,
            ))
        })
        .collect()
}

#[test]
fn validates_gnu_fde_ranges_against_executable_loads() {
    let dir = temp_dir("eh-exec-good");
    let image = build_fixture(&dir);
    let output = run_tool(&[&image]);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8(output.stdout).unwrap();
    let ranges = readelf_ranges(&image);
    assert!(!ranges.is_empty(), "GNU readelf produced no FDE ranges");
    for (start, end) in ranges {
        assert!(
            stdout.contains(&format!("{start:#018x}..{end:#018x}")),
            "missing GNU range {start:#x}..{end:#x} in:\n{stdout}"
        );
    }
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rejects_fde_range_that_escapes_executable_load() {
    let dir = temp_dir("eh-exec-escape");
    let image = build_fixture(&dir);
    let mut file = fs::read(&image).unwrap();
    let fde = first_fde_offset(&file);
    file[fde + 12..fde + 16].copy_from_slice(&i32::MAX.to_le_bytes());
    let malformed = dir.join("escape.so");
    fs::write(&malformed, file).unwrap();

    let output = run_tool(&[&malformed]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("not fully contained in one executable file-backed PT_LOAD"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rejects_file_backed_load_virtual_range_overflow() {
    let dir = temp_dir("eh-exec-overflow");
    let image = build_fixture(&dir);
    let mut file = fs::read(&image).unwrap();
    let load = program_headers(&file)
        .into_iter()
        .find(|(_, kind, _, _, _, filesz)| *kind == PT_LOAD && *filesz > 2)
        .expect("nonempty load");
    file[load.0 + 16..load.0 + 24].copy_from_slice(&(u64::MAX - 1).to_le_bytes());
    let malformed = dir.join("overflow.so");
    fs::write(&malformed, file).unwrap();

    let output = run_tool(&[&malformed]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("file-backed virtual range overflows u64"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn multi_input_failure_keeps_stdout_atomic() {
    let dir = temp_dir("eh-exec-atomic");
    let good = build_fixture(&dir);
    let mut file = fs::read(&good).unwrap();
    let fde = first_fde_offset(&file);
    file[fde + 12..fde + 16].copy_from_slice(&i32::MAX.to_le_bytes());
    let malformed = dir.join("bad.so");
    fs::write(&malformed, file).unwrap();

    let output = run_tool(&[&good, &malformed]);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    fs::remove_dir_all(dir).unwrap();
}
