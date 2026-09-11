use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const DT_NULL: i64 = 0;
const DT_HASH: i64 = 4;
const DT_GNU_HASH: i64 = 0x6fff_fef5;

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

fn phdrs(bytes: &[u8]) -> Vec<(u32, u64, u64, u64)> {
    let offset = read_u64(bytes, 32) as usize;
    let size = usize::from(read_u16(bytes, 54));
    let count = usize::from(read_u16(bytes, 56));
    (0..count)
        .map(|index| {
            let cursor = offset + index * size;
            (
                read_u32(bytes, cursor),
                read_u64(bytes, cursor + 8),
                read_u64(bytes, cursor + 16),
                read_u64(bytes, cursor + 32),
            )
        })
        .collect()
}

fn map_vaddr(bytes: &[u8], address: u64) -> usize {
    for (kind, offset, vaddr, filesz) in phdrs(bytes) {
        if kind == PT_LOAD && address >= vaddr && address < vaddr + filesz {
            return (offset + address - vaddr) as usize;
        }
    }
    panic!("address {address:#x} is not file backed");
}

fn dynamic_tag(bytes: &[u8], wanted: i64) -> Option<u64> {
    let (_, offset, _, filesz) = phdrs(bytes)
        .into_iter()
        .find(|header| header.0 == PT_DYNAMIC)
        .unwrap();
    let mut cursor = offset as usize;
    let end = (offset + filesz) as usize;
    while cursor + 16 <= end {
        let tag = read_i64(bytes, cursor);
        let value = read_u64(bytes, cursor + 8);
        if tag == wanted {
            return Some(value);
        }
        if tag == DT_NULL {
            break;
        }
        cursor += 16;
    }
    None
}

fn build_fixture(dir: &Path) -> PathBuf {
    let asm = dir.join("fixture.s");
    let obj = dir.join("fixture.o");
    let image = dir.join("fixture.so");
    fs::write(
        &asm,
        ".text\n.globl alpha\n.type alpha,@function\nalpha:\nret\n.size alpha,.-alpha\n.globl beta\n.type beta,@function\nbeta:\nret\n.size beta,.-beta\n",
    )
    .unwrap();
    assert!(Command::new("as")
        .args(["--64", "-o", obj.to_str().unwrap(), asm.to_str().unwrap()])
        .status()
        .unwrap()
        .success());
    assert!(Command::new("ld")
        .args([
            "-shared",
            "--hash-style=sysv",
            "-o",
            image.to_str().unwrap(),
            obj.to_str().unwrap(),
        ])
        .status()
        .unwrap()
        .success());
    image
}

fn run_tool(symbol: &str, image: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_mini-elf-sysv-hash-lookup"))
        .arg(symbol)
        .arg(image)
        .output()
        .unwrap()
}

#[test]
fn resolves_exported_symbol_in_sysv_hash_only_image() {
    let dir = temp_dir("sysv-hash-lookup");
    let image = build_fixture(&dir);
    let bytes = fs::read(&image).unwrap();
    assert!(dynamic_tag(&bytes, DT_HASH).is_some());
    assert!(dynamic_tag(&bytes, DT_GNU_HASH).is_none());

    let readelf = Command::new("readelf")
        .args(["--dyn-syms", "-W", image.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(readelf.status.success());
    let readelf_text = String::from_utf8(readelf.stdout).unwrap();
    assert!(readelf_text.lines().any(|line| line.ends_with(" alpha")));

    let output = run_tool("alpha", &image);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("symbol=alpha index="), "{stdout}");
    assert!(stdout.contains("type=2"), "{stdout}");
    assert!(stdout.contains("visibility=0"), "{stdout}");
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn reports_missing_symbol_without_linear_dynsym_scan() {
    let dir = temp_dir("sysv-hash-missing");
    let image = build_fixture(&dir);
    let output = run_tool("definitely_missing", &image);
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "SysV hash lookup: symbol=definitely_missing not-found\n"
    );
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rejects_bucket_symbol_outside_chain_count() {
    let dir = temp_dir("sysv-hash-bucket-range");
    let image = build_fixture(&dir);
    let mut bytes = fs::read(&image).unwrap();
    let hash = map_vaddr(&bytes, dynamic_tag(&bytes, DT_HASH).unwrap());
    let bucket_count = read_u32(&bytes, hash);
    let chain_count = read_u32(&bytes, hash + 4);
    assert!(bucket_count > 0);
    bytes[hash + 8..hash + 12].copy_from_slice(&chain_count.to_le_bytes());
    let bad = dir.join("bad.so");
    fs::write(&bad, bytes).unwrap();

    let output = run_tool("alpha", &bad);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("outside chain count"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rejects_hash_table_virtual_range_overflow() {
    let dir = temp_dir("sysv-hash-address-overflow");
    let image = build_fixture(&dir);
    let mut bytes = fs::read(&image).unwrap();
    let (_, dynamic_offset, _, dynamic_filesz) = phdrs(&bytes)
        .into_iter()
        .find(|header| header.0 == PT_DYNAMIC)
        .unwrap();
    let mut cursor = dynamic_offset as usize;
    let end = (dynamic_offset + dynamic_filesz) as usize;
    while cursor + 16 <= end {
        if read_i64(&bytes, cursor) == DT_HASH {
            bytes[cursor + 8..cursor + 16].copy_from_slice(&(u64::MAX - 3).to_le_bytes());
            break;
        }
        cursor += 16;
    }
    let bad = dir.join("overflow.so");
    fs::write(&bad, bytes).unwrap();

    let output = run_tool("alpha", &bad);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("DT_HASH header virtual range overflows u64")
    );
    fs::remove_dir_all(dir).unwrap();
}
