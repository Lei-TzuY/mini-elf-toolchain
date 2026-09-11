use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const DT_NULL: i64 = 0;
const DT_HASH: i64 = 4;
const DT_SYMTAB: i64 = 6;
const DT_RELA: i64 = 7;
const DT_GNU_HASH: i64 = 0x6fff_fef5;
const R_X86_64_8: u32 = 14;

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
    let off = read_u64(bytes, 32) as usize;
    let size = usize::from(read_u16(bytes, 54));
    let count = usize::from(read_u16(bytes, 56));
    (0..count)
        .map(|i| {
            let p = off + i * size;
            (
                read_u32(bytes, p),
                read_u64(bytes, p + 8),
                read_u64(bytes, p + 16),
                read_u64(bytes, p + 32),
            )
        })
        .collect()
}

fn map_vaddr(bytes: &[u8], address: u64) -> usize {
    for (kind, off, vaddr, filesz) in phdrs(bytes) {
        if kind == PT_LOAD && address >= vaddr && address < vaddr + filesz {
            return (off + address - vaddr) as usize;
        }
    }
    panic!("address {address:#x} is not file backed");
}

fn dynamic_tag(bytes: &[u8], wanted: i64) -> Option<u64> {
    let (_, off, _, filesz) = phdrs(bytes)
        .into_iter()
        .find(|header| header.0 == PT_DYNAMIC)
        .unwrap();
    let mut cursor = off as usize;
    let end = (off + filesz) as usize;
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
        ".text\n.globl dummy\n.type dummy,@function\ndummy:\nret\n.size dummy, .-dummy\n.data\n.globl ptr\n.type ptr,@object\n.size ptr,8\nptr:\n.quad target\n.globl target\n.type target,@object\n.size target,8\ntarget:\n.quad 0x1122334455667788\n",
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
            "--hash-style=gnu",
            "-o",
            image.to_str().unwrap(),
            obj.to_str().unwrap(),
        ])
        .status()
        .unwrap()
        .success());

    let mut bytes = fs::read(&image).unwrap();
    let rela = dynamic_tag(&bytes, DT_RELA).unwrap();
    let mut cursor = map_vaddr(&bytes, rela);
    loop {
        let info = read_u64(&bytes, cursor + 8);
        if info as u32 == 1 {
            let symbol = info >> 32;
            bytes[cursor + 8..cursor + 16]
                .copy_from_slice(&((symbol << 32) | u64::from(R_X86_64_8)).to_le_bytes());
            let symtab = map_vaddr(&bytes, dynamic_tag(&bytes, DT_SYMTAB).unwrap());
            let symbol_value = read_u64(&bytes, symtab + symbol as usize * 24 + 8);
            let addend = 0x80_i64 - i64::try_from(symbol_value).unwrap();
            bytes[cursor + 16..cursor + 24].copy_from_slice(&addend.to_le_bytes());
            break;
        }
        cursor += 24;
    }
    fs::write(&image, bytes).unwrap();
    image
}

fn run_tool(image: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_mini-elf-dynrela-u8"))
        .args(["--load-bias", "0"])
        .arg(image)
        .output()
        .unwrap()
}

#[test]
fn accepts_gnu_hash_only_image_and_gnu_readelf_recognizes_relocation() {
    let dir = temp_dir("u8-gnu-hash");
    let image = build_fixture(&dir);
    let bytes = fs::read(&image).unwrap();
    assert!(dynamic_tag(&bytes, DT_GNU_HASH).is_some());
    assert!(dynamic_tag(&bytes, DT_HASH).is_none());

    let dynamic = Command::new("readelf")
        .args(["-dW", image.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(dynamic.status.success());
    let dynamic_text = String::from_utf8(dynamic.stdout).unwrap();
    assert!(dynamic_text.contains("GNU_HASH"), "{dynamic_text}");

    let relocs = Command::new("readelf")
        .args(["-rW", image.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(relocs.status.success());
    let reloc_text = String::from_utf8(relocs.stdout).unwrap();
    assert!(reloc_text.contains("R_X86_64_8"), "{reloc_text}");

    let output = run_tool(&image);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("Validated R_X86_64_8 relocations"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rejects_malformed_gnu_hash_bloom_count() {
    let dir = temp_dir("u8-gnu-hash-bloom");
    let image = build_fixture(&dir);
    let mut bytes = fs::read(&image).unwrap();
    let hash = map_vaddr(&bytes, dynamic_tag(&bytes, DT_GNU_HASH).unwrap());
    bytes[hash + 8..hash + 12].copy_from_slice(&3_u32.to_le_bytes());
    let bad = dir.join("bad-bloom.so");
    fs::write(&bad, bytes).unwrap();

    let output = run_tool(&bad);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("bloom count 3 must be a non-zero power of two"));
    fs::remove_dir_all(dir).unwrap();
}
