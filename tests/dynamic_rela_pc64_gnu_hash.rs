use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const DT_NULL: i64 = 0;
const DT_GNU_HASH: i64 = 0x6fff_fef5;

fn temp(label: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "mini-elf-pc64-gnu-{label}-{}-{stamp}",
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
        ".text\n.globl dummy\ndummy:\nret\n.data\n.globl slot\nslot:\n.quad external - .\n",
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
            "--hash-style=gnu",
            "-o",
            image.to_str().unwrap(),
            object.to_str().unwrap(),
        ])
        .status()
        .unwrap()
        .success());
    image
}

fn run(image: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_mini-elf-dynrela-pc64"))
        .arg(image)
        .output()
        .unwrap()
}

fn u16at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}
fn u32at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
fn u64at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}
fn i64at(bytes: &[u8], offset: usize) -> i64 {
    i64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn phdrs(bytes: &[u8]) -> Vec<(u32, u64, u64, u64)> {
    let phoff = u64at(bytes, 32) as usize;
    let phentsize = usize::from(u16at(bytes, 54));
    let phnum = usize::from(u16at(bytes, 56));
    (0..phnum)
        .map(|index| {
            let offset = phoff + index * phentsize;
            (
                u32at(bytes, offset),
                u64at(bytes, offset + 8),
                u64at(bytes, offset + 16),
                u64at(bytes, offset + 32),
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

fn dynamic_tag(bytes: &[u8], wanted: i64) -> u64 {
    let dynamic = phdrs(bytes)
        .into_iter()
        .find(|header| header.0 == PT_DYNAMIC)
        .unwrap();
    let mut cursor = dynamic.1 as usize;
    let end = (dynamic.1 + dynamic.3) as usize;
    while cursor + 16 <= end {
        let tag = i64at(bytes, cursor);
        let value = u64at(bytes, cursor + 8);
        if tag == wanted {
            return value;
        }
        if tag == DT_NULL {
            break;
        }
        cursor += 16;
    }
    panic!("missing dynamic tag {wanted}");
}

#[test]
fn accepts_gnu_hash_only_pc64_image() {
    let dir = temp("good");
    let image = fixture(&dir);

    let dynamic = Command::new("readelf")
        .args(["-dW", image.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(dynamic.status.success());
    let dynamic_text = String::from_utf8(dynamic.stdout).unwrap();
    assert!(dynamic_text.contains("GNU_HASH"), "{dynamic_text}");
    assert!(
        !dynamic_text.lines().any(|line| line.contains("(HASH)")),
        "{dynamic_text}"
    );

    let relocations = Command::new("readelf")
        .args(["-rW", image.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(relocations.status.success());
    let relocation_text = String::from_utf8(relocations.stdout).unwrap();
    assert!(relocation_text.contains("R_X86_64_PC64"), "{relocation_text}");

    let output = run(&image);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("binding=external"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rejects_malformed_gnu_hash_bloom_count() {
    let dir = temp("bad-bloom");
    let image = fixture(&dir);
    let mut bytes = fs::read(&image).unwrap();
    let gnu_hash = map_vaddr(&bytes, dynamic_tag(&bytes, DT_GNU_HASH));
    bytes[gnu_hash + 8..gnu_hash + 12].copy_from_slice(&3_u32.to_le_bytes());
    let bad = dir.join("bad.so");
    fs::write(&bad, bytes).unwrap();

    let output = run(&bad);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("non-zero power of two"));
    fs::remove_dir_all(dir).unwrap();
}
