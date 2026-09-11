use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const DT_NULL: i64 = 0;
const DT_RELA: i64 = 7;
const DT_GNU_HASH: i64 = 0x6fff_fef5;
const R_X86_64_SIZE64: u32 = 33;

fn temp(label: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "mini-elf-size64-gnu-{label}-{}-{stamp}",
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
        ".text\n.globl dummy\ndummy:\nret\n.data\n.globl slot\nslot:\n.quad external@SIZE\n",
    )
    .unwrap();
    assert!(Command::new("as")
        .args([
            "--64",
            "-o",
            object.to_str().unwrap(),
            source.to_str().unwrap(),
        ])
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

fn run(input: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_mini-elf-dynrela-size64"))
        .arg(input)
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
    let offset = u64at(bytes, 32) as usize;
    let entry_size = usize::from(u16at(bytes, 54));
    let count = usize::from(u16at(bytes, 56));
    (0..count)
        .map(|index| {
            let p = offset + index * entry_size;
            (
                u32at(bytes, p),
                u64at(bytes, p + 8),
                u64at(bytes, p + 16),
                u64at(bytes, p + 32),
            )
        })
        .collect()
}

fn map_vaddr(bytes: &[u8], address: u64) -> usize {
    for (kind, offset, va, filesz) in phdrs(bytes) {
        if kind == PT_LOAD && address >= va && address < va + filesz {
            return (offset + address - va) as usize;
        }
    }
    panic!("address not file-backed")
}

fn dynamic_tag(bytes: &[u8], wanted: i64) -> Option<u64> {
    let (_, offset, _, filesz) = phdrs(bytes)
        .into_iter()
        .find(|header| header.0 == PT_DYNAMIC)
        .unwrap();
    let mut cursor = offset as usize;
    let end = (offset + filesz) as usize;
    while cursor + 16 <= end {
        let tag = i64at(bytes, cursor);
        let value = u64at(bytes, cursor + 8);
        if tag == wanted {
            return Some(value);
        }
        if tag == DT_NULL {
            return None;
        }
        cursor += 16;
    }
    None
}

#[test]
fn validates_gnu_hash_only_size64() {
    let dir = temp("good");
    let image = fixture(&dir);

    let dynamic = Command::new("readelf")
        .args(["-dW", image.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(dynamic.status.success());
    let dynamic_text = String::from_utf8_lossy(&dynamic.stdout);
    assert!(dynamic_text.contains("(GNU_HASH)"), "{dynamic_text}");
    assert!(!dynamic_text.contains(" (HASH)"), "{dynamic_text}");

    let relocations = Command::new("readelf")
        .args(["-rW", image.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(relocations.status.success());
    assert!(
        String::from_utf8_lossy(&relocations.stdout).contains("R_X86_64_SIZE64")
    );

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
    let gnu_hash = dynamic_tag(&bytes, DT_GNU_HASH).expect("GNU hash tag");
    let hash_offset = map_vaddr(&bytes, gnu_hash);
    bytes[hash_offset + 8..hash_offset + 12].copy_from_slice(&0u32.to_le_bytes());
    let bad = dir.join("bad.so");
    fs::write(&bad, bytes).unwrap();

    let output = run(&bad);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("bloom count"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn gnu_hash_fixture_contains_size64_relocation() {
    let dir = temp("reloc");
    let image = fixture(&dir);
    let bytes = fs::read(&image).unwrap();
    let rela = dynamic_tag(&bytes, DT_RELA).expect("RELA tag");
    let mut cursor = map_vaddr(&bytes, rela);
    let found = (0..64).any(|_| {
        let relocation = u64at(&bytes, cursor + 8) as u32 == R_X86_64_SIZE64;
        cursor += 24;
        relocation
    });
    assert!(found);
    fs::remove_dir_all(dir).unwrap();
}
