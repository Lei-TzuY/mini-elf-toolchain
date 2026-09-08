use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const DT_STRSZ: i64 = 10;
const DT_VERDEF: i64 = 0x6fff_fffc;
const DT_VERDEFNUM: i64 = 0x6fff_fffd;

fn temp_dir(label: &str) -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "mini-elf-toolchain-{label}-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&path).unwrap();
    path
}

fn tool_available(tool: &str) -> bool {
    Command::new(tool).arg("--version").output().is_ok()
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

fn program_headers(bytes: &[u8]) -> Vec<(u32, u64, u64, u64)> {
    let phoff = read_u64(bytes, 32) as usize;
    let phentsize = read_u16(bytes, 54) as usize;
    let phnum = read_u16(bytes, 56) as usize;
    (0..phnum)
        .map(|index| {
            let offset = phoff + index * phentsize;
            (
                read_u32(bytes, offset),
                read_u64(bytes, offset + 8),
                read_u64(bytes, offset + 16),
                read_u64(bytes, offset + 32),
            )
        })
        .collect()
}

fn dynamic_entry_offset(bytes: &[u8], wanted_tag: i64) -> usize {
    let dynamic = program_headers(bytes)
        .into_iter()
        .find(|(segment_type, _, _, _)| *segment_type == 2)
        .expect("shared object should contain PT_DYNAMIC");
    let mut offset = dynamic.1 as usize;
    let end = (dynamic.1 + dynamic.3) as usize;
    while offset + 16 <= end {
        let tag = read_i64(bytes, offset);
        if tag == wanted_tag {
            return offset;
        }
        if tag == 0 {
            break;
        }
        offset += 16;
    }
    panic!("shared object should contain dynamic tag {wanted_tag}")
}

fn build_versioned_library(dir: &std::path::Path) -> std::path::PathBuf {
    let assembly = dir.join("lib.s");
    let object = dir.join("lib.o");
    let shared = dir.join("libversioned.so");
    let script = dir.join("versions.map");
    fs::write(
        &assembly,
        ".text\n.globl foo\n.type foo,@function\nfoo:\n  ret\n.size foo,.-foo\n",
    )
    .unwrap();
    fs::write(&script, "VERS_1 { global: foo; local: *; };\n").unwrap();
    let assembled = Command::new("as")
        .arg("-o")
        .arg(&object)
        .arg(&assembly)
        .output()
        .unwrap();
    assert!(
        assembled.status.success(),
        "{}",
        String::from_utf8_lossy(&assembled.stderr)
    );
    let linked = Command::new("ld")
        .arg("-shared")
        .arg("--hash-style=gnu")
        .arg("--version-script")
        .arg(&script)
        .arg("-o")
        .arg(&shared)
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        linked.status.success(),
        "{}",
        String::from_utf8_lossy(&linked.stderr)
    );
    shared
}

#[test]
fn defined_version_name_matches_gnu_readelf() {
    if !tool_available("as") || !tool_available("ld") || !tool_available("readelf") {
        return;
    }
    let dir = temp_dir("versym-verdef-name");
    let shared = build_versioned_library(&dir);

    let gnu = Command::new("readelf")
        .arg("-VW")
        .arg(&shared)
        .output()
        .unwrap();
    assert!(gnu.status.success());
    let gnu_text = String::from_utf8_lossy(&gnu.stdout);
    assert!(gnu_text.contains("VERS_1"), "{gnu_text}");

    let ours = Command::new(env!("CARGO_BIN_EXE_mini-elf-versym"))
        .arg(&shared)
        .output()
        .unwrap();
    assert!(
        ours.status.success(),
        "{}",
        String::from_utf8_lossy(&ours.stderr)
    );
    let ours_text = String::from_utf8_lossy(&ours.stdout);
    assert!(ours_text.contains("index=2"), "{ours_text}");
    assert!(ours_text.contains("name=VERS_1"), "{ours_text}");
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn zero_verdef_count_is_rejected_atomically() {
    if !tool_available("as") || !tool_available("ld") {
        return;
    }
    let dir = temp_dir("versym-verdef-zero");
    let shared = build_versioned_library(&dir);
    let bad = dir.join("bad.so");
    let mut bytes = fs::read(&shared).unwrap();
    let count_entry = dynamic_entry_offset(&bytes, DT_VERDEFNUM);
    bytes[count_entry + 8..count_entry + 16].copy_from_slice(&0u64.to_le_bytes());
    fs::write(&bad, bytes).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-versym"))
        .arg(&shared)
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("DT_VERDEFNUM must be non-zero"));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn overflowing_verdef_virtual_range_is_rejected() {
    if !tool_available("as") || !tool_available("ld") {
        return;
    }
    let dir = temp_dir("versym-verdef-overflow");
    let shared = build_versioned_library(&dir);
    let bad = dir.join("overflow.so");
    let mut bytes = fs::read(&shared).unwrap();
    let verdef_entry = dynamic_entry_offset(&bytes, DT_VERDEF);
    bytes[verdef_entry + 8..verdef_entry + 16].copy_from_slice(&u64::MAX.to_le_bytes());
    fs::write(&bad, bytes).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-versym"))
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("DT_VERDEF entry 0 virtual range overflows u64"));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn unterminated_verdef_name_is_rejected() {
    if !tool_available("as") || !tool_available("ld") {
        return;
    }
    let dir = temp_dir("versym-verdef-string");
    let shared = build_versioned_library(&dir);
    let bad = dir.join("bad-string.so");
    let mut bytes = fs::read(&shared).unwrap();
    let verdef_entry = dynamic_entry_offset(&bytes, DT_VERDEF);
    let verdef_address = read_u64(&bytes, verdef_entry + 8);
    let verdef_offset = program_headers(&bytes)
        .into_iter()
        .find_map(|(segment_type, offset, virtual_address, file_size)| {
            if segment_type == 1
                && verdef_address >= virtual_address
                && verdef_address < virtual_address + file_size
            {
                Some((offset + verdef_address - virtual_address) as usize)
            } else {
                None
            }
        })
        .unwrap();
    let aux_relative = read_u32(&bytes, verdef_offset + 12) as u64;
    let aux_address = verdef_address + aux_relative;
    let aux_offset = program_headers(&bytes)
        .into_iter()
        .find_map(|(segment_type, offset, virtual_address, file_size)| {
            if segment_type == 1
                && aux_address >= virtual_address
                && aux_address < virtual_address + file_size
            {
                Some((offset + aux_address - virtual_address) as usize)
            } else {
                None
            }
        })
        .unwrap();
    let name_offset = u64::from(read_u32(&bytes, aux_offset));
    let strsz_entry = dynamic_entry_offset(&bytes, DT_STRSZ);
    let truncated_strsz = name_offset + "VERS_1".len() as u64;
    bytes[strsz_entry + 8..strsz_entry + 16].copy_from_slice(&truncated_strsz.to_le_bytes());
    fs::write(&bad, bytes).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-versym"))
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Verdaux version name"));
    let _ = fs::remove_dir_all(dir);
}
