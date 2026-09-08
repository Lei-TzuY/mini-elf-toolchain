use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const PT_GNU_PROPERTY: u32 = 0x6474_e553;

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

fn available(tool: &str) -> bool {
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

fn program_header_offsets(bytes: &[u8]) -> Vec<usize> {
    let offset = read_u64(bytes, 32) as usize;
    let entry_size = read_u16(bytes, 54) as usize;
    let count = read_u16(bytes, 56) as usize;
    (0..count)
        .map(|index| offset + index * entry_size)
        .collect()
}

fn property_header_offset(bytes: &[u8]) -> usize {
    program_header_offsets(bytes)
        .into_iter()
        .find(|offset| read_u32(bytes, *offset) == PT_GNU_PROPERTY)
        .expect("GNU fixture should contain PT_GNU_PROPERTY")
}

fn build_property_object(dir: &std::path::Path) -> std::path::PathBuf {
    let assembly = dir.join("property.s");
    let object = dir.join("property.o");
    let shared = dir.join("libproperty.so");
    fs::write(
        &assembly,
        ".section .note.gnu.property,\"a\",@note\n.p2align 3\n.long 4\n.long 16\n.long 5\n.asciz \"GNU\"\n.p2align 3\n.long 0xc0000002\n.long 4\n.long 3\n.long 0\n.text\n.globl exported\n.type exported,@function\nexported:\n ret\n.section .note.GNU-stack,\"\",@progbits\n",
    )
    .unwrap();
    let assembled = Command::new("as")
        .arg("--64")
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
    let bytes = fs::read(&shared).unwrap();
    property_header_offset(&bytes);
    shared
}

#[test]
fn x86_feature_1_and_matches_gnu_readelf() {
    if !available("as") || !available("ld") || !available("readelf") {
        return;
    }
    let dir = temp_dir("gnu-property-diff");
    let shared = build_property_object(&dir);
    let gnu = Command::new("readelf")
        .arg("-nW")
        .arg(&shared)
        .output()
        .unwrap();
    assert!(gnu.status.success());
    let gnu_text = String::from_utf8_lossy(&gnu.stdout);
    assert!(gnu_text.contains("IBT"), "{gnu_text}");
    assert!(gnu_text.contains("SHSTK"), "{gnu_text}");

    let ours = Command::new(env!("CARGO_BIN_EXE_mini-elf-gnu-property"))
        .arg(&shared)
        .output()
        .unwrap();
    assert!(
        ours.status.success(),
        "{}",
        String::from_utf8_lossy(&ours.stderr)
    );
    let text = String::from_utf8_lossy(&ours.stdout);
    assert!(text.contains("x86 feature_1_and=0x3 IBT SHSTK"), "{text}");
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn malformed_property_size_and_segment_range_are_rejected() {
    if !available("as") || !available("ld") {
        return;
    }
    let dir = temp_dir("gnu-property-malformed");
    let shared = build_property_object(&dir);
    let original = fs::read(&shared).unwrap();
    let phdr = property_header_offset(&original);
    let note_offset = read_u64(&original, phdr + 8) as usize;
    let property_offset = note_offset + 16;

    let bad_size = dir.join("bad-size");
    let mut bytes = original.clone();
    bytes[property_offset + 4..property_offset + 8].copy_from_slice(&u32::MAX.to_le_bytes());
    fs::write(&bad_size, bytes).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_mini-elf-gnu-property"))
        .arg(&bad_size)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert!(String::from_utf8_lossy(&result.stderr).contains("property data ends beyond"));

    let bad_range = dir.join("bad-range");
    let mut bytes = original;
    bytes[phdr + 32..phdr + 40].copy_from_slice(&u64::MAX.to_le_bytes());
    bytes[phdr + 40..phdr + 48].copy_from_slice(&u64::MAX.to_le_bytes());
    fs::write(&bad_range, bytes).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_mini-elf-gnu-property"))
        .arg(&bad_range)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert!(String::from_utf8_lossy(&result.stderr).contains("file range overflows"));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn malformed_later_input_keeps_stdout_atomic() {
    if !available("as") || !available("ld") {
        return;
    }
    let dir = temp_dir("gnu-property-atomic");
    let good = build_property_object(&dir);
    let mut bytes = fs::read(&good).unwrap();
    let phdr = property_header_offset(&bytes);
    let note_offset = read_u64(&bytes, phdr + 8) as usize;
    bytes[note_offset + 4..note_offset + 8].copy_from_slice(&u32::MAX.to_le_bytes());
    let bad = dir.join("bad-later");
    fs::write(&bad, bytes).unwrap();

    let result = Command::new(env!("CARGO_BIN_EXE_mini-elf-gnu-property"))
        .arg(&good)
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert!(String::from_utf8_lossy(&result.stderr).contains("descriptor ends beyond"));
    let _ = fs::remove_dir_all(dir);
}
