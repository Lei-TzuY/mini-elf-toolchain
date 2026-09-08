use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const PT_NOTE: u32 = 4;

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

fn note_header_offset(bytes: &[u8]) -> usize {
    program_header_offsets(bytes)
        .into_iter()
        .find(|offset| read_u32(bytes, *offset) == PT_NOTE)
        .expect("GNU fixture should contain PT_NOTE")
}

fn build_shared_object(dir: &std::path::Path) -> std::path::PathBuf {
    let assembly = dir.join("note.s");
    let object = dir.join("note.o");
    let shared = dir.join("libnote.so");
    fs::write(
        &assembly,
        ".text\n.globl exported\n.type exported,@function\nexported:\n ret\n.section .note.GNU-stack,\"\",@progbits\n",
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
        .arg("--build-id=sha1")
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
    note_header_offset(&bytes);
    shared
}

fn gnu_build_id(text: &str) -> String {
    text.lines()
        .find_map(|line| {
            line.split_once("Build ID:")
                .map(|(_, value)| value.trim().to_owned())
        })
        .expect("readelf should report a build ID")
}

#[test]
fn gnu_build_id_matches_readelf() {
    if !available("as") || !available("ld") || !available("readelf") {
        return;
    }
    let dir = temp_dir("note-build-id-diff");
    let shared = build_shared_object(&dir);
    let gnu = Command::new("readelf")
        .arg("-nW")
        .arg(&shared)
        .output()
        .unwrap();
    assert!(gnu.status.success());
    let build_id = gnu_build_id(&String::from_utf8_lossy(&gnu.stdout));

    let ours = Command::new(env!("CARGO_BIN_EXE_mini-elf-note"))
        .arg(&shared)
        .output()
        .unwrap();
    assert!(
        ours.status.success(),
        "{}",
        String::from_utf8_lossy(&ours.stderr)
    );
    let text = String::from_utf8_lossy(&ours.stdout);
    assert!(text.contains("PT_NOTE segment"), "{text}");
    assert!(text.contains("name=GNU"), "{text}");
    assert!(
        text.contains(&format!("GNU build-id: {build_id}")),
        "{text}"
    );
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn malformed_note_name_and_segment_ranges_are_rejected() {
    if !available("as") || !available("ld") {
        return;
    }
    let dir = temp_dir("note-malformed");
    let shared = build_shared_object(&dir);
    let original = fs::read(&shared).unwrap();
    let phdr = note_header_offset(&original);
    let note_offset = read_u64(&original, phdr + 8) as usize;

    let bad_name = dir.join("bad-name");
    let mut bytes = original.clone();
    bytes[note_offset..note_offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    fs::write(&bad_name, bytes).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_mini-elf-note"))
        .arg(&bad_name)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert!(String::from_utf8_lossy(&result.stderr).contains("name ends beyond"));

    let bad_range = dir.join("bad-range");
    let mut bytes = original;
    bytes[phdr + 32..phdr + 40].copy_from_slice(&u64::MAX.to_le_bytes());
    bytes[phdr + 40..phdr + 48].copy_from_slice(&u64::MAX.to_le_bytes());
    fs::write(&bad_range, bytes).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_mini-elf-note"))
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
    let dir = temp_dir("note-atomic");
    let good = build_shared_object(&dir);
    let mut bytes = fs::read(&good).unwrap();
    let phdr = note_header_offset(&bytes);
    let note_offset = read_u64(&bytes, phdr + 8) as usize;
    bytes[note_offset + 4..note_offset + 8].copy_from_slice(&u32::MAX.to_le_bytes());
    let bad = dir.join("bad-later");
    fs::write(&bad, bytes).unwrap();

    let result = Command::new(env!("CARGO_BIN_EXE_mini-elf-note"))
        .arg(&good)
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert!(String::from_utf8_lossy(&result.stderr).contains("descriptor ends beyond"));
    let _ = fs::remove_dir_all(dir);
}
