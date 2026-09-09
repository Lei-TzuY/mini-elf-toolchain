use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const PT_GNU_EH_FRAME: u32 = 0x6474_e550;

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

fn program_header_offsets(bytes: &[u8]) -> Vec<usize> {
    let phoff = read_u64(bytes, 32) as usize;
    let phentsize = read_u16(bytes, 54) as usize;
    let phnum = read_u16(bytes, 56) as usize;
    (0..phnum).map(|index| phoff + index * phentsize).collect()
}

fn eh_frame_header_offset(bytes: &[u8]) -> usize {
    program_header_offsets(bytes)
        .into_iter()
        .find(|offset| read_u32(bytes, *offset) == PT_GNU_EH_FRAME)
        .expect("fixture should contain PT_GNU_EH_FRAME")
}

fn build_shared(dir: &std::path::Path) -> std::path::PathBuf {
    let assembly = dir.join("sample.s");
    let object = dir.join("sample.o");
    let shared = dir.join("libsample.so");
    fs::write(
        &assembly,
        ".text\n.globl exported\n.type exported,@function\nexported:\n.cfi_startproc\n  ret\n.cfi_endproc\n",
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
        .arg("--eh-frame-hdr")
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

fn parse_eh_frame_address(text: &str) -> u64 {
    let line = text
        .lines()
        .find(|line| line.split_whitespace().any(|field| field == ".eh_frame"))
        .expect("readelf should report .eh_frame");
    let fields = line.split_whitespace().collect::<Vec<_>>();
    let name_index = fields.iter().position(|field| *field == ".eh_frame").unwrap();
    u64::from_str_radix(fields[name_index + 2].trim_start_matches("0x"), 16).unwrap()
}

#[test]
fn pointer_matches_gnu_readelf_section_address() {
    if !tool_available("as") || !tool_available("ld") || !tool_available("readelf") {
        return;
    }
    let dir = temp_dir("eh-frame-pointer-gnu");
    let shared = build_shared(&dir);
    let readelf = Command::new("readelf")
        .arg("-SW")
        .arg(&shared)
        .output()
        .unwrap();
    assert!(readelf.status.success());
    let expected = parse_eh_frame_address(&String::from_utf8_lossy(&readelf.stdout));

    let ours = Command::new(env!("CARGO_BIN_EXE_mini-elf-eh-frame-pointer"))
        .arg(&shared)
        .output()
        .unwrap();
    assert!(
        ours.status.success(),
        "{}",
        String::from_utf8_lossy(&ours.stderr)
    );
    let text = String::from_utf8_lossy(&ours.stdout);
    assert!(
        text.contains(&format!("Link-time .eh_frame address: {expected:#018x}")),
        "{text}"
    );
    assert!(text.contains("File-backed PT_LOAD segment:"), "{text}");
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn pointer_underflow_is_rejected_and_later_failure_is_atomic() {
    if !tool_available("as") || !tool_available("ld") {
        return;
    }
    let dir = temp_dir("eh-frame-pointer-underflow");
    let good = build_shared(&dir);
    let malformed = dir.join("underflow.so");
    let mut bytes = fs::read(&good).unwrap();
    let ph = eh_frame_header_offset(&bytes);
    let data_offset = read_u64(&bytes, ph + 8) as usize;
    bytes[data_offset + 4..data_offset + 8].copy_from_slice(&i32::MIN.to_le_bytes());
    fs::write(&malformed, bytes).unwrap();

    let one = Command::new(env!("CARGO_BIN_EXE_mini-elf-eh-frame-pointer"))
        .arg(&malformed)
        .output()
        .unwrap();
    assert!(!one.status.success());
    assert!(
        String::from_utf8_lossy(&one.stderr).contains(".eh_frame pointer arithmetic overflows")
    );
    assert!(one.stdout.is_empty());

    let atomic = Command::new(env!("CARGO_BIN_EXE_mini-elf-eh-frame-pointer"))
        .arg(&good)
        .arg(&malformed)
        .output()
        .unwrap();
    assert!(!atomic.status.success());
    assert!(atomic.stdout.is_empty());
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn pointer_outside_file_backed_load_and_runtime_overflow_are_rejected() {
    if !tool_available("as") || !tool_available("ld") {
        return;
    }
    let dir = temp_dir("eh-frame-pointer-range");
    let good = build_shared(&dir);
    let malformed = dir.join("outside.so");
    let mut bytes = fs::read(&good).unwrap();
    let ph = eh_frame_header_offset(&bytes);
    let data_offset = read_u64(&bytes, ph + 8) as usize;
    bytes[data_offset + 4..data_offset + 8].copy_from_slice(&i32::MAX.to_le_bytes());
    fs::write(&malformed, bytes).unwrap();

    let outside = Command::new(env!("CARGO_BIN_EXE_mini-elf-eh-frame-pointer"))
        .arg(&malformed)
        .output()
        .unwrap();
    assert!(!outside.status.success());
    assert!(
        String::from_utf8_lossy(&outside.stderr).contains("not contained in a file-backed PT_LOAD")
    );
    assert!(outside.stdout.is_empty());

    let overflow = Command::new(env!("CARGO_BIN_EXE_mini-elf-eh-frame-pointer"))
        .arg("--load-bias")
        .arg(u64::MAX.to_string())
        .arg(&good)
        .output()
        .unwrap();
    assert!(!overflow.status.success());
    assert!(String::from_utf8_lossy(&overflow.stderr).contains("runtime .eh_frame address overflows u64"));
    assert!(overflow.stdout.is_empty());
    let _ = fs::remove_dir_all(dir);
}
