use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const PT_LOAD: u32 = 1;
const PF_X: u32 = 1;

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

fn containing_load_offset(bytes: &[u8], address: u64) -> usize {
    program_header_offsets(bytes)
        .into_iter()
        .find(|offset| {
            if read_u32(bytes, *offset) != PT_LOAD {
                return false;
            }
            let start = read_u64(bytes, *offset + 16);
            let size = read_u64(bytes, *offset + 40);
            address >= start && address < start.checked_add(size).unwrap()
        })
        .expect("entry point should be contained in PT_LOAD")
}

fn build_object(dir: &std::path::Path) -> std::path::PathBuf {
    let assembly = dir.join("entry.s");
    let object = dir.join("entry.o");
    fs::write(
        &assembly,
        ".text\n.globl _start\n.type _start,@function\n_start:\n  xor %edi,%edi\n  mov $60,%eax\n  syscall\n.size _start,.-_start\n",
    )
    .unwrap();
    let assembled = Command::new("as")
        .arg("-o")
        .arg(&object)
        .arg(&assembly)
        .output()
        .unwrap();
    assert!(assembled.status.success());
    object
}

fn link_image(object: &std::path::Path, output: &std::path::Path, pie: bool) {
    let mut command = Command::new("ld");
    if pie {
        command.arg("-pie");
    }
    let linked = command
        .arg("-e")
        .arg("_start")
        .arg("-o")
        .arg(output)
        .arg(object)
        .output()
        .unwrap();
    assert!(linked.status.success(), "{}", String::from_utf8_lossy(&linked.stderr));
}

fn assert_readelf_entry(path: &std::path::Path, entry: u64) {
    let output = Command::new("readelf")
        .arg("-hW")
        .arg(path)
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Entry point address:"));
    assert!(stdout.contains(&format!("{entry:#x}")));
}

#[test]
fn gnu_exec_and_pie_entries_resolve_to_executable_loads() {
    if !tool_available("as") || !tool_available("ld") || !tool_available("readelf") {
        return;
    }
    let dir = temp_dir("entry-point-gnu");
    let object = build_object(&dir);
    let executable = dir.join("entry-exec");
    let pie = dir.join("entry-pie");
    link_image(&object, &executable, false);
    link_image(&object, &pie, true);

    for (path, expected_type, expected_name) in [
        (&executable, ET_EXEC, "ET_EXEC"),
        (&pie, ET_DYN, "ET_DYN"),
    ] {
        let bytes = fs::read(path).unwrap();
        assert_eq!(read_u16(&bytes, 16), expected_type);
        let entry = read_u64(&bytes, 24);
        assert_ne!(entry, 0);
        let load_offset = containing_load_offset(&bytes, entry);
        assert_ne!(read_u32(&bytes, load_offset + 4) & PF_X, 0);
        assert_readelf_entry(path, entry);

        let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-entry"))
            .arg(path)
            .output()
            .unwrap();
        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains(&format!("address={entry:#x}")));
        assert!(stdout.contains(expected_name));
    }
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn non_executable_entry_is_rejected_atomically() {
    if !tool_available("as") || !tool_available("ld") {
        return;
    }
    let dir = temp_dir("entry-point-nonexec");
    let object = build_object(&dir);
    let good = dir.join("good");
    link_image(&object, &good, false);

    let mut bad_bytes = fs::read(&good).unwrap();
    let entry = read_u64(&bad_bytes, 24);
    let load_offset = containing_load_offset(&bad_bytes, entry);
    let flags = read_u32(&bad_bytes, load_offset + 4);
    assert_ne!(flags & PF_X, 0);
    bad_bytes[load_offset + 4..load_offset + 8].copy_from_slice(&(flags & !PF_X).to_le_bytes());
    let bad = dir.join("bad-nonexec");
    fs::write(&bad, bad_bytes).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-entry"))
        .arg(&good)
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty(), "stdout must remain atomic");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("ELF entry point"));
    assert!(stderr.contains("non-executable PT_LOAD segment"));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn overflowing_entry_range_is_rejected() {
    if !tool_available("as") || !tool_available("ld") {
        return;
    }
    let dir = temp_dir("entry-point-overflow");
    let object = build_object(&dir);
    let good = dir.join("good");
    link_image(&object, &good, false);

    let mut bytes = fs::read(&good).unwrap();
    bytes[24..32].copy_from_slice(&u64::MAX.to_le_bytes());
    let bad = dir.join("bad-overflow");
    fs::write(&bad, bytes).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-entry"))
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("ELF entry-point virtual range overflows u64"));
    let _ = fs::remove_dir_all(dir);
}
