use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const PT_INTERP: u32 = 3;

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

fn interp_header_offset(bytes: &[u8]) -> usize {
    program_header_offsets(bytes)
        .into_iter()
        .find(|offset| read_u32(bytes, *offset) == PT_INTERP)
        .expect("fixture should contain PT_INTERP")
}

fn build_executable(dir: &std::path::Path) -> std::path::PathBuf {
    let provider_assembly = dir.join("provider.s");
    let provider_object = dir.join("provider.o");
    let provider_shared = dir.join("libprovider.so");
    fs::write(
        &provider_assembly,
        ".text\n.globl external_function\n.type external_function,@function\nexternal_function:\n  ret\n.section .note.GNU-stack,\"\",@progbits\n",
    )
    .unwrap();
    let assembled = Command::new("as")
        .arg("--64")
        .arg("-o")
        .arg(&provider_object)
        .arg(&provider_assembly)
        .output()
        .unwrap();
    assert!(
        assembled.status.success(),
        "{}",
        String::from_utf8_lossy(&assembled.stderr)
    );
    let linked_provider = Command::new("ld")
        .arg("-shared")
        .arg("-o")
        .arg(&provider_shared)
        .arg(&provider_object)
        .output()
        .unwrap();
    assert!(
        linked_provider.status.success(),
        "{}",
        String::from_utf8_lossy(&linked_provider.stderr)
    );

    let assembly = dir.join("start.s");
    let object = dir.join("start.o");
    let executable = dir.join("app");
    fs::write(
        &assembly,
        ".text\n.globl _start\n.type _start,@function\n_start:\n  call external_function\n  mov $60,%rax\n  xor %rdi,%rdi\n  syscall\n.section .note.GNU-stack,\"\",@progbits\n",
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
        .arg("--dynamic-linker")
        .arg("/lib64/ld-linux-x86-64.so.2")
        .arg("-o")
        .arg(&executable)
        .arg(&object)
        .arg(&provider_shared)
        .output()
        .unwrap();
    assert!(
        linked.status.success(),
        "{}",
        String::from_utf8_lossy(&linked.stderr)
    );
    let bytes = fs::read(&executable).unwrap();
    interp_header_offset(&bytes);
    executable
}

fn gnu_interp(text: &str) -> String {
    let marker = "Requesting program interpreter: ";
    let line = text
        .lines()
        .find(|line| line.contains(marker))
        .expect("GNU readelf should report interpreter");
    line.split_once(marker)
        .unwrap()
        .1
        .trim_end_matches(']')
        .to_owned()
}

#[test]
fn interp_matches_gnu_readelf() {
    if !tool_available("as") || !tool_available("ld") || !tool_available("readelf") {
        return;
    }
    let dir = temp_dir("interp-diff");
    let executable = build_executable(&dir);
    let gnu = Command::new("readelf")
        .arg("-lW")
        .arg(&executable)
        .output()
        .unwrap();
    assert!(gnu.status.success());
    let expected = gnu_interp(&String::from_utf8_lossy(&gnu.stdout));

    let ours = Command::new(env!("CARGO_BIN_EXE_mini-elf-interp"))
        .arg(&executable)
        .output()
        .unwrap();
    assert!(
        ours.status.success(),
        "{}",
        String::from_utf8_lossy(&ours.stderr)
    );
    let text = String::from_utf8_lossy(&ours.stdout);
    assert!(text.contains("PT_INTERP segment"), "{text}");
    assert!(text.contains(&format!("interpreter={expected}")), "{text}");
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn duplicate_and_unterminated_interp_are_rejected() {
    if !tool_available("as") || !tool_available("ld") {
        return;
    }
    let dir = temp_dir("interp-malformed");
    let executable = build_executable(&dir);
    let original = fs::read(&executable).unwrap();
    let interp = interp_header_offset(&original);

    let duplicate = dir.join("duplicate");
    let mut bytes = original.clone();
    let other = program_header_offsets(&bytes)
        .into_iter()
        .find(|offset| *offset != interp)
        .expect("fixture should have another program header");
    bytes[other..other + 4].copy_from_slice(&PT_INTERP.to_le_bytes());
    fs::write(&duplicate, bytes).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_mini-elf-interp"))
        .arg(&duplicate)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("multiple PT_INTERP segments"));
    assert!(result.stdout.is_empty());

    let unterminated = dir.join("unterminated");
    let mut bytes = original;
    let offset = read_u64(&bytes, interp + 8) as usize;
    let size = read_u64(&bytes, interp + 32) as usize;
    bytes[offset + size - 1] = b'X';
    fs::write(&unterminated, bytes).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_mini-elf-interp"))
        .arg(&unterminated)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("not NUL-terminated"));
    assert!(result.stdout.is_empty());
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn interp_file_range_overflow_is_rejected() {
    if !tool_available("as") || !tool_available("ld") {
        return;
    }
    let dir = temp_dir("interp-overflow");
    let executable = build_executable(&dir);
    let malformed = dir.join("overflow");
    let mut bytes = fs::read(&executable).unwrap();
    let interp = interp_header_offset(&bytes);
    bytes[interp + 8..interp + 16].copy_from_slice(&u64::MAX.to_le_bytes());
    bytes[interp + 32..interp + 40].copy_from_slice(&2_u64.to_le_bytes());
    bytes[interp + 40..interp + 48].copy_from_slice(&2_u64.to_le_bytes());
    fs::write(&malformed, bytes).unwrap();

    let result = Command::new(env!("CARGO_BIN_EXE_mini-elf-interp"))
        .arg(&malformed)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("file range overflows u64"));
    assert!(result.stdout.is_empty());
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn malformed_later_input_keeps_stdout_atomic() {
    if !tool_available("as") || !tool_available("ld") {
        return;
    }
    let dir = temp_dir("interp-atomic");
    let good = build_executable(&dir);
    let bad = dir.join("bad");
    let mut bytes = fs::read(&good).unwrap();
    let interp = interp_header_offset(&bytes);
    let offset = read_u64(&bytes, interp + 8) as usize;
    let size = read_u64(&bytes, interp + 32) as usize;
    bytes[offset + size - 1] = b'X';
    fs::write(&bad, bytes).unwrap();

    let result = Command::new(env!("CARGO_BIN_EXE_mini-elf-interp"))
        .arg(&good)
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert!(String::from_utf8_lossy(&result.stderr).contains("not NUL-terminated"));
    let _ = fs::remove_dir_all(dir);
}
