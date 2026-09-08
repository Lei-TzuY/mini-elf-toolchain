use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const PT_GNU_STACK: u32 = 0x6474_e551;

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

fn stack_header_offset(bytes: &[u8]) -> usize {
    program_header_offsets(bytes)
        .into_iter()
        .find(|offset| read_u32(bytes, *offset) == PT_GNU_STACK)
        .expect("fixture should contain PT_GNU_STACK")
}

fn build_shared(dir: &std::path::Path, executable_stack: bool) -> std::path::PathBuf {
    let assembly = dir.join(if executable_stack {
        "exec.s"
    } else {
        "noexec.s"
    });
    let object = dir.join(if executable_stack {
        "exec.o"
    } else {
        "noexec.o"
    });
    let shared = dir.join(if executable_stack {
        "libexec.so"
    } else {
        "libnoexec.so"
    });
    let stack_flags = if executable_stack { "x" } else { "" };
    fs::write(
        &assembly,
        format!(
            ".text\n.globl exported\n.type exported,@function\nexported:\n  ret\n.section .note.GNU-stack,\"{stack_flags}\",@progbits\n"
        ),
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
    stack_header_offset(&bytes);
    shared
}

fn gnu_stack_flags(text: &str) -> String {
    let line = text
        .lines()
        .find(|line| line.trim_start().starts_with("GNU_STACK"))
        .expect("GNU readelf should report GNU_STACK");
    line.split_whitespace()
        .find(|field| *field == "R" || *field == "RW" || *field == "RWE" || *field == "RE")
        .expect("GNU_STACK line should contain flags")
        .to_owned()
}

#[test]
fn gnu_stack_matches_gnu_readelf_for_nonexec_and_exec_policy() {
    if !tool_available("as") || !tool_available("ld") || !tool_available("readelf") {
        return;
    }
    let dir = temp_dir("gnu-stack-diff");
    for executable in [false, true] {
        let shared = build_shared(&dir, executable);
        let gnu = Command::new("readelf")
            .arg("-lW")
            .arg(&shared)
            .output()
            .unwrap();
        assert!(gnu.status.success());
        let flags = gnu_stack_flags(&String::from_utf8_lossy(&gnu.stdout));
        let expected_exec = flags.contains('E');

        let ours = Command::new(env!("CARGO_BIN_EXE_mini-elf-gnu-stack"))
            .arg(&shared)
            .output()
            .unwrap();
        assert!(
            ours.status.success(),
            "{}",
            String::from_utf8_lossy(&ours.stderr)
        );
        let text = String::from_utf8_lossy(&ours.stdout);
        assert!(text.contains("PT_GNU_STACK segment"), "{text}");
        assert!(
            text.contains(if expected_exec {
                "executable=yes"
            } else {
                "executable=no"
            }),
            "gnu={flags} ours={text}"
        );
    }
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn duplicate_gnu_stack_segments_are_rejected() {
    if !tool_available("as") || !tool_available("ld") {
        return;
    }
    let dir = temp_dir("gnu-stack-duplicate");
    let shared = build_shared(&dir, false);
    let malformed = dir.join("duplicate.so");
    let mut bytes = fs::read(&shared).unwrap();
    let stack = stack_header_offset(&bytes);
    let other = program_header_offsets(&bytes)
        .into_iter()
        .find(|offset| *offset != stack)
        .expect("fixture should have another program header");
    bytes[other..other + 4].copy_from_slice(&PT_GNU_STACK.to_le_bytes());
    fs::write(&malformed, bytes).unwrap();

    let ours = Command::new(env!("CARGO_BIN_EXE_mini-elf-gnu-stack"))
        .arg(&malformed)
        .output()
        .unwrap();
    assert!(!ours.status.success());
    assert!(String::from_utf8_lossy(&ours.stderr).contains("multiple PT_GNU_STACK segments"));
    assert!(ours.stdout.is_empty());
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn unknown_stack_flags_and_file_range_overflow_are_rejected() {
    if !tool_available("as") || !tool_available("ld") {
        return;
    }
    let dir = temp_dir("gnu-stack-malformed");
    let shared = build_shared(&dir, false);
    let original = fs::read(&shared).unwrap();
    let stack = stack_header_offset(&original);

    let unknown = dir.join("unknown-flags.so");
    let mut bytes = original.clone();
    bytes[stack + 4..stack + 8].copy_from_slice(&0x8_u32.to_le_bytes());
    fs::write(&unknown, bytes).unwrap();
    let unknown_result = Command::new(env!("CARGO_BIN_EXE_mini-elf-gnu-stack"))
        .arg(&unknown)
        .output()
        .unwrap();
    assert!(!unknown_result.status.success());
    assert!(
        String::from_utf8_lossy(&unknown_result.stderr).contains("unknown permission flag bits")
    );
    assert!(unknown_result.stdout.is_empty());

    let overflow = dir.join("overflow.so");
    let mut bytes = original;
    bytes[stack + 8..stack + 16].copy_from_slice(&u64::MAX.to_le_bytes());
    bytes[stack + 32..stack + 40].copy_from_slice(&1_u64.to_le_bytes());
    bytes[stack + 40..stack + 48].copy_from_slice(&1_u64.to_le_bytes());
    fs::write(&overflow, bytes).unwrap();
    let overflow_result = Command::new(env!("CARGO_BIN_EXE_mini-elf-gnu-stack"))
        .arg(&overflow)
        .output()
        .unwrap();
    assert!(!overflow_result.status.success());
    assert!(String::from_utf8_lossy(&overflow_result.stderr).contains("file range overflows u64"));
    assert!(overflow_result.stdout.is_empty());
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn malformed_later_input_keeps_stdout_atomic() {
    if !tool_available("as") || !tool_available("ld") {
        return;
    }
    let dir = temp_dir("gnu-stack-atomic");
    let good = build_shared(&dir, false);
    let malformed = dir.join("bad.so");
    let mut bytes = fs::read(&good).unwrap();
    let stack = stack_header_offset(&bytes);
    bytes[stack + 4..stack + 8].copy_from_slice(&0x8_u32.to_le_bytes());
    fs::write(&malformed, bytes).unwrap();

    let result = Command::new(env!("CARGO_BIN_EXE_mini-elf-gnu-stack"))
        .arg(&good)
        .arg(&malformed)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert!(String::from_utf8_lossy(&result.stderr).contains("unknown permission flag bits"));
    let _ = fs::remove_dir_all(dir);
}
