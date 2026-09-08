use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

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

fn program_headers(bytes: &[u8]) -> Vec<(u32, u64, u64, u64, u64)> {
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
                read_u64(bytes, offset + 40),
            )
        })
        .collect()
}

fn dynamic_range(bytes: &[u8]) -> (usize, usize) {
    let dynamic = program_headers(bytes)
        .into_iter()
        .find(|(segment_type, _, _, _, _)| *segment_type == 2)
        .expect("shared object should contain PT_DYNAMIC");
    (dynamic.1 as usize, (dynamic.1 + dynamic.3) as usize)
}

fn dynamic_value_offset(bytes: &[u8], wanted_tag: i64) -> usize {
    let (mut offset, end) = dynamic_range(bytes);
    while offset + 16 <= end {
        let tag = read_i64(bytes, offset);
        if tag == wanted_tag {
            return offset + 8;
        }
        if tag == 0 {
            break;
        }
        offset += 16;
    }
    panic!("shared object should contain dynamic tag {wanted_tag}")
}

fn duplicate_tag_offset(bytes: &[u8], wanted_tag: i64) -> usize {
    let (mut offset, end) = dynamic_range(bytes);
    while offset + 16 <= end {
        let tag = read_i64(bytes, offset);
        if tag == 0 {
            break;
        }
        if tag != 12 && tag != 13 && tag != wanted_tag {
            return offset;
        }
        offset += 16;
    }
    panic!("shared object should contain a spare dynamic entry to mutate")
}

fn build_shared(dir: &std::path::Path) -> std::path::PathBuf {
    let assembly = dir.join("hooks.s");
    let object = dir.join("hooks.o");
    let shared = dir.join("libhooks.so");
    fs::write(
        &assembly,
        ".text\n.globl init_hook\n.type init_hook,@function\ninit_hook:\n  ret\n.size init_hook,.-init_hook\n.globl fini_hook\n.type fini_hook,@function\nfini_hook:\n  ret\n.size fini_hook,.-fini_hook\n",
    )
    .unwrap();
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
        .arg("-init")
        .arg("init_hook")
        .arg("-fini")
        .arg("fini_hook")
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
fn direct_init_and_fini_hooks_match_gnu_readelf() {
    if !tool_available("as") || !tool_available("ld") || !tool_available("readelf") {
        return;
    }
    let dir = temp_dir("dyninit-hooks-gnu");
    let shared = build_shared(&dir);
    let bytes = fs::read(&shared).unwrap();
    let init = read_u64(&bytes, dynamic_value_offset(&bytes, 12));
    let fini = read_u64(&bytes, dynamic_value_offset(&bytes, 13));

    let gnu = Command::new("readelf")
        .arg("-dW")
        .arg(&shared)
        .output()
        .unwrap();
    assert!(gnu.status.success());
    let gnu_text = String::from_utf8_lossy(&gnu.stdout);
    assert!(gnu_text.contains("(INIT)"), "{gnu_text}");
    assert!(gnu_text.contains("(FINI)"), "{gnu_text}");
    assert!(gnu_text.contains(&format!("{init:#x}")), "{gnu_text}");
    assert!(gnu_text.contains(&format!("{fini:#x}")), "{gnu_text}");

    let ours = Command::new(env!("CARGO_BIN_EXE_mini-elf-dyninit"))
        .arg(&shared)
        .output()
        .unwrap();
    assert!(
        ours.status.success(),
        "{}",
        String::from_utf8_lossy(&ours.stderr)
    );
    let ours_text = String::from_utf8_lossy(&ours.stdout);
    assert!(
        ours_text.contains(&format!("DT_INIT: address={init:#x}")),
        "{ours_text}"
    );
    assert!(
        ours_text.contains(&format!("DT_FINI: address={fini:#x}")),
        "{ours_text}"
    );
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn duplicate_direct_init_tag_is_rejected() {
    if !tool_available("as") || !tool_available("ld") {
        return;
    }
    let dir = temp_dir("dyninit-hooks-duplicate");
    let shared = build_shared(&dir);
    let bad = dir.join("duplicate-init.so");
    let mut bytes = fs::read(&shared).unwrap();
    let offset = duplicate_tag_offset(&bytes, 12);
    bytes[offset..offset + 8].copy_from_slice(&12_i64.to_le_bytes());
    fs::write(&bad, bytes).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-dyninit"))
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("duplicate DT_INIT"));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn direct_init_address_overflow_is_rejected() {
    if !tool_available("as") || !tool_available("ld") {
        return;
    }
    let dir = temp_dir("dyninit-hooks-overflow");
    let shared = build_shared(&dir);
    let bad = dir.join("overflow-init.so");
    let mut bytes = fs::read(&shared).unwrap();
    let init = dynamic_value_offset(&bytes, 12);
    bytes[init..init + 8].copy_from_slice(&u64::MAX.to_le_bytes());
    fs::write(&bad, bytes).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-dyninit"))
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("DT_INIT virtual address range overflows u64"));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn malformed_later_hook_input_keeps_stdout_atomic() {
    if !tool_available("as") || !tool_available("ld") {
        return;
    }
    let dir = temp_dir("dyninit-hooks-atomic");
    let good = build_shared(&dir);
    let bad = dir.join("bad-fini.so");
    let mut bytes = fs::read(&good).unwrap();
    let fini = dynamic_value_offset(&bytes, 13);
    bytes[fini..fini + 8].copy_from_slice(&u64::MAX.to_le_bytes());
    fs::write(&bad, bytes).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-dyninit"))
        .arg(&good)
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty(), "stdout must remain atomic");
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("DT_FINI virtual address range overflows u64"));
    let _ = fs::remove_dir_all(dir);
}
