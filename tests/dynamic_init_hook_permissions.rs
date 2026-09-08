use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

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

fn read_i64(bytes: &[u8], offset: usize) -> i64 {
    i64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn program_header_offsets(bytes: &[u8]) -> Vec<usize> {
    let phoff = read_u64(bytes, 32) as usize;
    let phentsize = read_u16(bytes, 54) as usize;
    let phnum = read_u16(bytes, 56) as usize;
    (0..phnum).map(|index| phoff + index * phentsize).collect()
}

fn dynamic_value(bytes: &[u8], wanted_tag: i64) -> u64 {
    let dynamic = program_header_offsets(bytes)
        .into_iter()
        .find(|offset| read_u32(bytes, *offset) == 2)
        .expect("shared object should contain PT_DYNAMIC");
    let mut offset = read_u64(bytes, dynamic + 8) as usize;
    let end = offset + read_u64(bytes, dynamic + 32) as usize;
    while offset + 16 <= end {
        let tag = read_i64(bytes, offset);
        if tag == wanted_tag {
            return read_u64(bytes, offset + 8);
        }
        if tag == 0 {
            break;
        }
        offset += 16;
    }
    panic!("shared object should contain dynamic tag {wanted_tag}")
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
        .expect("direct hook should be contained in PT_LOAD")
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
    assert!(assembled.status.success());
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
    assert!(linked.status.success());
    shared
}

#[test]
fn direct_init_in_non_executable_load_is_rejected_atomically() {
    if !tool_available("as") || !tool_available("ld") || !tool_available("readelf") {
        return;
    }
    let dir = temp_dir("dyninit-hook-permissions");
    let good = build_shared(&dir);
    let good_bytes = fs::read(&good).unwrap();
    let init = dynamic_value(&good_bytes, 12);
    let load_offset = containing_load_offset(&good_bytes, init);
    let flags = read_u32(&good_bytes, load_offset + 4);
    assert_ne!(
        flags & PF_X,
        0,
        "GNU ld should place DT_INIT in executable PT_LOAD"
    );

    let readelf = Command::new("readelf")
        .arg("-dW")
        .arg(&good)
        .output()
        .unwrap();
    assert!(readelf.status.success());
    assert!(String::from_utf8_lossy(&readelf.stdout).contains("(INIT)"));

    let good_output = Command::new(env!("CARGO_BIN_EXE_mini-elf-dyninit"))
        .arg(&good)
        .output()
        .unwrap();
    assert!(good_output.status.success());

    let bad = dir.join("non-exec-init.so");
    let mut bad_bytes = good_bytes;
    bad_bytes[load_offset + 4..load_offset + 8].copy_from_slice(&(flags & !PF_X).to_le_bytes());
    fs::write(&bad, bad_bytes).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-dyninit"))
        .arg(&good)
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty(), "stdout must remain atomic");
    assert!(String::from_utf8_lossy(&output.stderr).contains("DT_INIT virtual address"));
    assert!(String::from_utf8_lossy(&output.stderr).contains("non-executable PT_LOAD segment"));
    let _ = fs::remove_dir_all(dir);
}
