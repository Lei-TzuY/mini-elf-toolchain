use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_dir() -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "mini-elf-toolchain-versym-gnu-hash-overflow-{}-{nonce}",
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

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn read_i64(bytes: &[u8], offset: usize) -> i64 {
    i64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn dynamic_entry_offset(bytes: &[u8], wanted_tag: i64) -> usize {
    let phoff = read_u64(bytes, 32) as usize;
    let phentsize = read_u16(bytes, 54) as usize;
    let phnum = read_u16(bytes, 56) as usize;
    for index in 0..phnum {
        let ph = phoff + index * phentsize;
        if u32::from_le_bytes(bytes[ph..ph + 4].try_into().unwrap()) != 2 {
            continue;
        }
        let mut offset = read_u64(bytes, ph + 8) as usize;
        let end = offset + read_u64(bytes, ph + 32) as usize;
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
    }
    panic!("fixture should contain dynamic tag {wanted_tag}")
}

#[test]
fn overflowing_gnu_hash_virtual_range_is_rejected_atomically() {
    if !tool_available("as") || !tool_available("ld") {
        return;
    }

    let dir = temp_dir();
    let assembly = dir.join("lib.s");
    let object = dir.join("lib.o");
    let script = dir.join("versions.map");
    let good = dir.join("good.so");
    let bad = dir.join("bad.so");
    fs::write(
        &assembly,
        ".text\n.globl foo\n.type foo,@function\nfoo:\n  ret\n.size foo,.-foo\n",
    )
    .unwrap();
    fs::write(&script, "VERS_1 { global: foo; local: *; };\n").unwrap();
    assert!(Command::new("as")
        .arg("-o")
        .arg(&object)
        .arg(&assembly)
        .status()
        .unwrap()
        .success());
    assert!(Command::new("ld")
        .arg("-shared")
        .arg("--hash-style=gnu")
        .arg("--version-script")
        .arg(&script)
        .arg("-o")
        .arg(&good)
        .arg(&object)
        .status()
        .unwrap()
        .success());

    let mut bytes = fs::read(&good).unwrap();
    let entry = dynamic_entry_offset(&bytes, 0x6fff_fef5) + 8;
    bytes[entry..entry + 8].copy_from_slice(&(u64::MAX - 7).to_le_bytes());
    fs::write(&bad, bytes).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-versym"))
        .arg(&good)
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty(), "stdout must remain atomic");
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("DT_GNU_HASH header virtual range overflows u64"));
    let _ = fs::remove_dir_all(dir);
}
