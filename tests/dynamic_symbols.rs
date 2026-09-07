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

fn build_shared(dir: &std::path::Path) -> std::path::PathBuf {
    let assembly = dir.join("sample.s");
    let object = dir.join("sample.o");
    let shared = dir.join("libsample.so");
    fs::write(
        &assembly,
        ".text\n.globl exported\n.type exported,@function\nexported:\n  ret\n.size exported, .-exported\n.data\n.globl exported_data\n.type exported_data,@object\n.size exported_data,8\nexported_data:\n  .quad 7\n",
    )
    .unwrap();
    assert!(Command::new("as")
        .arg("-o")
        .arg(&object)
        .arg(&assembly)
        .status()
        .unwrap()
        .success());
    assert!(Command::new("ld")
        .arg("-shared")
        .arg("--hash-style=sysv")
        .arg("-soname")
        .arg("libsample.so")
        .arg("-o")
        .arg(&shared)
        .arg(&object)
        .status()
        .unwrap()
        .success());
    shared
}

fn dynamic_value_offset(bytes: &[u8], wanted: i64) -> usize {
    let phoff = read_u64(bytes, 32) as usize;
    let phentsize = read_u16(bytes, 54) as usize;
    let phnum = read_u16(bytes, 56) as usize;
    for index in 0..phnum {
        let ph = phoff + index * phentsize;
        if read_u32(bytes, ph) != 2 {
            continue;
        }
        let mut offset = read_u64(bytes, ph + 8) as usize;
        let end = offset + read_u64(bytes, ph + 32) as usize;
        while offset + 16 <= end {
            let tag = read_i64(bytes, offset);
            if tag == wanted {
                return offset + 8;
            }
            if tag == 0 {
                break;
            }
            offset += 16;
        }
    }
    panic!("missing dynamic tag {wanted}")
}

#[test]
fn dynamic_symbols_match_gnu_readelf_facts() {
    if !tool_available("as") || !tool_available("ld") || !tool_available("readelf") {
        return;
    }
    let dir = temp_dir("dynsym-gnu");
    let shared = build_shared(&dir);
    let gnu = Command::new("readelf")
        .arg("--dyn-syms")
        .arg("-W")
        .arg(&shared)
        .output()
        .unwrap();
    assert!(gnu.status.success());
    let ours = Command::new(env!("CARGO_BIN_EXE_mini-elf-dynsym"))
        .arg(&shared)
        .output()
        .unwrap();
    assert!(
        ours.status.success(),
        "{}",
        String::from_utf8_lossy(&ours.stderr)
    );
    let gnu_text = String::from_utf8_lossy(&gnu.stdout);
    let ours_text = String::from_utf8_lossy(&ours.stdout);
    assert!(gnu_text.contains("exported"), "{gnu_text}");
    assert!(gnu_text.contains("exported_data"), "{gnu_text}");
    assert!(ours_text.contains("FUNC"), "{ours_text}");
    assert!(ours_text.contains("OBJECT"), "{ours_text}");
    assert!(ours_text.contains("exported"), "{ours_text}");
    assert!(ours_text.contains("exported_data"), "{ours_text}");
    assert!(ours_text.contains("    8 OBJECT"), "{ours_text}");
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn malformed_syment_in_later_input_keeps_stdout_atomic() {
    if !tool_available("as") || !tool_available("ld") {
        return;
    }
    let dir = temp_dir("dynsym-atomic");
    let good = build_shared(&dir);
    let bad = dir.join("bad.so");
    let mut bytes = fs::read(&good).unwrap();
    let syment = dynamic_value_offset(&bytes, 11);
    bytes[syment..syment + 8].copy_from_slice(&16u64.to_le_bytes());
    fs::write(&bad, bytes).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-dynsym"))
        .arg(&good)
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty(), "stdout must remain atomic");
    assert!(String::from_utf8_lossy(&output.stderr).contains("DT_SYMENT is 16"));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn overflowing_dt_symtab_virtual_range_is_rejected() {
    if !tool_available("as") || !tool_available("ld") {
        return;
    }
    let dir = temp_dir("dynsym-overflow");
    let shared = build_shared(&dir);
    let bad = dir.join("overflow.so");
    let mut bytes = fs::read(&shared).unwrap();
    let symtab = dynamic_value_offset(&bytes, 6);
    bytes[symtab..symtab + 8].copy_from_slice(&(u64::MAX - 7).to_le_bytes());
    fs::write(&bad, bytes).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-dynsym"))
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("virtual range overflows u64"));
    let _ = fs::remove_dir_all(dir);
}
