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

fn assemble_sample(dir: &std::path::Path) -> std::path::PathBuf {
    let assembly = dir.join("sample.s");
    let object = dir.join("sample.o");
    fs::write(
        &assembly,
        ".text\n.globl caller\ncaller:\n  call target\n.data\n  .quad target\n",
    )
    .unwrap();
    let output = Command::new("as")
        .arg("-o")
        .arg(&object)
        .arg(&assembly)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    object
}

#[test]
fn relocation_core_facts_match_gnu_readelf() {
    if !tool_available("as") || !tool_available("readelf") {
        return;
    }
    let dir = temp_dir("relocs-gnu");
    let object = assemble_sample(&dir);
    let ours = Command::new(env!("CARGO_BIN_EXE_mini-elf-relocs"))
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        ours.status.success(),
        "{}",
        String::from_utf8_lossy(&ours.stderr)
    );
    let gnu = Command::new("readelf")
        .arg("-rW")
        .arg(&object)
        .output()
        .unwrap();
    assert!(gnu.status.success());
    let ours = String::from_utf8_lossy(&ours.stdout);
    let gnu = String::from_utf8_lossy(&gnu.stdout);
    for relocation in ["R_X86_64_PLT32", "R_X86_64_64"] {
        assert!(
            ours.contains(relocation),
            "ours missing {relocation}: {ours}"
        );
        assert!(gnu.contains(relocation), "GNU missing {relocation}: {gnu}");
    }
    assert!(ours.contains("target"));
    assert!(gnu.contains("target"));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn malformed_later_relocation_table_keeps_stdout_atomic() {
    if !tool_available("as") {
        return;
    }
    let dir = temp_dir("relocs-atomic");
    let good = assemble_sample(&dir);
    let bad = dir.join("bad.o");
    let mut bytes = fs::read(&good).unwrap();
    let shoff = read_u64(&bytes, 40) as usize;
    let shentsize = read_u16(&bytes, 58) as usize;
    let shnum = read_u16(&bytes, 60) as usize;
    let rela = (0..shnum)
        .find_map(|index| {
            let offset = shoff + index * shentsize;
            (read_u32(&bytes, offset + 4) == 4).then_some(offset)
        })
        .expect("assembler should emit SHT_RELA");
    bytes[rela + 56..rela + 64].copy_from_slice(&8u64.to_le_bytes());
    fs::write(&bad, bytes).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-relocs"))
        .arg(&good)
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty(), "stdout must remain atomic");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("entry size 8"), "{stderr}");
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn overflowing_relocation_section_range_is_rejected() {
    if !tool_available("as") {
        return;
    }
    let dir = temp_dir("relocs-overflow");
    let object = assemble_sample(&dir);
    let bad = dir.join("overflow.o");
    let mut bytes = fs::read(&object).unwrap();
    let shoff = read_u64(&bytes, 40) as usize;
    let shentsize = read_u16(&bytes, 58) as usize;
    let shnum = read_u16(&bytes, 60) as usize;
    let rela = (0..shnum)
        .find_map(|index| {
            let offset = shoff + index * shentsize;
            (read_u32(&bytes, offset + 4) == 4).then_some(offset)
        })
        .expect("assembler should emit SHT_RELA");
    bytes[rela + 24..rela + 32].copy_from_slice(&u64::MAX.to_le_bytes());
    bytes[rela + 32..rela + 40].copy_from_slice(&24u64.to_le_bytes());
    fs::write(&bad, bytes).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-relocs"))
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("file range overflows u64"));
    let _ = fs::remove_dir_all(dir);
}
