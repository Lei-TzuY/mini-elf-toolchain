use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const PT_DYNAMIC: u32 = 2;
const DT_NULL: i64 = 0;
const DT_NEEDED: i64 = 1;
const DT_VERNEED: i64 = 0x6fff_fffe;
const REMOVED_NEEDED_TAG: i64 = 0x6000_000d;

fn temp_dir(label: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "mini-elf-needed-check-{label}-{}-{stamp}",
        std::process::id()
    ));
    fs::create_dir_all(&path).unwrap();
    path
}

fn command_ok(command: &mut Command) {
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "command failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn build_fixture(dir: &Path) -> PathBuf {
    let dep_s = dir.join("dep.s");
    let dep_o = dir.join("dep.o");
    let dep_map = dir.join("dep.map");
    let dep_so = dir.join("libdep.so");
    fs::write(
        &dep_s,
        ".text\n.globl dep\n.type dep,@function\ndep:\n  ret\n.size dep, .-dep\n",
    )
    .unwrap();
    fs::write(&dep_map, "VERS_DEP { global: dep; };\n").unwrap();
    command_ok(
        Command::new("as")
            .arg("--64")
            .arg("-o")
            .arg(&dep_o)
            .arg(&dep_s),
    );
    command_ok(
        Command::new("ld")
            .arg("-shared")
            .arg("--hash-style=gnu")
            .arg("--version-script")
            .arg(&dep_map)
            .arg("-soname")
            .arg("libdep.so")
            .arg("-o")
            .arg(&dep_so)
            .arg(&dep_o),
    );

    let use_s = dir.join("use.s");
    let use_o = dir.join("use.o");
    let use_so = dir.join("consumer.so");
    fs::write(
        &use_s,
        ".text\n.globl exported\n.type exported,@function\nexported:\n  call dep@PLT\n  ret\n.size exported, .-exported\n",
    )
    .unwrap();
    command_ok(
        Command::new("as")
            .arg("--64")
            .arg("-o")
            .arg(&use_o)
            .arg(&use_s),
    );
    command_ok(
        Command::new("ld")
            .arg("-shared")
            .arg("--hash-style=gnu")
            .arg("-o")
            .arg(&use_so)
            .arg(&use_o)
            .arg("-L")
            .arg(dir)
            .arg("-ldep"),
    );
    use_so
}

#[test]
fn accepts_gnu_version_requirement_backed_by_needed_library() {
    let dir = temp_dir("differential");
    let shared = build_fixture(&dir);
    let ours = Command::new(env!("CARGO_BIN_EXE_mini-elf-needed-check"))
        .arg(&shared)
        .output()
        .unwrap();
    assert!(
        ours.status.success(),
        "{}",
        String::from_utf8_lossy(&ours.stderr)
    );
    let ours = String::from_utf8(ours.stdout).unwrap();
    assert!(ours.contains("dependency=libdep.so"), "{ours}");

    let dynamic = Command::new("readelf")
        .arg("-dW")
        .arg(&shared)
        .output()
        .unwrap();
    assert!(dynamic.status.success());
    assert!(
        String::from_utf8_lossy(&dynamic.stdout).contains("Shared library: [libdep.so]")
    );

    let versions = Command::new("readelf")
        .arg("-VW")
        .arg(&shared)
        .output()
        .unwrap();
    assert!(versions.status.success());
    let versions = String::from_utf8_lossy(&versions.stdout);
    assert!(versions.contains("File: libdep.so"), "{versions}");
    assert!(versions.contains("Name: VERS_DEP"), "{versions}");
}

#[test]
fn rejects_verneed_dependency_without_needed_declaration() {
    let dir = temp_dir("missing-needed");
    let good = build_fixture(&dir);
    let bad = dir.join("missing-needed.so");
    let mut bytes = fs::read(&good).unwrap();
    patch_dynamic_tag(&mut bytes, DT_NEEDED, REMOVED_NEEDED_TAG).unwrap();
    fs::write(&bad, bytes).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-needed-check"))
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("DT_VERNEED dependency 'libdep.so' is not declared by DT_NEEDED"),
        "{stderr}"
    );
    assert!(output.stdout.is_empty());
}

#[test]
fn rejects_verneed_virtual_range_overflow_atomically() {
    let dir = temp_dir("overflow");
    let good = build_fixture(&dir);
    let bad = dir.join("overflow.so");
    let mut bytes = fs::read(&good).unwrap();
    patch_dynamic_value(&mut bytes, DT_VERNEED, u64::MAX - 7).unwrap();
    fs::write(&bad, bytes).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-needed-check"))
        .arg(&good)
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("DT_VERNEED entry virtual range overflows u64"),
        "{stderr}"
    );
    assert!(output.stdout.is_empty());
}

fn patch_dynamic_tag(bytes: &mut [u8], old_tag: i64, new_tag: i64) -> Result<(), String> {
    let (offset, size) = dynamic_segment(bytes)?;
    for entry in (offset..offset + size).step_by(16) {
        let tag = read_i64(bytes, entry);
        if tag == old_tag {
            bytes[entry..entry + 8].copy_from_slice(&new_tag.to_le_bytes());
            return Ok(());
        }
        if tag == DT_NULL {
            break;
        }
    }
    Err(format!("dynamic tag {old_tag:#x} not found"))
}

fn patch_dynamic_value(bytes: &mut [u8], tag: i64, value: u64) -> Result<(), String> {
    let (offset, size) = dynamic_segment(bytes)?;
    for entry in (offset..offset + size).step_by(16) {
        let current = read_i64(bytes, entry);
        if current == tag {
            bytes[entry + 8..entry + 16].copy_from_slice(&value.to_le_bytes());
            return Ok(());
        }
        if current == DT_NULL {
            break;
        }
    }
    Err(format!("dynamic tag {tag:#x} not found"))
}

fn dynamic_segment(bytes: &[u8]) -> Result<(usize, usize), String> {
    let phoff = read_u64(bytes, 32) as usize;
    let phentsize = read_u16(bytes, 54) as usize;
    let phnum = read_u16(bytes, 56) as usize;
    for index in 0..phnum {
        let offset = phoff + index * phentsize;
        if read_u32(bytes, offset) == PT_DYNAMIC {
            return Ok((
                read_u64(bytes, offset + 8) as usize,
                read_u64(bytes, offset + 32) as usize,
            ));
        }
    }
    Err("PT_DYNAMIC not found".to_owned())
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
