use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const DT_NULL: i64 = 0;
const DT_VERNEED: i64 = 0x6fff_fffe;
const DT_VERSYM: i64 = 0x6fff_fff0;

fn temp_dir(label: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "mini-elf-vercheck-{label}-{}-{stamp}",
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
    let use_map = dir.join("use.map");
    let use_so = dir.join("consumer.so");
    fs::write(
        &use_s,
        ".text\n.globl exported\n.type exported,@function\nexported:\n  call dep@PLT\n  ret\n.size exported, .-exported\n",
    )
    .unwrap();
    fs::write(&use_map, "VERS_LOCAL { global: exported; };\n").unwrap();
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
            .arg("--version-script")
            .arg(&use_map)
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
fn resolves_definition_and_requirement_names_against_gnu_readelf() {
    let dir = temp_dir("differential");
    let shared = build_fixture(&dir);

    let ours = Command::new(env!("CARGO_BIN_EXE_mini-elf-vercheck"))
        .arg(&shared)
        .output()
        .unwrap();
    assert!(
        ours.status.success(),
        "{}",
        String::from_utf8_lossy(&ours.stderr)
    );
    let ours = String::from_utf8(ours.stdout).unwrap();
    assert!(ours.contains("source=definition name=VERS_LOCAL"), "{ours}");
    assert!(
        ours.contains("source=requirement dependency=libdep.so name=VERS_DEP"),
        "{ours}"
    );

    let readelf = Command::new("readelf")
        .arg("-VW")
        .arg(&shared)
        .output()
        .unwrap();
    assert!(readelf.status.success());
    let readelf = String::from_utf8(readelf.stdout).unwrap();
    assert!(readelf.contains("VERS_LOCAL"), "{readelf}");
    assert!(readelf.contains("VERS_DEP"), "{readelf}");
    assert!(readelf.contains("libdep.so"), "{readelf}");
}

#[test]
fn rejects_unresolved_versym_index() {
    let dir = temp_dir("unresolved");
    let shared = build_fixture(&dir);
    let bad = dir.join("bad.so");
    let mut bytes = fs::read(&shared).unwrap();
    let versym = dynamic_tag_value(&bytes, DT_VERSYM).unwrap();
    let versym_offset = map_virtual(&bytes, versym).unwrap();

    let symbol_count = versym_entry_count_from_section(&bytes).unwrap();
    let mut patched = false;
    for index in 0..symbol_count {
        let offset = versym_offset + index * 2;
        let raw = read_u16(&bytes, offset);
        if raw & 0x7fff >= 2 {
            bytes[offset..offset + 2].copy_from_slice(&0x7ffeu16.to_le_bytes());
            patched = true;
            break;
        }
    }
    assert!(patched, "fixture has no versioned DT_VERSYM entry");
    fs::write(&bad, bytes).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-vercheck"))
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unresolved version index 32766"));
    assert!(output.stdout.is_empty());
}

#[test]
fn rejects_verneed_virtual_range_overflow_atomically() {
    let dir = temp_dir("overflow");
    let good = build_fixture(&dir);
    let bad = dir.join("overflow.so");
    let mut bytes = fs::read(&good).unwrap();
    patch_dynamic_tag_value(&mut bytes, DT_VERNEED, u64::MAX - 7).unwrap();
    fs::write(&bad, bytes).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-vercheck"))
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

fn patch_dynamic_tag_value(bytes: &mut [u8], tag: i64, value: u64) -> Result<(), String> {
    let dynamic = dynamic_segment(bytes)?;
    for offset in (dynamic.0..dynamic.0 + dynamic.1).step_by(16) {
        let current = read_i64(bytes, offset);
        if current == tag {
            bytes[offset + 8..offset + 16].copy_from_slice(&value.to_le_bytes());
            return Ok(());
        }
        if current == DT_NULL {
            break;
        }
    }
    Err(format!("dynamic tag {tag:#x} not found"))
}

fn dynamic_tag_value(bytes: &[u8], tag: i64) -> Result<u64, String> {
    let dynamic = dynamic_segment(bytes)?;
    for offset in (dynamic.0..dynamic.0 + dynamic.1).step_by(16) {
        let current = read_i64(bytes, offset);
        if current == tag {
            return Ok(read_u64(bytes, offset + 8));
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

fn map_virtual(bytes: &[u8], address: u64) -> Result<usize, String> {
    let phoff = read_u64(bytes, 32) as usize;
    let phentsize = read_u16(bytes, 54) as usize;
    let phnum = read_u16(bytes, 56) as usize;
    for index in 0..phnum {
        let offset = phoff + index * phentsize;
        if read_u32(bytes, offset) != PT_LOAD {
            continue;
        }
        let file_offset = read_u64(bytes, offset + 8);
        let virtual_address = read_u64(bytes, offset + 16);
        let file_size = read_u64(bytes, offset + 32);
        if address >= virtual_address && address < virtual_address + file_size {
            return Ok((file_offset + address - virtual_address) as usize);
        }
    }
    Err(format!("virtual address {address:#x} is not file-backed"))
}

fn versym_entry_count_from_section(bytes: &[u8]) -> Result<usize, String> {
    let shoff = read_u64(bytes, 40) as usize;
    let shentsize = read_u16(bytes, 58) as usize;
    let shnum = read_u16(bytes, 60) as usize;
    for index in 0..shnum {
        let offset = shoff + index * shentsize;
        if read_u32(bytes, offset + 4) == 0x6fff_ffff {
            let size = read_u64(bytes, offset + 32) as usize;
            let entsize = read_u64(bytes, offset + 56) as usize;
            if entsize == 2 {
                return Ok(size / entsize);
            }
        }
    }
    Err("SHT_GNU_versym section not found".to_owned())
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
