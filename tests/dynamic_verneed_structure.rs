use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const DT_NULL: i64 = 0;
const DT_VERNEED: i64 = 0x6fff_fffe;

fn temp_dir(label: &str) -> std::path::PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "mini-elf-verneed-structure-{label}-{}-{stamp}",
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

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn program_headers(bytes: &[u8]) -> Vec<(u32, u64, u64, u64)> {
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
            )
        })
        .collect()
}

fn dynamic_value(bytes: &[u8], wanted: i64) -> u64 {
    let dynamic = program_headers(bytes)
        .into_iter()
        .find(|(kind, _, _, _)| *kind == PT_DYNAMIC)
        .expect("fixture should contain PT_DYNAMIC");
    let mut offset = dynamic.1 as usize;
    let end = (dynamic.1 + dynamic.3) as usize;
    while offset + 16 <= end {
        let tag = read_i64(bytes, offset);
        if tag == wanted {
            return read_u64(bytes, offset + 8);
        }
        if tag == DT_NULL {
            break;
        }
        offset += 16;
    }
    panic!("missing dynamic tag {wanted}");
}

fn virtual_to_file(bytes: &[u8], address: u64, size: u64) -> usize {
    for (kind, offset, virtual_address, file_size) in program_headers(bytes) {
        if kind != PT_LOAD {
            continue;
        }
        let end = address + size;
        if address >= virtual_address && end <= virtual_address + file_size {
            return (offset + (address - virtual_address)) as usize;
        }
    }
    panic!("virtual range should be file-backed")
}

fn build_fixture(dir: &std::path::Path) -> std::path::PathBuf {
    let dep_s = dir.join("dep.s");
    let dep_o = dir.join("dep.o");
    let dep_so = dir.join("libdep.so");
    let map = dir.join("dep.map");
    fs::write(
        &dep_s,
        ".text\n.globl foo\n.type foo,@function\nfoo:\n  ret\n.size foo,.-foo\n",
    )
    .unwrap();
    fs::write(&map, "VERS_1 { global: foo; local: *; };\n").unwrap();
    assert!(
        Command::new("as")
            .args(["-o"])
            .arg(&dep_o)
            .arg(&dep_s)
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("ld")
            .arg("-shared")
            .arg("--hash-style=sysv")
            .arg("-soname")
            .arg("libdep.so")
            .arg("--version-script")
            .arg(&map)
            .arg("-o")
            .arg(&dep_so)
            .arg(&dep_o)
            .status()
            .unwrap()
            .success()
    );

    let consumer_s = dir.join("consumer.s");
    let consumer_o = dir.join("consumer.o");
    let consumer_so = dir.join("consumer.so");
    fs::write(
        &consumer_s,
        ".text\n.globl caller\n.type caller,@function\ncaller:\n  call foo@PLT\n  ret\n.size caller,.-caller\n",
    )
    .unwrap();
    assert!(
        Command::new("as")
            .args(["-o"])
            .arg(&consumer_o)
            .arg(&consumer_s)
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("ld")
            .arg("-shared")
            .arg("--hash-style=sysv")
            .arg("-o")
            .arg(&consumer_so)
            .arg(&consumer_o)
            .arg("-L")
            .arg(dir)
            .arg("-ldep")
            .status()
            .unwrap()
            .success()
    );
    consumer_so
}

#[test]
fn gnu_verneed_structure_is_accepted() {
    if !tool_available("as") || !tool_available("ld") || !tool_available("readelf") {
        return;
    }
    let dir = temp_dir("gnu");
    let shared = build_fixture(&dir);
    let gnu = Command::new("readelf")
        .arg("-VW")
        .arg(&shared)
        .output()
        .unwrap();
    assert!(gnu.status.success());
    assert!(String::from_utf8_lossy(&gnu.stdout).contains("VERS_1"));

    let ours = Command::new(env!("CARGO_BIN_EXE_mini-elf-verneed-structure"))
        .arg(&shared)
        .output()
        .unwrap();
    assert!(
        ours.status.success(),
        "{}",
        String::from_utf8_lossy(&ours.stderr)
    );
    assert!(String::from_utf8_lossy(&ours.stdout).contains("forward and non-overlapping"));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn overlapping_vn_aux_is_rejected_atomically() {
    if !tool_available("as") || !tool_available("ld") {
        return;
    }
    let dir = temp_dir("overlap");
    let good = build_fixture(&dir);
    let bad = dir.join("bad.so");
    let mut bytes = fs::read(&good).unwrap();
    let verneed = dynamic_value(&bytes, DT_VERNEED);
    let offset = virtual_to_file(&bytes, verneed, 16);
    write_u32(&mut bytes, offset + 8, 8);
    fs::write(&bad, bytes).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-verneed-structure"))
        .arg(&good)
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty(), "stdout must remain atomic");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("vn_aux 8 overlaps"), "{stderr}");
    let _ = fs::remove_dir_all(dir);
}
