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

fn program_headers(bytes: &[u8]) -> Vec<(usize, u32, u64, u64, u64, u64)> {
    let phoff = read_u64(bytes, 32) as usize;
    let phentsize = read_u16(bytes, 54) as usize;
    let phnum = read_u16(bytes, 56) as usize;
    (0..phnum)
        .map(|index| {
            let offset = phoff + index * phentsize;
            (
                offset,
                read_u32(bytes, offset),
                read_u64(bytes, offset + 8),
                read_u64(bytes, offset + 16),
                read_u64(bytes, offset + 32),
                read_u64(bytes, offset + 40),
            )
        })
        .collect()
}

fn dynamic_entries(bytes: &[u8]) -> Vec<usize> {
    let dynamic = program_headers(bytes)
        .into_iter()
        .find(|(_, segment_type, _, _, _, _)| *segment_type == 2)
        .expect("shared object should contain PT_DYNAMIC");
    let mut offsets = Vec::new();
    let mut offset = dynamic.2 as usize;
    let end = (dynamic.2 + dynamic.4) as usize;
    while offset + 16 <= end {
        offsets.push(offset);
        if read_i64(bytes, offset) == 0 {
            break;
        }
        offset += 16;
    }
    offsets
}

fn dynamic_value_offset(bytes: &[u8], wanted_tag: i64) -> usize {
    dynamic_entries(bytes)
        .into_iter()
        .find(|offset| read_i64(bytes, *offset) == wanted_tag)
        .map(|offset| offset + 8)
        .unwrap_or_else(|| panic!("shared object should contain dynamic tag {wanted_tag}"))
}

fn virtual_to_file(bytes: &[u8], address: u64, size: u64) -> usize {
    program_headers(bytes)
        .into_iter()
        .filter(|(_, segment_type, _, _, _, _)| *segment_type == 1)
        .find_map(|(_, _, offset, virtual_address, file_size, _)| {
            let end = virtual_address.checked_add(file_size)?;
            let wanted_end = address.checked_add(size)?;
            if address >= virtual_address && wanted_end <= end {
                Some((offset + (address - virtual_address)) as usize)
            } else {
                None
            }
        })
        .expect("virtual range should be file-backed")
}

fn build_relr_shared(dir: &std::path::Path) -> std::path::PathBuf {
    let assembly = dir.join("sample.s");
    let object = dir.join("sample.o");
    let shared = dir.join("libsample.so");
    fs::write(
        &assembly,
        ".data\n.local target\ntarget:\n  .quad 0\n.globl ptr0\n.type ptr0,@object\n.size ptr0,8\nptr0:\n  .quad target\n.globl ptr1\n.type ptr1,@object\n.size ptr1,8\nptr1:\n  .quad target\n.globl ptr2\n.type ptr2,@object\n.size ptr2,8\nptr2:\n  .quad target\n",
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

    let mut bytes = fs::read(&shared).unwrap();
    let rela_address = read_u64(&bytes, dynamic_value_offset(&bytes, 7));
    let rela_size = read_u64(&bytes, dynamic_value_offset(&bytes, 8));
    assert!(rela_size >= 72, "expected at least three ELF64 Rela entries");
    let table_offset = virtual_to_file(&bytes, rela_address, 72);

    let relocations = [
        (read_u64(&bytes, table_offset), read_u64(&bytes, table_offset + 16)),
        (
            read_u64(&bytes, table_offset + 24),
            read_u64(&bytes, table_offset + 40),
        ),
        (
            read_u64(&bytes, table_offset + 48),
            read_u64(&bytes, table_offset + 64),
        ),
    ];
    assert_eq!(relocations[1].0, relocations[0].0 + 8);
    assert_eq!(relocations[2].0, relocations[0].0 + 16);

    let target_offsets = relocations.map(|(address, _)| virtual_to_file(&bytes, address, 8));
    for ((_, addend), target_offset) in relocations.into_iter().zip(target_offsets) {
        bytes[target_offset..target_offset + 8].copy_from_slice(&addend.to_le_bytes());
    }

    for offset in dynamic_entries(&bytes) {
        match read_i64(&bytes, offset) {
            7 => bytes[offset..offset + 8].copy_from_slice(&36_i64.to_le_bytes()),
            8 => {
                bytes[offset..offset + 8].copy_from_slice(&35_i64.to_le_bytes());
                bytes[offset + 8..offset + 16].copy_from_slice(&16_u64.to_le_bytes());
            }
            9 => {
                bytes[offset..offset + 8].copy_from_slice(&37_i64.to_le_bytes());
                bytes[offset + 8..offset + 16].copy_from_slice(&8_u64.to_le_bytes());
            }
            _ => {}
        }
    }
    bytes[table_offset..table_offset + 8].copy_from_slice(&relocations[0].0.to_le_bytes());
    bytes[table_offset + 8..table_offset + 16].copy_from_slice(&7_u64.to_le_bytes());
    fs::write(&shared, bytes).unwrap();
    shared
}

#[test]
fn load_bias_simulates_relative_values_and_preserves_gnu_offsets() {
    if !tool_available("as") || !tool_available("ld") || !tool_available("readelf") {
        return;
    }
    let dir = temp_dir("dynrelr-load-bias");
    let shared = build_relr_shared(&dir);
    let bytes = fs::read(&shared).unwrap();
    let relr_address = read_u64(&bytes, dynamic_value_offset(&bytes, 36));
    let table_offset = virtual_to_file(&bytes, relr_address, 16);
    let first_address = read_u64(&bytes, table_offset);
    let first_target = virtual_to_file(&bytes, first_address, 8);
    let first_addend = read_u64(&bytes, first_target);
    let load_bias = 0x10_0000_u64;
    let first_value = load_bias.checked_add(first_addend).unwrap();

    let ours = Command::new(env!("CARGO_BIN_EXE_mini-elf-dynrelr"))
        .arg("--load-bias")
        .arg(format!("{load_bias:#x}"))
        .arg(&shared)
        .output()
        .unwrap();
    assert!(
        ours.status.success(),
        "{}",
        String::from_utf8_lossy(&ours.stderr)
    );
    let ours_text = String::from_utf8_lossy(&ours.stdout);
    assert!(ours_text.contains(&format!("Load bias: {load_bias:#018x}")), "{ours_text}");
    assert!(
        ours_text.contains(&format!(
            "{first_address:#018x} {first_addend:#018x} {first_value:#018x}"
        )),
        "{ours_text}"
    );

    let gnu = Command::new("readelf")
        .arg("--use-dynamic")
        .arg("-rW")
        .arg(&shared)
        .output()
        .unwrap();
    assert!(gnu.status.success());
    let gnu_text = String::from_utf8_lossy(&gnu.stdout);
    assert!(
        gnu_text.contains(&format!("{first_address:016x}")),
        "GNU readelf missing first RELR offset\n{gnu_text}"
    );
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn load_bias_value_overflow_is_rejected_atomically() {
    if !tool_available("as") || !tool_available("ld") {
        return;
    }
    let dir = temp_dir("dynrelr-load-bias-overflow");
    let shared = build_relr_shared(&dir);
    let bad = dir.join("overflow.so");
    let mut bytes = fs::read(&shared).unwrap();
    let relr_address = read_u64(&bytes, dynamic_value_offset(&bytes, 36));
    let table_offset = virtual_to_file(&bytes, relr_address, 8);
    let first_address = read_u64(&bytes, table_offset);
    let first_target = virtual_to_file(&bytes, first_address, 8);
    bytes[first_target..first_target + 8].copy_from_slice(&u64::MAX.to_le_bytes());
    fs::write(&bad, bytes).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-dynrelr"))
        .arg("--load-bias=1")
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty(), "stdout must remain atomic");
    assert!(String::from_utf8_lossy(&output.stderr).contains("value overflows u64"));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn load_bias_requires_file_backed_implicit_addend() {
    if !tool_available("as") || !tool_available("ld") {
        return;
    }
    let dir = temp_dir("dynrelr-load-bias-file-backed");
    let shared = build_relr_shared(&dir);
    let bad = dir.join("memory-only.so");
    let mut bytes = fs::read(&shared).unwrap();
    let relr_address = read_u64(&bytes, dynamic_value_offset(&bytes, 36));
    let table_offset = virtual_to_file(&bytes, relr_address, 8);
    let first_address = read_u64(&bytes, table_offset);

    let (ph_offset, _, _, virtual_address, file_size, memory_size) = program_headers(&bytes)
        .into_iter()
        .find(|(_, segment_type, _, virtual_address, _, memory_size)| {
            *segment_type == 1
                && first_address >= *virtual_address
                && first_address + 8 <= *virtual_address + *memory_size
        })
        .expect("first relocation target should be in PT_LOAD");
    let new_file_size = first_address - virtual_address;
    assert!(new_file_size < file_size);
    assert!(new_file_size <= memory_size);
    bytes[ph_offset + 32..ph_offset + 40].copy_from_slice(&new_file_size.to_le_bytes());
    fs::write(&bad, bytes).unwrap();

    let default_output = Command::new(env!("CARGO_BIN_EXE_mini-elf-dynrelr"))
        .arg(&bad)
        .output()
        .unwrap();
    assert!(
        default_output.status.success(),
        "{}",
        String::from_utf8_lossy(&default_output.stderr)
    );

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-dynrelr"))
        .arg("--load-bias=0x1000")
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("not backed by a PT_LOAD file range"));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn invalid_load_bias_is_rejected_before_input_io() {
    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-dynrelr"))
        .arg("--load-bias=0xnothex")
        .arg("definitely-missing.so")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("invalid --load-bias address"), "{stderr}");
    assert!(!stderr.contains("cannot read"), "{stderr}");
}
