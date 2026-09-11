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
        ".text\n.globl exported\n.type exported,@function\nexported:\n  ret\n.size exported, .-exported\n",
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
        .arg("--hash-style=gnu")
        .arg("-soname")
        .arg("libsample.so")
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

fn dynamic_tag_value_offset(bytes: &[u8], wanted: i64) -> usize {
    let headers = program_headers(bytes);
    let dynamic = headers
        .iter()
        .find(|(segment_type, _, _, _)| *segment_type == 2)
        .expect("shared object should contain PT_DYNAMIC");
    let mut offset = dynamic.1 as usize;
    let end = (dynamic.1 + dynamic.3) as usize;
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
    panic!("shared object should contain requested dynamic tag")
}

fn virtual_to_file(bytes: &[u8], address: u64, size: u64) -> usize {
    for (segment_type, file_offset, virtual_address, file_size) in program_headers(bytes) {
        if segment_type != 1 {
            continue;
        }
        let end = virtual_address + file_size;
        if address >= virtual_address && address + size <= end {
            return (file_offset + address - virtual_address) as usize;
        }
    }
    panic!("virtual address should be PT_LOAD file-backed")
}

fn dynsym_count(output: &str) -> usize {
    for line in output.lines() {
        if let Some(rest) = line.split(" contains ").nth(1) {
            if let Some(count) = rest.split_whitespace().next() {
                if let Ok(count) = count.parse() {
                    return count;
                }
            }
        }
    }
    panic!("could not parse GNU dynsym count: {output}")
}

#[test]
fn gnu_hash_only_symbol_count_matches_readelf() {
    if !tool_available("as") || !tool_available("ld") || !tool_available("readelf") {
        return;
    }
    let dir = temp_dir("gnu-hash-differential");
    let shared = build_shared(&dir);

    let dynamic = Command::new("readelf")
        .arg("-dW")
        .arg(&shared)
        .output()
        .unwrap();
    assert!(dynamic.status.success());
    let dynamic_text = String::from_utf8_lossy(&dynamic.stdout);
    assert!(dynamic_text.contains("(GNU_HASH)"), "{dynamic_text}");
    assert!(!dynamic_text.contains("(HASH)"), "{dynamic_text}");

    let symbols = Command::new("readelf")
        .arg("--dyn-syms")
        .arg("-W")
        .arg(&shared)
        .output()
        .unwrap();
    assert!(symbols.status.success());
    let symbols_text = String::from_utf8_lossy(&symbols.stdout);
    let expected = dynsym_count(&symbols_text);

    let ours = Command::new(env!("CARGO_BIN_EXE_mini-elf-gnu-hash"))
        .arg(&shared)
        .output()
        .unwrap();
    assert!(
        ours.status.success(),
        "{}",
        String::from_utf8_lossy(&ours.stderr)
    );
    let ours_text = String::from_utf8_lossy(&ours.stdout);
    assert!(ours_text.contains("GNU DT_GNU_HASH"), "{ours_text}");
    assert!(
        ours_text.contains(&format!("dynamic symbols: {expected}")),
        "ours={ours_text}\nreadelf={symbols_text}"
    );
    assert!(ours_text.contains("Buckets:"), "{ours_text}");
    assert!(ours_text.contains("Chain words inspected:"), "{ours_text}");
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn malformed_zero_bloom_count_is_rejected_atomically() {
    if !tool_available("as") || !tool_available("ld") {
        return;
    }
    let dir = temp_dir("gnu-hash-malformed");
    let good = build_shared(&dir);
    let bad = dir.join("bad.so");
    let mut bytes = fs::read(&good).unwrap();
    let value_offset = dynamic_tag_value_offset(&bytes, 0x6fff_fef5);
    let hash_address = read_u64(&bytes, value_offset);
    let hash_offset = virtual_to_file(&bytes, hash_address, 16);
    bytes[hash_offset + 8..hash_offset + 12].copy_from_slice(&0u32.to_le_bytes());
    fs::write(&bad, bytes).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-gnu-hash"))
        .arg(&good)
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty(), "stdout must remain atomic");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("bloom count 0"), "{stderr}");
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn overflowing_gnu_hash_virtual_range_is_rejected() {
    if !tool_available("as") || !tool_available("ld") {
        return;
    }
    let dir = temp_dir("gnu-hash-overflow");
    let shared = build_shared(&dir);
    let bad = dir.join("overflow.so");
    let mut bytes = fs::read(&shared).unwrap();
    let value_offset = dynamic_tag_value_offset(&bytes, 0x6fff_fef5);
    bytes[value_offset..value_offset + 8].copy_from_slice(&(u64::MAX - 7).to_le_bytes());
    fs::write(&bad, bytes).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-gnu-hash"))
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("virtual range overflows u64"));
    let _ = fs::remove_dir_all(dir);
}
