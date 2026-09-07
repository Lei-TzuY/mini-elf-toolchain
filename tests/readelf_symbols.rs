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

fn symbol_facts(output: &str, name: &str) -> (u64, u64, String, String, String, String) {
    output
        .lines()
        .find_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            if fields.last().copied() != Some(name) || fields.len() < 8 {
                return None;
            }
            let number = fields[0].trim_end_matches(':');
            number.parse::<usize>().ok()?;
            Some((
                u64::from_str_radix(fields[1], 16).ok()?,
                fields[2].parse().ok()?,
                fields[3].to_owned(),
                fields[4].to_owned(),
                fields[5].to_owned(),
                fields[6].to_owned(),
            ))
        })
        .expect("expected named symbol")
}

fn assemble_sample(dir: &std::path::Path) -> std::path::PathBuf {
    let assembly = dir.join("sample.s");
    let object = dir.join("sample.o");
    fs::write(
        &assembly,
        ".text\n.globl sample\n.type sample,@function\nsample:\n  nop\n.size sample, .-sample\n.data\n.globl value\n.type value,@object\nvalue:\n  .quad 0x1234\n.size value, .-value\n.weak missing\n  .quad missing\n",
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
    object
}

#[test]
fn symbols_match_gnu_readelf_core_facts() {
    if !tool_available("as") || !tool_available("readelf") {
        return;
    }

    let dir = temp_dir("readelf-symbols");
    let object = assemble_sample(&dir);

    let ours = Command::new(env!("CARGO_BIN_EXE_mini-elf-readelf"))
        .arg("--symbols")
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        ours.status.success(),
        "{}",
        String::from_utf8_lossy(&ours.stderr)
    );
    let gnu = Command::new("readelf")
        .arg("-sW")
        .arg(&object)
        .output()
        .unwrap();
    assert!(gnu.status.success());

    let ours_stdout = String::from_utf8_lossy(&ours.stdout);
    let gnu_stdout = String::from_utf8_lossy(&gnu.stdout);
    for name in ["sample", "value", "missing"] {
        assert_eq!(
            symbol_facts(&ours_stdout, name),
            symbol_facts(&gnu_stdout, name),
            "symbol {name} differs"
        );
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn malformed_later_symbol_name_keeps_stdout_atomic() {
    if !tool_available("as") {
        return;
    }

    let dir = temp_dir("readelf-symbols-atomic");
    let good = assemble_sample(&dir);
    let bad = dir.join("bad.o");
    let mut bytes = fs::read(&good).unwrap();

    let section_header_offset = read_u64(&bytes, 40) as usize;
    let section_header_size = read_u16(&bytes, 58) as usize;
    let section_count = read_u16(&bytes, 60) as usize;
    let symtab = (0..section_count)
        .find_map(|index| {
            let offset = section_header_offset + index * section_header_size;
            (read_u32(&bytes, offset + 4) == 2).then_some(offset)
        })
        .expect("assembler should emit SHT_SYMTAB");
    let symbol_offset = read_u64(&bytes, symtab + 24) as usize;
    let symbol_size = read_u64(&bytes, symtab + 56) as usize;
    let symbol_count = read_u64(&bytes, symtab + 32) as usize / symbol_size;
    assert!(symbol_count > 1);
    bytes[symbol_offset + symbol_size..symbol_offset + symbol_size + 4]
        .copy_from_slice(&u32::MAX.to_le_bytes());
    fs::write(&bad, bytes).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-readelf"))
        .arg("-s")
        .arg(&good)
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty(), "stdout must remain atomic");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("name offset"), "{stderr}");
    assert!(stderr.contains("string-table size"), "{stderr}");

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn overflowing_symbol_table_section_range_is_rejected() {
    if !tool_available("as") {
        return;
    }

    let dir = temp_dir("readelf-symbols-overflow");
    let object = assemble_sample(&dir);
    let bad = dir.join("overflow.o");
    let mut bytes = fs::read(&object).unwrap();
    let section_header_offset = read_u64(&bytes, 40) as usize;
    let section_header_size = read_u16(&bytes, 58) as usize;
    let section_count = read_u16(&bytes, 60) as usize;
    let symtab = (0..section_count)
        .find_map(|index| {
            let offset = section_header_offset + index * section_header_size;
            (read_u32(&bytes, offset + 4) == 2).then_some(offset)
        })
        .expect("assembler should emit SHT_SYMTAB");
    bytes[symtab + 24..symtab + 32].copy_from_slice(&u64::MAX.to_le_bytes());
    bytes[symtab + 32..symtab + 40].copy_from_slice(&24u64.to_le_bytes());
    fs::write(&bad, bytes).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-readelf"))
        .arg("--symbols")
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("file range overflows u64"), "{stderr}");

    let _ = fs::remove_dir_all(dir);
}
