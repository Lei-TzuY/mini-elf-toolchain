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

fn parse_hex(value: &str) -> u64 {
    u64::from_str_radix(value.trim_start_matches("0x"), 16).unwrap()
}

fn named_section_facts(output: &str, name: &str) -> (String, u64, u64, u64) {
    output
        .lines()
        .find_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            let name_index = fields.iter().position(|field| *field == name)?;
            (fields.len() > name_index + 4).then(|| {
                (
                    fields[name_index + 1].to_owned(),
                    parse_hex(fields[name_index + 2]),
                    parse_hex(fields[name_index + 3]),
                    parse_hex(fields[name_index + 4]),
                )
            })
        })
        .expect("expected named section")
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn synthetic_elf_with_shstrtab() -> Vec<u8> {
    let names = b"\0.shstrtab\0";
    let mut bytes = vec![0u8; 192 + names.len()];
    bytes[0..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    put_u16(&mut bytes, 16, 1);
    put_u16(&mut bytes, 18, 62);
    put_u32(&mut bytes, 20, 1);
    put_u64(&mut bytes, 40, 64);
    put_u16(&mut bytes, 52, 64);
    put_u16(&mut bytes, 58, 64);
    put_u16(&mut bytes, 60, 2);
    put_u16(&mut bytes, 62, 1);

    put_u32(&mut bytes, 128, 1);
    put_u32(&mut bytes, 132, 3);
    put_u64(&mut bytes, 152, 192);
    put_u64(&mut bytes, 160, names.len() as u64);
    put_u64(&mut bytes, 176, 1);
    bytes[192..].copy_from_slice(names);
    bytes
}

#[test]
fn section_headers_match_gnu_readelf_text_facts() {
    if !tool_available("as") || !tool_available("readelf") {
        return;
    }

    let dir = temp_dir("readelf-section-headers");
    let assembly = dir.join("sample.s");
    let object = dir.join("sample.o");
    fs::write(
        &assembly,
        ".text\n.globl sample\nsample:\n  nop\n.data\n.globl value\nvalue:\n  .quad 0x1234\n",
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

    let ours = Command::new(env!("CARGO_BIN_EXE_mini-elf-readelf"))
        .arg("--section-headers")
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        ours.status.success(),
        "{}",
        String::from_utf8_lossy(&ours.stderr)
    );
    let gnu = Command::new("readelf")
        .arg("-SW")
        .arg(&object)
        .output()
        .unwrap();
    assert!(gnu.status.success());

    let ours_stdout = String::from_utf8_lossy(&ours.stdout);
    let gnu_stdout = String::from_utf8_lossy(&gnu.stdout);
    assert_eq!(
        named_section_facts(&ours_stdout, ".text"),
        named_section_facts(&gnu_stdout, ".text")
    );
    assert_eq!(
        named_section_facts(&ours_stdout, ".data"),
        named_section_facts(&gnu_stdout, ".data")
    );

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn malformed_later_section_name_keeps_stdout_atomic() {
    let dir = temp_dir("readelf-section-headers-atomic");
    let good = dir.join("good.o");
    let bad = dir.join("bad.o");
    fs::write(&good, synthetic_elf_with_shstrtab()).unwrap();

    let mut malformed = synthetic_elf_with_shstrtab();
    put_u32(&mut malformed, 64, u32::MAX);
    fs::write(&bad, malformed).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-readelf"))
        .arg("-S")
        .arg(&good)
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty(), "stdout must remain atomic");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("name offset"), "{stderr}");
    assert!(stderr.contains("section-name string-table size"), "{stderr}");

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn overflowing_section_data_range_is_rejected() {
    let dir = temp_dir("readelf-section-headers-overflow");
    let bad = dir.join("overflow.o");
    let mut bytes = synthetic_elf_with_shstrtab();
    put_u32(&mut bytes, 68, 1);
    put_u64(&mut bytes, 88, u64::MAX);
    put_u64(&mut bytes, 96, 2);
    fs::write(&bad, bytes).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-readelf"))
        .arg("--section-headers")
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("file range overflows u64"), "{stderr}");

    let _ = fs::remove_dir_all(dir);
}
