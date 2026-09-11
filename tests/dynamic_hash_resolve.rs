use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const DT_NULL: i64 = 0;
const DT_HASH: i64 = 4;
const DT_GNU_HASH: i64 = 0x6fff_fef5;

fn temp_dir() -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "mini-elf-dynamic-hash-resolve-{}-{stamp}",
        std::process::id()
    ));
    fs::create_dir_all(&path).unwrap();
    path
}

fn run(command: &mut Command) -> Output {
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "command failed: status={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn build_so(dir: &Path, stem: &str, hash_style: &str) -> PathBuf {
    let source = dir.join(format!("{stem}.s"));
    let object = dir.join(format!("{stem}.o"));
    let image = dir.join(format!("{stem}.so"));
    fs::write(
        &source,
        ".text\n.globl public_api\n.type public_api,@function\npublic_api:\n  ret\n.size public_api, .-public_api\n",
    )
    .unwrap();
    run(Command::new("as")
        .arg("--64")
        .arg("-o")
        .arg(&object)
        .arg(&source));
    run(Command::new("ld")
        .arg("-shared")
        .arg(format!("--hash-style={hash_style}"))
        .arg("-o")
        .arg(&image)
        .arg(&object));
    image
}

fn tool() -> &'static str {
    env!("CARGO_BIN_EXE_mini-elf-dynamic-hash-resolve")
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

fn phdrs(bytes: &[u8]) -> Vec<(u32, u64, u64, u64)> {
    let offset = read_u64(bytes, 32) as usize;
    let size = usize::from(read_u16(bytes, 54));
    let count = usize::from(read_u16(bytes, 56));
    (0..count)
        .map(|index| {
            let cursor = offset + index * size;
            (
                read_u32(bytes, cursor),
                read_u64(bytes, cursor + 8),
                read_u64(bytes, cursor + 16),
                read_u64(bytes, cursor + 32),
            )
        })
        .collect()
}

fn map_vaddr(bytes: &[u8], address: u64) -> usize {
    for (kind, offset, vaddr, filesz) in phdrs(bytes) {
        if kind == PT_LOAD && address >= vaddr && address < vaddr + filesz {
            return (offset + address - vaddr) as usize;
        }
    }
    panic!("address {address:#x} is not file backed");
}

fn dynamic_tag(bytes: &[u8], wanted: i64) -> Option<u64> {
    let (_, offset, _, filesz) = phdrs(bytes)
        .into_iter()
        .find(|header| header.0 == PT_DYNAMIC)
        .unwrap();
    let mut cursor = offset as usize;
    let end = (offset + filesz) as usize;
    while cursor + 16 <= end {
        let tag = read_i64(bytes, cursor);
        let value = read_u64(bytes, cursor + 8);
        if tag == wanted {
            return Some(value);
        }
        if tag == DT_NULL {
            break;
        }
        cursor += 16;
    }
    None
}

#[test]
fn resolves_first_eligible_definition_across_mixed_hash_styles() {
    let dir = temp_dir();
    let sysv = build_so(&dir, "sysv", "sysv");
    let gnu = build_so(&dir, "gnu", "gnu");

    let sysv_dynamic = run(Command::new("readelf").arg("-dW").arg(&sysv));
    let sysv_dynamic = String::from_utf8(sysv_dynamic.stdout).unwrap();
    assert!(sysv_dynamic.lines().any(|line| line.contains("(HASH)")));
    assert!(!sysv_dynamic.contains("GNU_HASH"));

    let gnu_dynamic = run(Command::new("readelf").arg("-dW").arg(&gnu));
    let gnu_dynamic = String::from_utf8(gnu_dynamic.stdout).unwrap();
    assert!(gnu_dynamic.contains("GNU_HASH"));
    assert!(!gnu_dynamic.lines().any(|line| line.contains("(HASH)")));

    for image in [&sysv, &gnu] {
        let symbols = run(Command::new("readelf")
            .arg("--dyn-syms")
            .arg("-W")
            .arg(image));
        assert!(String::from_utf8(symbols.stdout)
            .unwrap()
            .lines()
            .any(|line| line.ends_with(" public_api")));
    }

    let output = run(Command::new(tool()).arg("public_api").arg(&sysv).arg(&gnu));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains(&format!("file={}", sysv.to_string_lossy())));
    assert!(stdout.contains("hash=sysv"));
    assert!(!stdout.contains(&format!("file={}", gnu.to_string_lossy())));

    let output = run(Command::new(tool()).arg("public_api").arg(&gnu).arg(&sysv));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains(&format!("file={}", gnu.to_string_lossy())));
    assert!(stdout.contains("hash=gnu"));
    assert!(!stdout.contains(&format!("file={}", sysv.to_string_lossy())));

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn returns_not_found_across_mixed_hash_styles() {
    let dir = temp_dir();
    let gnu = build_so(&dir, "gnu", "gnu");
    let sysv = build_so(&dir, "sysv", "sysv");
    let output = run(Command::new(tool()).arg("missing_api").arg(&gnu).arg(&sysv));
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "Dynamic external resolve: symbol=missing_api not-found\n"
    );
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn malformed_present_gnu_hash_fails_closed_instead_of_falling_back_to_sysv() {
    let dir = temp_dir();
    let image = build_so(&dir, "both", "both");
    let mut bytes = fs::read(&image).unwrap();
    assert!(dynamic_tag(&bytes, DT_HASH).is_some());
    let gnu_hash = dynamic_tag(&bytes, DT_GNU_HASH).unwrap();
    let offset = map_vaddr(&bytes, gnu_hash);
    bytes[offset + 12..offset + 16].copy_from_slice(&64u32.to_le_bytes());
    fs::write(&image, bytes).unwrap();

    let output = Command::new(tool())
        .arg("public_api")
        .arg(&image)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("bloom shift 64"));

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn malformed_earlier_input_keeps_stdout_atomic() {
    let dir = temp_dir();
    let bad = build_so(&dir, "bad", "sysv");
    let good = build_so(&dir, "good", "gnu");
    let mut bytes = fs::read(&bad).unwrap();
    bytes[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
    fs::write(&bad, bytes).unwrap();

    let output = Command::new(tool())
        .arg("public_api")
        .arg(&bad)
        .arg(&good)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.is_empty());

    fs::remove_dir_all(dir).unwrap();
}
