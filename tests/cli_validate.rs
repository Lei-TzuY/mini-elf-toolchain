use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn valid_elf64_header() -> Vec<u8> {
    let mut file = vec![0u8; 64];
    file[0..4].copy_from_slice(b"\x7fELF");
    file[4] = 2;
    file[5] = 1;
    file[6] = 1;
    file[16..18].copy_from_slice(&1u16.to_le_bytes());
    file[18..20].copy_from_slice(&62u16.to_le_bytes());
    file[20..24].copy_from_slice(&1u32.to_le_bytes());
    file[52..54].copy_from_slice(&64u16.to_le_bytes());
    file
}

fn fixture_path(name: &str) -> std::path::PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock must be after Unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "mini-elf-toolchain-{}-{unique}-{name}",
        std::process::id()
    ))
}

#[test]
fn validate_accepts_minimal_valid_elf64() {
    let path = fixture_path("valid.o");
    fs::write(&path, valid_elf64_header()).expect("write fixture");

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .arg("validate")
        .arg(&path)
        .output()
        .expect("run CLI");

    let _ = fs::remove_file(&path);
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).expect("stdout must be UTF-8"),
        "valid ELF64 x86-64: sections=0, symbol_tables=0, symbols=0\n"
    );
    assert!(output.stderr.is_empty());
}

#[test]
fn validate_reports_parser_diagnostics_for_malformed_input() {
    let path = fixture_path("bad.o");
    let mut file = valid_elf64_header();
    file[0] = 0;
    fs::write(&path, file).expect("write fixture");

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .arg("validate")
        .arg(&path)
        .output()
        .expect("run CLI");

    let _ = fs::remove_file(&path);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).expect("stderr must be UTF-8");
    assert!(stderr.contains("invalid ELF magic"), "stderr was: {stderr}");
}

#[test]
fn validate_rel_accepts_multiple_relocatable_inputs() {
    let first = fixture_path("first.o");
    let second = fixture_path("second.o");
    fs::write(&first, valid_elf64_header()).expect("write first fixture");
    fs::write(&second, valid_elf64_header()).expect("write second fixture");

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .arg("validate-rel")
        .arg(&first)
        .arg(&second)
        .output()
        .expect("run CLI");

    let _ = fs::remove_file(&first);
    let _ = fs::remove_file(&second);
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).expect("stdout must be UTF-8"),
        "valid relocatable ELF64 x86-64 inputs: objects=2, sections=0, symbol_tables=0, symbols=0, rela_tables=0, relocations=0\n"
    );
    assert!(output.stderr.is_empty());
}

#[test]
fn validate_rel_rejects_non_relocatable_elf() {
    let path = fixture_path("exec");
    let mut file = valid_elf64_header();
    file[16..18].copy_from_slice(&2u16.to_le_bytes());
    fs::write(&path, file).expect("write fixture");

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .arg("validate-rel")
        .arg(&path)
        .output()
        .expect("run CLI");

    let _ = fs::remove_file(&path);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).expect("stderr must be UTF-8");
    assert!(
        stderr.contains("expected relocatable object (ET_REL)"),
        "stderr was: {stderr}"
    );
}

#[test]
fn missing_input_is_a_usage_error() {
    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .arg("validate")
        .output()
        .expect("run CLI");

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).expect("stderr must be UTF-8"),
        "missing input path\nusage: mini-elf-toolchain validate <input>\n       mini-elf-toolchain validate-rel <input>...\n       mini-elf-toolchain link -o <output> [--map <map-file>] [--entry <symbol>] <input>...\n"
    );
}
