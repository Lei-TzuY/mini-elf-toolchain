use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_path(suffix: &str) -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock must be after Unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "mini-elf-toolchain-cli-{}-{nonce}.{suffix}",
        std::process::id()
    ))
}

fn minimal_elf64(file_type: u16) -> Vec<u8> {
    let mut bytes = vec![0u8; 64];
    bytes[0..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    bytes[16..18].copy_from_slice(&file_type.to_le_bytes());
    bytes[18..20].copy_from_slice(&62u16.to_le_bytes());
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
    bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
    bytes[58..60].copy_from_slice(&64u16.to_le_bytes());
    bytes
}

#[test]
fn validate_accepts_minimal_valid_elf64() {
    let path = temp_path("elf");
    fs::write(&path, minimal_elf64(1)).expect("write temp ELF");

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["validate", path.to_str().expect("UTF-8 temp path")])
        .output()
        .expect("run CLI");

    let _ = fs::remove_file(&path);
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert_eq!(
        String::from_utf8(output.stdout).expect("stdout must be UTF-8"),
        "valid ELF64 x86-64: sections=0, symbol_tables=0, symbols=0\n"
    );
}

#[test]
fn validate_reports_parser_diagnostics_for_malformed_input() {
    let path = temp_path("elf");
    fs::write(&path, b"not an elf").expect("write temp invalid ELF");

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["validate", path.to_str().expect("UTF-8 temp path")])
        .output()
        .expect("run CLI");

    let _ = fs::remove_file(&path);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).expect("stderr must be UTF-8");
    assert!(stderr.starts_with("error: "));
}

#[test]
fn validate_rel_accepts_multiple_relocatable_inputs() {
    let first = temp_path("o");
    let second = temp_path("o");
    fs::write(&first, minimal_elf64(1)).expect("write first temp ELF");
    fs::write(&second, minimal_elf64(1)).expect("write second temp ELF");

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args([
            "validate-rel",
            first.to_str().expect("UTF-8 temp path"),
            second.to_str().expect("UTF-8 temp path"),
        ])
        .output()
        .expect("run CLI");

    let _ = fs::remove_file(&first);
    let _ = fs::remove_file(&second);
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert_eq!(
        String::from_utf8(output.stdout).expect("stdout must be UTF-8"),
        "valid relocatable ELF64 x86-64 inputs: objects=2, sections=0, symbol_tables=0, symbols=0, rela_tables=0, relocations=0\n"
    );
}

#[test]
fn validate_rel_rejects_non_relocatable_elf() {
    let path = temp_path("elf");
    fs::write(&path, minimal_elf64(2)).expect("write temp executable ELF");

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["validate-rel", path.to_str().expect("UTF-8 temp path")])
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
        "missing input path\nusage: mini-elf-toolchain validate <input>\n       mini-elf-toolchain validate-rel <input>...\n       mini-elf-toolchain link <-o <output>|--output=<output>> [--map <map-file>|-Map=<map-file>] [--entry <symbol>] [--image-base <address>] [-u <symbol>|-u<symbol>|--undefined <symbol>] [-L <dir>|-L<dir>] <input|-l<name>|-l <name>|--start-group|--end-group|--whole-archive|--no-whole-archive|--push-state|--pop-state>...\n"
    );
}
