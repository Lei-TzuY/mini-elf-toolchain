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

#[test]
fn print_file_name_matches_gnu_nm_provenance_for_real_et_rel() {
    if !tool_available("as") || !tool_available("nm") {
        return;
    }

    let dir = temp_dir("nm-print-file-name");
    let assembly = dir.join("sample.s");
    let object = dir.join("sample.o");
    fs::write(&assembly, ".globl alpha\nalpha:\n  ret\n").unwrap();
    let assembled = Command::new("as")
        .arg("-o")
        .arg(&object)
        .arg(&assembly)
        .output()
        .unwrap();
    assert!(assembled.status.success());

    let ours = Command::new(env!("CARGO_BIN_EXE_mini-elf-nm"))
        .arg("-A")
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        ours.status.success(),
        "{}",
        String::from_utf8_lossy(&ours.stderr)
    );
    let ours_stdout = String::from_utf8_lossy(&ours.stdout);
    let expected_prefix = format!("{}:", object.to_string_lossy());
    let ours_alpha = ours_stdout
        .lines()
        .find(|line| line.ends_with(" alpha"))
        .unwrap();
    assert!(
        ours_alpha.starts_with(&expected_prefix),
        "{ours_stdout}"
    );

    let gnu = Command::new("nm").arg("-A").arg(&object).output().unwrap();
    assert!(gnu.status.success());
    let gnu_stdout = String::from_utf8_lossy(&gnu.stdout);
    let gnu_alpha = gnu_stdout
        .lines()
        .find(|line| line.ends_with(" alpha"))
        .unwrap();
    assert!(gnu_alpha.starts_with(&expected_prefix), "{gnu_stdout}");

    let long = Command::new(env!("CARGO_BIN_EXE_mini-elf-nm"))
        .arg("--print-file-name")
        .arg(&object)
        .output()
        .unwrap();
    assert!(long.status.success());
    assert_eq!(ours.stdout, long.stdout);

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn print_file_name_keeps_malformed_input_failure_atomic() {
    let dir = temp_dir("nm-print-file-name-malformed");
    let input = dir.join("bad.o");
    fs::write(&input, b"\x7fELF").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-nm"))
        .arg("-A")
        .arg(&input)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty(), "stdout must remain atomic");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("ELF64 header is truncated"), "{stderr}");

    let _ = fs::remove_dir_all(dir);
}
