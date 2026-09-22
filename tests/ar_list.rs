use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn command_available(command: &str) -> bool {
    Command::new(command)
        .arg("--version")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn temp_dir() -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before Unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "mini-elf-toolchain-ar-list-{}-{nonce}",
        std::process::id()
    ))
}

#[test]
fn lists_real_archive_members_like_gnu_ar() {
    if !command_available("as") || !command_available("ar") {
        return;
    }

    let dir = temp_dir();
    fs::create_dir_all(&dir).unwrap();
    let first_source = dir.join("first.s");
    let second_source = dir.join("second.s");
    let first_object = dir.join("first.o");
    let second_object = dir.join("second.o");
    let archive = dir.join("libmembers.a");
    fs::write(&first_source, ".globl first\nfirst:\n  ret\n").unwrap();
    fs::write(&second_source, ".globl second\nsecond:\n  ret\n").unwrap();
    assert!(Command::new("as")
        .args([
            "-o",
            first_object.to_str().unwrap(),
            first_source.to_str().unwrap(),
        ])
        .status()
        .unwrap()
        .success());
    assert!(Command::new("as")
        .args([
            "-o",
            second_object.to_str().unwrap(),
            second_source.to_str().unwrap(),
        ])
        .status()
        .unwrap()
        .success());
    assert!(Command::new("ar")
        .args([
            "rcs",
            archive.to_str().unwrap(),
            first_object.to_str().unwrap(),
            second_object.to_str().unwrap(),
        ])
        .status()
        .unwrap()
        .success());

    let ours = Command::new(env!("CARGO_BIN_EXE_mini-elf-ar"))
        .args(["t", archive.to_str().unwrap()])
        .output()
        .unwrap();
    let gnu = Command::new("ar")
        .args(["t", archive.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        ours.status.success(),
        "{}",
        String::from_utf8_lossy(&ours.stderr)
    );
    assert!(gnu.status.success());
    assert_eq!(ours.stdout, gnu.stdout);

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn malformed_archive_fails_without_stdout() {
    let dir = temp_dir();
    fs::create_dir_all(&dir).unwrap();
    let archive = dir.join("broken.a");
    fs::write(&archive, b"!<arch>\nshort").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-ar"))
        .args(["t", archive.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("truncated archive member header"));

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn rejects_unsupported_operation_before_reading_input() {
    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-ar"))
        .args(["x", "definitely-missing.a"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("only 't' is supported"));
}
