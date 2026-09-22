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

fn temp_dir(label: &str) -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before Unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "mini-elf-toolchain-ar-extract-{label}-{}-{nonce}",
        std::process::id()
    ))
}

fn append_member(bytes: &mut Vec<u8>, name: &str, data: &[u8]) {
    assert!(name.len() <= 16);
    let mut header = format!(
        "{name:<16}{:<12}{:<6}{:<6}{:<8}{:<10}",
        "0",
        "0",
        "0",
        "100644",
        data.len()
    )
    .into_bytes();
    header.extend_from_slice(&[0x60, b'\n']);
    assert_eq!(header.len(), 60);
    bytes.extend_from_slice(&header);
    bytes.extend_from_slice(data);
    if data.len() % 2 != 0 {
        bytes.push(b'\n');
    }
}

fn create_real_archive(dir: &std::path::Path) -> std::path::PathBuf {
    let first_source = dir.join("first.s");
    let second_source = dir.join("second.s");
    let first_object = dir.join("first.o");
    let second_object = dir.join("second.o");
    let archive = dir.join("libmembers.a");

    fs::write(&first_source, ".globl first\nfirst:\n  ret\n").unwrap();
    fs::write(&second_source, ".globl second\nsecond:\n  nop\n  ret\n").unwrap();
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
    archive
}

#[test]
fn extracts_real_archive_members_like_gnu_ar() {
    if !command_available("as") || !command_available("ar") {
        return;
    }

    let dir = temp_dir("gnu");
    let ours_dir = dir.join("ours");
    let gnu_dir = dir.join("gnu");
    fs::create_dir_all(&ours_dir).unwrap();
    fs::create_dir_all(&gnu_dir).unwrap();
    let archive = create_real_archive(&dir);

    let ours = Command::new(env!("CARGO_BIN_EXE_mini-elf-ar"))
        .current_dir(&ours_dir)
        .args(["x", archive.to_str().unwrap()])
        .output()
        .unwrap();
    let gnu = Command::new("ar")
        .current_dir(&gnu_dir)
        .args(["x", archive.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(
        ours.status.success(),
        "{}",
        String::from_utf8_lossy(&ours.stderr)
    );
    assert!(
        gnu.status.success(),
        "{}",
        String::from_utf8_lossy(&gnu.stderr)
    );
    assert!(ours.stdout.is_empty());
    assert_eq!(
        fs::read(ours_dir.join("first.o")).unwrap(),
        fs::read(gnu_dir.join("first.o")).unwrap()
    );
    assert_eq!(
        fs::read(ours_dir.join("second.o")).unwrap(),
        fs::read(gnu_dir.join("second.o")).unwrap()
    );

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn extracts_only_selected_member() {
    if !command_available("as") || !command_available("ar") {
        return;
    }

    let dir = temp_dir("selected");
    let out_dir = dir.join("out");
    fs::create_dir_all(&out_dir).unwrap();
    let archive = create_real_archive(&dir);

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-ar"))
        .current_dir(&out_dir)
        .args(["x", archive.to_str().unwrap(), "second.o"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!out_dir.join("first.o").exists());
    assert!(out_dir.join("second.o").exists());

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn rejects_unsafe_member_name_before_writing_anything() {
    let dir = temp_dir("unsafe");
    let out_dir = dir.join("out");
    fs::create_dir_all(&out_dir).unwrap();

    let mut bytes = b"!<arch>\n".to_vec();
    append_member(&mut bytes, "safe.o/", b"safe");
    append_member(&mut bytes, "../escape.o/", b"escape");
    let archive = dir.join("unsafe.a");
    fs::write(&archive, bytes).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-ar"))
        .current_dir(&out_dir)
        .args(["x", archive.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unsafe archive member name"));
    assert!(!out_dir.join("safe.o").exists());
    assert!(!dir.join("escape.o").exists());

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn refuses_to_overwrite_existing_output() {
    if !command_available("as") || !command_available("ar") {
        return;
    }

    let dir = temp_dir("existing");
    let out_dir = dir.join("out");
    fs::create_dir_all(&out_dir).unwrap();
    let archive = create_real_archive(&dir);
    fs::write(out_dir.join("first.o"), b"keep-existing").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-ar"))
        .current_dir(&out_dir)
        .args(["x", archive.to_str().unwrap(), "first.o"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("refusing to overwrite"));
    assert_eq!(fs::read(out_dir.join("first.o")).unwrap(), b"keep-existing");

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn duplicate_output_names_fail_before_writing() {
    let dir = temp_dir("duplicate");
    let out_dir = dir.join("out");
    fs::create_dir_all(&out_dir).unwrap();

    let mut bytes = b"!<arch>\n".to_vec();
    append_member(&mut bytes, "dup.o/", b"first");
    append_member(&mut bytes, "dup.o/", b"second");
    let archive = dir.join("duplicate.a");
    fs::write(&archive, bytes).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-ar"))
        .current_dir(&out_dir)
        .args(["x", archive.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("duplicate extraction output"));
    assert!(!out_dir.join("dup.o").exists());

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn malformed_archive_fails_before_writing_selected_member() {
    let dir = temp_dir("malformed");
    let out_dir = dir.join("out");
    fs::create_dir_all(&out_dir).unwrap();

    let mut bytes = b"!<arch>\n".to_vec();
    append_member(&mut bytes, "first.o/", b"first");
    bytes.extend_from_slice(b"short");
    let archive = dir.join("malformed.a");
    fs::write(&archive, bytes).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-ar"))
        .current_dir(&out_dir)
        .args(["x", archive.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("truncated archive member header"));
    assert!(!out_dir.join("first.o").exists());

    let _ = fs::remove_dir_all(dir);
}
