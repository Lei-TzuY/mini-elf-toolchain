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
fn file_header_matches_gnu_readelf_facts_for_real_et_rel() {
    if !tool_available("as") || !tool_available("readelf") {
        return;
    }

    let dir = temp_dir("readelf-header");
    let assembly = dir.join("sample.s");
    let object = dir.join("sample.o");
    fs::write(&assembly, ".text\n.globl sample\nsample:\n  ret\n").unwrap();
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
        .arg("-h")
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        ours.status.success(),
        "{}",
        String::from_utf8_lossy(&ours.stderr)
    );
    let ours_stdout = String::from_utf8_lossy(&ours.stdout);
    assert!(ours_stdout.contains("Class:                             ELF64"));
    assert!(ours_stdout.contains("Type:                              REL (Relocatable file)"));
    assert!(ours_stdout.contains("Machine:                           Advanced Micro Devices X86-64"));
    assert!(ours_stdout.contains("Entry point address:               0x0"));

    let gnu = Command::new("readelf")
        .arg("-h")
        .arg(&object)
        .output()
        .unwrap();
    assert!(gnu.status.success());
    let gnu_stdout = String::from_utf8_lossy(&gnu.stdout);
    assert!(gnu_stdout.contains("Class:                             ELF64"));
    assert!(gnu_stdout.contains("Type:                              REL (Relocatable file)"));
    assert!(gnu_stdout.contains("Machine:                           Advanced Micro Devices X86-64"));
    assert!(gnu_stdout.contains("Entry point address:               0x0"));

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn malformed_later_input_keeps_stdout_atomic() {
    if !tool_available("as") {
        return;
    }

    let dir = temp_dir("readelf-header-atomic");
    let assembly = dir.join("good.s");
    let good = dir.join("good.o");
    let bad = dir.join("bad.o");
    fs::write(&assembly, ".text\n.globl good\ngood:\n  ret\n").unwrap();
    let assembled = Command::new("as")
        .arg("-o")
        .arg(&good)
        .arg(&assembly)
        .output()
        .unwrap();
    assert!(assembled.status.success());
    fs::write(&bad, b"\x7fELF").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-readelf"))
        .arg("--file-header")
        .arg(&good)
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty(), "stdout must remain atomic");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("ELF64 header is truncated"), "{stderr}");

    let _ = fs::remove_dir_all(dir);
}
