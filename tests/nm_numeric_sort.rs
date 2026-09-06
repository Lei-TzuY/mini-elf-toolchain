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
fn numeric_sort_matches_gnu_nm_for_real_et_rel() {
    if !tool_available("as") || !tool_available("nm") {
        return;
    }

    let dir = temp_dir("nm-numeric-sort");
    let assembly = dir.join("sample.s");
    let object = dir.join("sample.o");
    fs::write(
        &assembly,
        ".globl high\n.set high,0x30\n.globl low\n.set low,0x10\n.globl middle\n.set middle,0x20\n",
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

    let short = Command::new(env!("CARGO_BIN_EXE_mini-elf-nm"))
        .arg("-n")
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        short.status.success(),
        "{}",
        String::from_utf8_lossy(&short.stderr)
    );
    let short_stdout = String::from_utf8_lossy(&short.stdout);
    let low = short_stdout.find(" low\n").unwrap();
    let middle = short_stdout.find(" middle\n").unwrap();
    let high = short_stdout.find(" high\n").unwrap();
    assert!(low < middle && middle < high, "{short_stdout}");

    let long = Command::new(env!("CARGO_BIN_EXE_mini-elf-nm"))
        .arg("--numeric-sort")
        .arg(&object)
        .output()
        .unwrap();
    assert!(long.status.success());
    assert_eq!(short.stdout, long.stdout);

    let gnu = Command::new("nm").arg("-n").arg(&object).output().unwrap();
    assert!(gnu.status.success());
    let gnu_stdout = String::from_utf8_lossy(&gnu.stdout);
    let gnu_low = gnu_stdout.find(" low\n").unwrap();
    let gnu_middle = gnu_stdout.find(" middle\n").unwrap();
    let gnu_high = gnu_stdout.find(" high\n").unwrap();
    assert!(
        gnu_low < gnu_middle && gnu_middle < gnu_high,
        "{gnu_stdout}"
    );

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn numeric_sort_keeps_malformed_input_failure_atomic() {
    let dir = temp_dir("nm-numeric-sort-malformed");
    let input = dir.join("bad.o");
    fs::write(&input, b"\x7fELF").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-nm"))
        .arg("--numeric-sort")
        .arg(&input)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty(), "stdout must remain atomic");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("ELF64 header is truncated"), "{stderr}");

    let _ = fs::remove_dir_all(dir);
}
