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
fn no_weak_matches_gnu_nm_on_real_object() {
    if !tool_available("as") || !tool_available("nm") {
        return;
    }
    let dir = temp_dir("nm-no-weak");
    let assembly = dir.join("sample.s");
    let object = dir.join("sample.o");
    fs::write(
        &assembly,
        ".text\n.globl strong_symbol\nstrong_symbol:\n ret\n.weak weak_symbol\nweak_symbol:\n ret\n.local local_symbol\nlocal_symbol:\n ret\n",
    )
    .unwrap();
    assert!(
        Command::new("as")
            .arg("-o")
            .arg(&object)
            .arg(&assembly)
            .status()
            .unwrap()
            .success()
    );

    for flag in ["-W", "--no-weak"] {
        let ours = Command::new(env!("CARGO_BIN_EXE_mini-elf-nm"))
            .args([flag, "--just-symbols"])
            .arg(&object)
            .output()
            .unwrap();
        assert!(
            ours.status.success(),
            "{}",
            String::from_utf8_lossy(&ours.stderr)
        );
        let output = String::from_utf8_lossy(&ours.stdout);
        assert!(output.contains("strong_symbol\n"));
        assert!(output.contains("local_symbol\n"));
        assert!(!output.contains("weak_symbol\n"));
    }

    let ours = Command::new(env!("CARGO_BIN_EXE_mini-elf-nm"))
        .args(["-W", "--just-symbols"])
        .arg(&object)
        .output()
        .unwrap();
    let gnu = Command::new("nm")
        .args(["-W", "--just-symbols"])
        .arg(&object)
        .output()
        .unwrap();
    assert!(gnu.status.success());
    assert_eq!(ours.stdout, gnu.stdout);

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn no_weak_composes_with_extern_only() {
    if !tool_available("as") {
        return;
    }
    let dir = temp_dir("nm-no-weak-extern");
    let assembly = dir.join("sample.s");
    let object = dir.join("sample.o");
    fs::write(
        &assembly,
        ".text\n.globl strong_symbol\nstrong_symbol:\n ret\n.weak weak_symbol\nweak_symbol:\n ret\n.local local_symbol\nlocal_symbol:\n ret\n",
    )
    .unwrap();
    assert!(
        Command::new("as")
            .arg("-o")
            .arg(&object)
            .arg(&assembly)
            .status()
            .unwrap()
            .success()
    );

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-nm"))
        .args(["-W", "-g", "--just-symbols"])
        .arg(&object)
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "strong_symbol\n");
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn malformed_input_remains_stdout_atomic_with_no_weak() {
    let dir = temp_dir("nm-no-weak-malformed");
    let malformed = dir.join("bad.o");
    fs::write(&malformed, b"\x7fELF\x02\x01\x01").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-nm"))
        .arg("-W")
        .arg(&malformed)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.is_empty());
    let _ = fs::remove_dir_all(dir);
}
