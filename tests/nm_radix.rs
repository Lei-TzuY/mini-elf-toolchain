use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_dir(label: &str) -> std::path::PathBuf {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let path = std::env::temp_dir().join(format!("mini-elf-toolchain-{label}-{}-{nonce}", std::process::id()));
    fs::create_dir_all(&path).unwrap();
    path
}

fn tool_available(tool: &str) -> bool {
    Command::new(tool).arg("--version").output().is_ok()
}

#[test]
fn radix_forms_render_real_symbol_values() {
    if !tool_available("as") || !tool_available("nm") {
        return;
    }
    let dir = temp_dir("nm-radix");
    let assembly = dir.join("sample.s");
    let object = dir.join("sample.o");
    fs::write(&assembly, ".globl marker\n.set marker,0x2a\n").unwrap();
    assert!(Command::new("as").arg("-o").arg(&object).arg(&assembly).status().unwrap().success());

    for (args, expected) in [
        (vec!["-t", "d"], "0000000000000042"),
        (vec!["-to"], "0000000000000052"),
        (vec!["--radix=x"], "000000000000002a"),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-nm"))
            .args(args).arg(&object).output().unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.lines().any(|line| line.starts_with(expected) && line.ends_with(" marker")), "{stdout}");
    }

    let gnu = Command::new("nm").args(["-t", "d"]).arg(&object).output().unwrap();
    assert!(gnu.status.success());
    assert!(String::from_utf8_lossy(&gnu.stdout).contains("0000000000000042"));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn invalid_radix_fails_before_input_io() {
    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-nm"))
        .args(["--radix=bad", "does-not-exist.o"]).output().unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("invalid radix 'bad'"), "{stderr}");
    assert!(!stderr.contains("cannot read"), "{stderr}");
}

#[test]
fn radix_keeps_malformed_input_failure_atomic() {
    let dir = temp_dir("nm-radix-malformed");
    let input = dir.join("bad.o");
    fs::write(&input, b"\x7fELF").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-nm"))
        .args(["--radix", "o"]).arg(&input).output().unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty(), "stdout must remain atomic");
    assert!(String::from_utf8_lossy(&output.stderr).contains("ELF64 header is truncated"));
    let _ = fs::remove_dir_all(dir);
}
