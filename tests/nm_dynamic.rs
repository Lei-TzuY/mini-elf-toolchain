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
        std::process::id(),
    ));
    fs::create_dir_all(&path).unwrap();
    path
}

fn tool_available(tool: &str) -> bool {
    Command::new(tool).arg("--version").output().is_ok()
}

#[test]
fn dynamic_selects_dynsym_from_real_shared_object() {
    if !tool_available("as") || !tool_available("ld") || !tool_available("nm") {
        return;
    }
    let dir = temp_dir("nm-dynamic");
    let assembly = dir.join("sample.s");
    let object = dir.join("sample.o");
    let shared = dir.join("libsample.so");
    fs::write(
        &assembly,
        ".text\n.globl exported\n.type exported,@function\nexported:\n  ret\n.size exported,.-exported\n",
    )
    .unwrap();
    assert!(Command::new("as")
        .arg("-o")
        .arg(&object)
        .arg(&assembly)
        .status()
        .unwrap()
        .success());
    assert!(Command::new("ld")
        .args(["-shared", "-o"])
        .arg(&shared)
        .arg(&object)
        .status()
        .unwrap()
        .success());

    for flag in ["-D", "--dynamic"] {
        let ours = Command::new(env!("CARGO_BIN_EXE_mini-elf-nm"))
            .args([flag, "--just-symbols"])
            .arg(&shared)
            .output()
            .unwrap();
        assert!(
            ours.status.success(),
            "{}",
            String::from_utf8_lossy(&ours.stderr)
        );
        let ours = String::from_utf8_lossy(&ours.stdout);
        assert_eq!(ours.lines().filter(|line| *line == "exported").count(), 1);
    }

    let gnu = Command::new("nm")
        .args(["-D", "--just-symbols"])
        .arg(&shared)
        .output()
        .unwrap();
    assert!(gnu.status.success());
    assert_eq!(
        String::from_utf8_lossy(&gnu.stdout)
            .lines()
            .filter(|line| *line == "exported")
            .count(),
        1
    );
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn dynamic_keeps_malformed_input_failure_atomic() {
    let dir = temp_dir("nm-dynamic-malformed");
    let input = dir.join("bad.so");
    fs::write(&input, b"\x7fELF").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-nm"))
        .args(["-D", "--just-symbols"])
        .arg(&input)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty(), "stdout must remain atomic");
    assert!(String::from_utf8_lossy(&output.stderr).contains("ELF64 header is truncated"));
    let _ = fs::remove_dir_all(dir);
}
