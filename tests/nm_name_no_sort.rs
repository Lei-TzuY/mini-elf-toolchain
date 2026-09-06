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

fn assert_order(output: &[u8], names: &[&str]) {
    let stdout = String::from_utf8_lossy(output);
    let mut previous = None;
    for name in names {
        let position = stdout.find(&format!(" {name}\n")).unwrap();
        if let Some(previous) = previous {
            assert!(previous < position, "{stdout}");
        }
        previous = Some(position);
    }
}

#[test]
fn default_name_and_no_sort_match_gnu_nm_for_real_et_rel() {
    if !tool_available("as") || !tool_available("nm") {
        return;
    }

    let dir = temp_dir("nm-name-no-sort");
    let assembly = dir.join("sample.s");
    let object = dir.join("sample.o");
    fs::write(
        &assembly,
        ".globl zed\n.set zed,0x10\n.globl alpha\n.set alpha,0x30\n.globl middle\n.set middle,0x20\n",
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

    let default = Command::new(env!("CARGO_BIN_EXE_mini-elf-nm"))
        .arg(&object)
        .output()
        .unwrap();
    assert!(default.status.success());
    assert_order(&default.stdout, &["alpha", "middle", "zed"]);

    let gnu_default = Command::new("nm").arg(&object).output().unwrap();
    assert!(gnu_default.status.success());
    assert_order(&gnu_default.stdout, &["alpha", "middle", "zed"]);

    let no_sort = Command::new(env!("CARGO_BIN_EXE_mini-elf-nm"))
        .arg("-p")
        .arg(&object)
        .output()
        .unwrap();
    assert!(no_sort.status.success());
    assert_order(&no_sort.stdout, &["zed", "alpha", "middle"]);

    let long_no_sort = Command::new(env!("CARGO_BIN_EXE_mini-elf-nm"))
        .arg("--no-sort")
        .arg(&object)
        .output()
        .unwrap();
    assert!(long_no_sort.status.success());
    assert_eq!(no_sort.stdout, long_no_sort.stdout);

    let gnu_no_sort = Command::new("nm").arg("-p").arg(&object).output().unwrap();
    assert!(gnu_no_sort.status.success());
    assert_order(&gnu_no_sort.stdout, &["zed", "alpha", "middle"]);

    let numeric_then_no_sort = Command::new(env!("CARGO_BIN_EXE_mini-elf-nm"))
        .arg("-n")
        .arg("-p")
        .arg(&object)
        .output()
        .unwrap();
    assert!(numeric_then_no_sort.status.success());
    assert_eq!(no_sort.stdout, numeric_then_no_sort.stdout);

    let no_sort_then_numeric = Command::new(env!("CARGO_BIN_EXE_mini-elf-nm"))
        .arg("-p")
        .arg("-n")
        .arg(&object)
        .output()
        .unwrap();
    assert!(no_sort_then_numeric.status.success());
    assert_order(&no_sort_then_numeric.stdout, &["zed", "middle", "alpha"]);

    let no_sort_reverse = Command::new(env!("CARGO_BIN_EXE_mini-elf-nm"))
        .arg("-p")
        .arg("-r")
        .arg(&object)
        .output()
        .unwrap();
    assert!(no_sort_reverse.status.success());
    assert_eq!(no_sort.stdout, no_sort_reverse.stdout);

    let gnu_no_sort_reverse = Command::new("nm")
        .arg("-p")
        .arg("-r")
        .arg(&object)
        .output()
        .unwrap();
    assert!(gnu_no_sort_reverse.status.success());
    assert_order(&gnu_no_sort_reverse.stdout, &["zed", "alpha", "middle"]);

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn no_sort_keeps_malformed_input_failure_atomic() {
    let dir = temp_dir("nm-no-sort-malformed");
    let input = dir.join("bad.o");
    fs::write(&input, b"\x7fELF").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-nm"))
        .arg("--no-sort")
        .arg(&input)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty(), "stdout must remain atomic");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("ELF64 header is truncated"), "{stderr}");

    let _ = fs::remove_dir_all(dir);
}
