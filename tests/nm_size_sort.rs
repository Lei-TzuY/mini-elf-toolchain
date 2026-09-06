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
fn size_sort_matches_gnu_nm_for_real_et_rel() {
    if !tool_available("as") || !tool_available("nm") {
        return;
    }

    let dir = temp_dir("nm-size-sort");
    let assembly = dir.join("sample.s");
    let object = dir.join("sample.o");
    fs::write(
        &assembly,
        ".globl large\n.type large,@object\n.size large,8\nlarge: .quad 0\n\
.globl zeta\n.type zeta,@object\n.size zeta,4\nzeta: .long 0\n\
.globl alpha\n.type alpha,@object\n.size alpha,4\nalpha: .long 0\n\
.globl tiny\n.type tiny,@object\n.size tiny,1\ntiny: .byte 0\n",
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

    let ours = Command::new(env!("CARGO_BIN_EXE_mini-elf-nm"))
        .arg("--size-sort")
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        ours.status.success(),
        "{}",
        String::from_utf8_lossy(&ours.stderr)
    );
    let ours_stdout = String::from_utf8_lossy(&ours.stdout);
    let ours_tiny = ours_stdout.find(" tiny\n").unwrap();
    let ours_alpha = ours_stdout.find(" alpha\n").unwrap();
    let ours_zeta = ours_stdout.find(" zeta\n").unwrap();
    let ours_large = ours_stdout.find(" large\n").unwrap();
    assert!(
        ours_tiny < ours_alpha && ours_alpha < ours_zeta && ours_zeta < ours_large,
        "{ours_stdout}"
    );

    let gnu = Command::new("nm")
        .arg("--size-sort")
        .arg(&object)
        .output()
        .unwrap();
    assert!(gnu.status.success());
    let gnu_stdout = String::from_utf8_lossy(&gnu.stdout);
    let gnu_tiny = gnu_stdout.find(" tiny\n").unwrap();
    let gnu_alpha = gnu_stdout.find(" alpha\n").unwrap();
    let gnu_zeta = gnu_stdout.find(" zeta\n").unwrap();
    let gnu_large = gnu_stdout.find(" large\n").unwrap();
    assert!(
        gnu_tiny < gnu_alpha && gnu_alpha < gnu_zeta && gnu_zeta < gnu_large,
        "{gnu_stdout}"
    );

    let reversed = Command::new(env!("CARGO_BIN_EXE_mini-elf-nm"))
        .arg("--size-sort")
        .arg("-r")
        .arg(&object)
        .output()
        .unwrap();
    assert!(reversed.status.success());
    let reversed_stdout = String::from_utf8_lossy(&reversed.stdout);
    assert!(
        reversed_stdout.find(" large\n").unwrap() < reversed_stdout.find(" tiny\n").unwrap(),
        "{reversed_stdout}"
    );

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn size_sort_keeps_malformed_input_failure_atomic() {
    let dir = temp_dir("nm-size-sort-malformed");
    let input = dir.join("bad.o");
    fs::write(&input, b"\x7fELF").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-nm"))
        .arg("--size-sort")
        .arg(&input)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty(), "stdout must remain atomic");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("ELF64 header is truncated"), "{stderr}");

    let _ = fs::remove_dir_all(dir);
}
