use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn command_reports(program: &str, marker: &str) -> bool {
    let Ok(output) = Command::new(program).arg("--version").output() else {
        return false;
    };
    output.status.success()
        && (String::from_utf8_lossy(&output.stdout).contains(marker)
            || String::from_utf8_lossy(&output.stderr).contains(marker))
}

fn have_gnu_tools() -> bool {
    command_reports("as", "GNU assembler")
        && command_reports("ar", "GNU ar")
        && command_reports("ld", "GNU ld")
        && command_reports("nm", "GNU nm")
}

fn temp_dir(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after Unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "mini-elf-toolchain-partial-archive-{label}-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&path).unwrap();
    path
}

fn assemble(dir: &Path, stem: &str, source: &str) -> PathBuf {
    let asm = dir.join(format!("{stem}.s"));
    let object = dir.join(format!("{stem}.o"));
    fs::write(&asm, source).unwrap();
    let status = Command::new("as")
        .args(["--64", "-o"])
        .arg(&object)
        .arg(&asm)
        .status()
        .unwrap();
    assert!(status.success(), "GNU as failed for {stem}");
    object
}

fn make_archive(dir: &Path, members: &[&Path]) -> PathBuf {
    let archive = dir.join("libsupport.a");
    let mut command = Command::new("ar");
    command.arg("rcs").arg(&archive);
    for member in members {
        command.arg(member);
    }
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    archive
}

fn global_records(path: &Path) -> BTreeSet<String> {
    let output = Command::new("nm").arg("-g").arg(path).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn build_fixture(dir: &Path) -> (PathBuf, PathBuf) {
    let start = assemble(
        dir,
        "start",
        r#".section .text
.globl _start
.type _start,@function
.extern helper
_start:
    mov $60, %rax
    xor %rdi, %rdi
    syscall
    .quad helper
.size _start, .-_start
"#,
    );
    let helper = assemble(
        dir,
        "helper",
        r#".section .text
.globl helper
.type helper,@function
.extern leaf
helper:
    ret
    .quad leaf
.size helper, .-helper
"#,
    );
    let leaf = assemble(
        dir,
        "leaf",
        r#".section .text
.globl leaf
.type leaf,@function
leaf:
    ret
.size leaf, .-leaf
"#,
    );
    let unused = assemble(
        dir,
        "unused",
        r#".section .text
.globl unused_symbol
.type unused_symbol,@function
unused_symbol:
    ret
.size unused_symbol, .-unused_symbol
"#,
    );
    let archive = make_archive(dir, &[&helper, &leaf, &unused]);
    (start, archive)
}

#[test]
fn partial_link_lazily_extracts_transitive_archive_members_like_gnu_ld_r() {
    if !have_gnu_tools() {
        return;
    }

    let dir = temp_dir("transitive");
    let (start, archive) = build_fixture(&dir);
    let ours = dir.join("ours.o");
    let gnu = dir.join("gnu.o");

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["partial", "-o"])
        .arg(&ours)
        .arg(&start)
        .arg(&archive)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("objects=3"));

    let gnu_output = Command::new("ld")
        .args(["-r", "-o"])
        .arg(&gnu)
        .arg(&start)
        .arg(&archive)
        .output()
        .unwrap();
    assert!(
        gnu_output.status.success(),
        "{}",
        String::from_utf8_lossy(&gnu_output.stderr)
    );

    assert_eq!(global_records(&ours), global_records(&gnu));
    let records = global_records(&ours);
    assert!(records.iter().any(|line| line.ends_with(" _start")));
    assert!(records.iter().any(|line| line.ends_with(" helper")));
    assert!(records.iter().any(|line| line.ends_with(" leaf")));
    assert!(!records.iter().any(|line| line.ends_with(" unused_symbol")));

    let mini_exe = dir.join("mini-final");
    let mini = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&mini_exe)
        .arg(&ours)
        .output()
        .unwrap();
    assert!(
        mini.status.success(),
        "{}",
        String::from_utf8_lossy(&mini.stderr)
    );

    let gnu_exe = dir.join("gnu-final");
    let gnu_final = Command::new("ld")
        .args(["-static", "-o"])
        .arg(&gnu_exe)
        .arg(&ours)
        .output()
        .unwrap();
    assert!(
        gnu_final.status.success(),
        "{}",
        String::from_utf8_lossy(&gnu_final.stderr)
    );

    #[cfg(target_os = "linux")]
    for executable in [&mini_exe, &gnu_exe] {
        let status = Command::new(executable).status().unwrap();
        assert!(
            status.success(),
            "{} returned {status}",
            executable.display()
        );
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn partial_archive_lookup_preserves_left_to_right_order() {
    if !have_gnu_tools() {
        return;
    }

    let dir = temp_dir("order");
    let (start, archive) = build_fixture(&dir);
    let ours = dir.join("ours-order.o");
    let gnu = dir.join("gnu-order.o");

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["partial", "-o"])
        .arg(&ours)
        .arg(&archive)
        .arg(&start)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("objects=1"));

    let gnu_output = Command::new("ld")
        .args(["-r", "-o"])
        .arg(&gnu)
        .arg(&archive)
        .arg(&start)
        .output()
        .unwrap();
    assert!(
        gnu_output.status.success(),
        "{}",
        String::from_utf8_lossy(&gnu_output.stderr)
    );

    assert_eq!(global_records(&ours), global_records(&gnu));
    let records = global_records(&ours);
    assert!(records.iter().any(|line| line == "U helper"));
    assert!(!records.iter().any(|line| line.ends_with(" leaf")));
    assert!(!records.iter().any(|line| line.ends_with(" unused_symbol")));

    let _ = fs::remove_dir_all(dir);
}
