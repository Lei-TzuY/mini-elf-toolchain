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
        "mini-elf-toolchain-partial-whole-{label}-{}-{nonce}",
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

fn make_unindexed_archive(dir: &Path, name: &str, members: &[&Path]) -> PathBuf {
    let archive = dir.join(name);
    let mut command = Command::new("ar");
    command.arg("rcS").arg(&archive);
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

fn globals(path: &Path) -> BTreeSet<String> {
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

#[test]
fn partial_whole_archive_forces_unindexed_members_like_gnu_ld_r() {
    if !have_gnu_tools() {
        return;
    }

    let dir = temp_dir("unindexed");
    let start = assemble(
        &dir,
        "start",
        r#".section .text
.globl _start
.type _start,@function
_start:
    mov $60, %rax
    xor %rdi, %rdi
    syscall
.size _start, .-_start
"#,
    );
    let helper = assemble(
        &dir,
        "helper",
        r#".section .text
.globl helper
.type helper,@function
helper:
    ret
.size helper, .-helper
"#,
    );
    let unused = assemble(
        &dir,
        "unused",
        r#".section .text
.globl unused_symbol
.type unused_symbol,@function
unused_symbol:
    ret
.size unused_symbol, .-unused_symbol
"#,
    );
    let archive = make_unindexed_archive(&dir, "libextra.a", &[&helper, &unused]);

    let ordinary = dir.join("ordinary.o");
    let ordinary_output = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["partial", "-o"])
        .arg(&ordinary)
        .arg(&start)
        .arg(&archive)
        .output()
        .unwrap();
    assert!(!ordinary_output.status.success());
    assert!(ordinary_output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&ordinary_output.stderr).contains("symbol index"));
    assert!(!ordinary.exists());

    let ours = dir.join("ours.o");
    let whole_output = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["partial", "-o"])
        .arg(&ours)
        .arg(&start)
        .arg("--whole-archive")
        .arg(&archive)
        .arg("--no-whole-archive")
        .output()
        .unwrap();
    assert!(
        whole_output.status.success(),
        "{}",
        String::from_utf8_lossy(&whole_output.stderr)
    );
    assert!(String::from_utf8_lossy(&whole_output.stdout).contains("objects=3"));

    let gnu = dir.join("gnu.o");
    let gnu_output = Command::new("ld")
        .args(["-r", "-o"])
        .arg(&gnu)
        .arg(&start)
        .arg("--whole-archive")
        .arg(&archive)
        .arg("--no-whole-archive")
        .output()
        .unwrap();
    assert!(
        gnu_output.status.success(),
        "{}",
        String::from_utf8_lossy(&gnu_output.stderr)
    );

    assert_eq!(globals(&ours), globals(&gnu));
    let records = globals(&ours);
    assert!(records.iter().any(|line| line.ends_with(" _start")));
    assert!(records.iter().any(|line| line.ends_with(" helper")));
    assert!(records.iter().any(|line| line.ends_with(" unused_symbol")));

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
fn partial_whole_archive_rejects_malformed_member_before_output() {
    if !command_reports("ar", "GNU ar") {
        return;
    }

    let dir = temp_dir("malformed");
    let malformed = dir.join("bad.txt");
    fs::write(&malformed, b"not an ELF object").unwrap();
    let archive = make_unindexed_archive(&dir, "libbad.a", &[&malformed]);
    let output_path = dir.join("partial.o");

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["partial", "-o"])
        .arg(&output_path)
        .arg("--whole-archive")
        .arg(&archive)
        .arg("--no-whole-archive")
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("libbad.a"), "{stderr}");
    assert!(stderr.contains("bad.txt"), "{stderr}");
    assert!(stderr.contains("ET_REL"), "{stderr}");
    assert!(!output_path.exists());

    let _ = fs::remove_dir_all(dir);
}
