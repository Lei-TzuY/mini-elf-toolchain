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
        "mini-elf-toolchain-partial-forced-{label}-{}-{nonce}",
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

fn archive(dir: &Path, members: &[&Path]) -> PathBuf {
    let path = dir.join("libhooks.a");
    let mut command = Command::new("ar");
    command.arg("rcs").arg(&path);
    for member in members {
        command.arg(member);
    }
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    path
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
fn forced_root_selects_archive_member_and_transitive_dependency_like_gnu_ld_r() {
    if !have_gnu_tools() {
        return;
    }

    let dir = temp_dir("matched");
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
    let hook = assemble(
        &dir,
        "hook",
        r#".section .text
.globl hook
.type hook,@function
.extern leaf
hook:
    ret
    .quad leaf
.size hook, .-hook
"#,
    );
    let leaf = assemble(
        &dir,
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
    let _library = archive(&dir, &[&hook, &leaf, &unused]);

    let ordinary = dir.join("ordinary.o");
    let ordinary_output = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["partial", "-o"])
        .arg(&ordinary)
        .arg(&start)
        .arg("-L")
        .arg(&dir)
        .arg("-lhooks")
        .output()
        .unwrap();
    assert!(
        ordinary_output.status.success(),
        "{}",
        String::from_utf8_lossy(&ordinary_output.stderr)
    );
    assert!(String::from_utf8_lossy(&ordinary_output.stdout).contains("objects=1"));
    let ordinary_globals = globals(&ordinary);
    assert!(!ordinary_globals.iter().any(|line| line.ends_with(" hook")));

    let ours = dir.join("ours.o");
    let forced = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["partial", "-o"])
        .arg(&ours)
        .args(["-u", "hook"])
        .arg(&start)
        .arg("-L")
        .arg(&dir)
        .arg("-lhooks")
        .output()
        .unwrap();
    assert!(
        forced.status.success(),
        "{}",
        String::from_utf8_lossy(&forced.stderr)
    );
    assert!(String::from_utf8_lossy(&forced.stdout).contains("objects=3"));

    let gnu = dir.join("gnu.o");
    let gnu_output = Command::new("ld")
        .args(["-r", "-u", "hook", "-o"])
        .arg(&gnu)
        .arg(&start)
        .arg("-L")
        .arg(&dir)
        .arg("-lhooks")
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
    assert!(records.iter().any(|line| line.ends_with(" hook")));
    assert!(records.iter().any(|line| line.ends_with(" leaf")));
    assert!(!records.iter().any(|line| line.ends_with(" unused_symbol")));
    assert!(!records.iter().any(|line| line == "U hook"));
    assert!(!records.iter().any(|line| line == "U leaf"));

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
fn unmatched_forced_root_is_preserved_as_global_undefined_like_gnu_ld_r() {
    if !have_gnu_tools() {
        return;
    }

    let dir = temp_dir("unmatched");
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

    let ours = dir.join("ours.o");
    let forced = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["partial", "-o"])
        .arg(&ours)
        .arg("--undefined=missing_root")
        .arg(&start)
        .output()
        .unwrap();
    assert!(
        forced.status.success(),
        "{}",
        String::from_utf8_lossy(&forced.stderr)
    );

    let gnu = dir.join("gnu.o");
    let gnu_output = Command::new("ld")
        .args(["-r", "--undefined=missing_root", "-o"])
        .arg(&gnu)
        .arg(&start)
        .output()
        .unwrap();
    assert!(
        gnu_output.status.success(),
        "{}",
        String::from_utf8_lossy(&gnu_output.stderr)
    );

    assert_eq!(globals(&ours), globals(&gnu));
    assert!(globals(&ours).iter().any(|line| line == "U missing_root"));

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn empty_forced_root_is_rejected_before_input_io() {
    let dir = temp_dir("empty");
    let output_path = dir.join("partial.o");
    let result = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args([
            "partial",
            "-o",
            output_path.to_str().unwrap(),
            "--undefined=",
            "definitely-missing.o",
        ])
        .output()
        .unwrap();

    assert_eq!(result.status.code(), Some(2));
    assert!(result.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&result.stderr).contains("forced undefined symbol cannot be empty")
    );
    assert!(!output_path.exists());

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn forced_root_preserves_same_name_weak_undefined_like_gnu_ld_r() {
    if !have_gnu_tools() {
        return;
    }

    let dir = temp_dir("weak-promotion");
    let object = assemble(
        &dir,
        "weak",
        r#".section .text
.globl _start
.weak optional_hook
.type _start,@function
_start:
    mov $60, %rax
    xor %rdi, %rdi
    syscall
    .quad optional_hook
.size _start, .-_start
"#,
    );
    let ours = dir.join("ours.o");
    let gnu = dir.join("gnu.o");

    let ours_output = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["partial", "-o"])
        .arg(&ours)
        .arg("-uoptional_hook")
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        ours_output.status.success(),
        "{}",
        String::from_utf8_lossy(&ours_output.stderr)
    );

    let gnu_output = Command::new("ld")
        .args(["-r", "-uoptional_hook", "-o"])
        .arg(&gnu)
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        gnu_output.status.success(),
        "{}",
        String::from_utf8_lossy(&gnu_output.stderr)
    );

    assert_eq!(globals(&ours), globals(&gnu));
    let records = globals(&ours);
    assert!(records.iter().any(|line| line == "w optional_hook"));
    assert!(!records.iter().any(|line| line == "U optional_hook"));

    let _ = fs::remove_dir_all(dir);
}
