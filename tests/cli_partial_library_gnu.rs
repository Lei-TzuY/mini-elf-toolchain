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
        "mini-elf-toolchain-partial-library-{label}-{}-{nonce}",
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

fn archive(path: &Path, members: &[&Path]) {
    let mut command = Command::new("ar");
    command.arg("rcs").arg(path);
    for member in members {
        command.arg(member);
    }
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
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

fn start_object(dir: &Path, symbol: &str) -> PathBuf {
    assemble(
        dir,
        "start",
        &format!(
            ".section .text\n.globl _start\n.type _start,@function\n.extern {symbol}\n_start:\n  mov $60, %rax\n  xor %rdi, %rdi\n  syscall\n  .quad {symbol}\n.size _start, .-_start\n"
        ),
    )
}

#[test]
fn partial_library_search_matches_gnu_first_path_and_exact_name_semantics() {
    if !have_gnu_tools() {
        return;
    }

    let dir = temp_dir("search");
    let first_dir = dir.join("first");
    let second_dir = dir.join("second");
    fs::create_dir_all(&first_dir).unwrap();
    fs::create_dir_all(&second_dir).unwrap();

    let start = start_object(&dir, "helper");
    let first_member = assemble(
        &dir,
        "first-helper",
        ".text\n.globl helper\n.globl first_marker\nhelper:\nfirst_marker:\n  ret\n",
    );
    let second_member = assemble(
        &dir,
        "second-helper",
        ".text\n.globl helper\n.globl second_marker\nhelper:\nsecond_marker:\n  ret\n",
    );
    archive(&first_dir.join("libchoice.a"), &[&first_member]);
    archive(&second_dir.join("libchoice.a"), &[&second_member]);

    let exact_member = assemble(
        &dir,
        "exact-helper",
        ".text\n.globl exact_helper\n.globl exact_marker\nexact_helper:\nexact_marker:\n  ret\n",
    );
    archive(&first_dir.join("custom-support.a"), &[&exact_member]);

    let ours = dir.join("ours.o");
    let gnu = dir.join("gnu.o");

    let ours_output = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["partial", "-o"])
        .arg(&ours)
        .arg(&start)
        .arg("-L")
        .arg(&first_dir)
        .arg(format!("-L{}", second_dir.display()))
        .arg("-lchoice")
        .output()
        .unwrap();
    assert!(
        ours_output.status.success(),
        "{}",
        String::from_utf8_lossy(&ours_output.stderr)
    );

    let gnu_output = Command::new("ld")
        .args(["-r", "-o"])
        .arg(&gnu)
        .arg(&start)
        .arg("-L")
        .arg(&first_dir)
        .arg(format!("-L{}", second_dir.display()))
        .arg("-lchoice")
        .output()
        .unwrap();
    assert!(
        gnu_output.status.success(),
        "{}",
        String::from_utf8_lossy(&gnu_output.stderr)
    );

    assert_eq!(globals(&ours), globals(&gnu));
    let records = globals(&ours);
    assert!(records.iter().any(|line| line.ends_with(" first_marker")));
    assert!(!records.iter().any(|line| line.ends_with(" second_marker")));

    let exact_start = start_object(&dir, "exact_helper");
    let exact = dir.join("exact.o");
    let exact_output = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["partial", "-o"])
        .arg(&exact)
        .arg(&exact_start)
        .arg("--library-path")
        .arg(&first_dir)
        .arg("--library=:custom-support.a")
        .output()
        .unwrap();
    assert!(
        exact_output.status.success(),
        "{}",
        String::from_utf8_lossy(&exact_output.stderr)
    );
    assert!(globals(&exact)
        .iter()
        .any(|line| line.ends_with(" exact_marker")));

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn library_search_composes_with_partial_archive_groups_and_final_linking() {
    if !have_gnu_tools() {
        return;
    }

    let dir = temp_dir("group");
    let libdir = dir.join("lib");
    fs::create_dir_all(&libdir).unwrap();

    let start = start_object(&dir, "first_entry");
    let first_entry = assemble(
        &dir,
        "first-entry",
        ".text\n.globl first_entry\n.extern second_entry\nfirst_entry:\n  ret\n  .quad second_entry\n",
    );
    let first_tail = assemble(
        &dir,
        "first-tail",
        ".text\n.globl first_tail\nfirst_tail:\n  ret\n",
    );
    let second_entry = assemble(
        &dir,
        "second-entry",
        ".text\n.globl second_entry\n.extern first_tail\nsecond_entry:\n  ret\n  .quad first_tail\n",
    );
    archive(&libdir.join("libfirst.a"), &[&first_entry, &first_tail]);
    archive(&libdir.join("libsecond.a"), &[&second_entry]);

    let ours = dir.join("ours.o");
    let gnu = dir.join("gnu.o");

    let ours_output = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["partial", "-o"])
        .arg(&ours)
        .arg(&start)
        .arg("-L")
        .arg(&libdir)
        .arg("--start-group")
        .arg("-lfirst")
        .arg("-lsecond")
        .arg("--end-group")
        .output()
        .unwrap();
    assert!(
        ours_output.status.success(),
        "{}",
        String::from_utf8_lossy(&ours_output.stderr)
    );
    assert!(String::from_utf8_lossy(&ours_output.stdout).contains("objects=4"));

    let gnu_output = Command::new("ld")
        .args(["-r", "-o"])
        .arg(&gnu)
        .arg(&start)
        .arg("-L")
        .arg(&libdir)
        .arg("--start-group")
        .arg("-lfirst")
        .arg("-lsecond")
        .arg("--end-group")
        .output()
        .unwrap();
    assert!(
        gnu_output.status.success(),
        "{}",
        String::from_utf8_lossy(&gnu_output.stderr)
    );
    assert_eq!(globals(&ours), globals(&gnu));

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
fn missing_partial_library_fails_before_output() {
    let dir = temp_dir("missing");
    let output = dir.join("missing.o");
    let result = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["partial", "-o"])
        .arg(&output)
        .arg("-L")
        .arg(&dir)
        .arg("-lmissing")
        .output()
        .unwrap();

    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert!(String::from_utf8_lossy(&result.stderr).contains("libmissing.a"));
    assert!(!output.exists());

    let _ = fs::remove_dir_all(dir);
}
