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
        "mini-elf-toolchain-partial-group-{label}-{}-{nonce}",
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

fn archive(dir: &Path, name: &str, members: &[&Path]) -> PathBuf {
    let path = dir.join(name);
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

struct Fixture {
    start: PathBuf,
    first: PathBuf,
    second: PathBuf,
}

fn build_fixture(dir: &Path) -> Fixture {
    let start = assemble(
        dir,
        "start",
        r#".section .text
.globl _start
.type _start,@function
.extern foo
_start:
    mov $60, %rax
    xor %rdi, %rdi
    syscall
    .quad foo
.size _start, .-_start
"#,
    );
    let foo = assemble(
        dir,
        "foo",
        r#".section .text
.globl foo
.type foo,@function
.extern bar
foo:
    ret
    .quad bar
.size foo, .-foo
"#,
    );
    let baz = assemble(
        dir,
        "baz",
        r#".section .text
.globl baz
.type baz,@function
baz:
    ret
.size baz, .-baz
"#,
    );
    let bar = assemble(
        dir,
        "bar",
        r#".section .text
.globl bar
.type bar,@function
.extern baz
bar:
    ret
    .quad baz
.size bar, .-bar
"#,
    );

    Fixture {
        start,
        first: archive(dir, "libfirst.a", &[&foo, &baz]),
        second: archive(dir, "libsecond.a", &[&bar]),
    }
}

#[test]
fn archive_group_rescans_to_resolve_circular_partial_dependencies_like_gnu_ld_r() {
    if !have_gnu_tools() {
        return;
    }

    let dir = temp_dir("rescan");
    let fixture = build_fixture(&dir);
    let ours = dir.join("ours.o");
    let gnu = dir.join("gnu.o");

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["partial", "-o"])
        .arg(&ours)
        .arg(&fixture.start)
        .arg("--start-group")
        .arg(&fixture.first)
        .arg(&fixture.second)
        .arg("--end-group")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("objects=4"));

    let gnu_output = Command::new("ld")
        .args(["-r", "-o"])
        .arg(&gnu)
        .arg(&fixture.start)
        .arg("--start-group")
        .arg(&fixture.first)
        .arg(&fixture.second)
        .arg("--end-group")
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
    assert!(records.iter().any(|line| line.ends_with(" foo")));
    assert!(records.iter().any(|line| line.ends_with(" bar")));
    assert!(records.iter().any(|line| line.ends_with(" baz")));
    assert!(!records.iter().any(|line| line == "U baz"));

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
fn without_group_earlier_archive_is_not_retroactively_rescanned() {
    if !have_gnu_tools() {
        return;
    }

    let dir = temp_dir("no-group");
    let fixture = build_fixture(&dir);
    let ours = dir.join("ours-no-group.o");
    let gnu = dir.join("gnu-no-group.o");

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["partial", "-o"])
        .arg(&ours)
        .arg(&fixture.start)
        .arg(&fixture.first)
        .arg(&fixture.second)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let gnu_output = Command::new("ld")
        .args(["-r", "-o"])
        .arg(&gnu)
        .arg(&fixture.start)
        .arg(&fixture.first)
        .arg(&fixture.second)
        .output()
        .unwrap();
    assert!(
        gnu_output.status.success(),
        "{}",
        String::from_utf8_lossy(&gnu_output.stderr)
    );

    assert_eq!(globals(&ours), globals(&gnu));
    let records = globals(&ours);
    assert!(records.iter().any(|line| line == "U baz"));

    let final_path = dir.join("should-not-link");
    let final_output = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&final_path)
        .arg(&ours)
        .output()
        .unwrap();
    assert!(!final_output.status.success());
    assert!(!final_path.exists());

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn nested_partial_archive_groups_fail_before_output() {
    let dir = temp_dir("nested");
    let output_path = dir.join("partial.o");
    let result = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args([
            "partial",
            "-o",
            output_path.to_str().unwrap(),
            "--start-group",
            "--start-group",
            "--end-group",
            "--end-group",
        ])
        .output()
        .unwrap();

    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert!(String::from_utf8_lossy(&result.stderr)
        .contains("nested --start-group is not supported"));
    assert!(!output_path.exists());

    let _ = fs::remove_dir_all(dir);
}
