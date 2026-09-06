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

fn have_gnu_toolchain() -> bool {
    command_reports("ar", "GNU ar")
        && command_reports("as", "GNU assembler")
        && command_reports("ld", "GNU ld")
        && command_reports("readelf", "GNU readelf")
}

fn temp_dir() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock must be after Unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "mini-elf-toolchain-cli-nested-archive-group-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&path).expect("create temporary test directory");
    path
}

fn assemble(dir: &Path, stem: &str, source: &str) {
    fs::write(dir.join(format!("{stem}.s")), source).expect("write assembly source");
    let status = Command::new("as")
        .current_dir(dir)
        .args(["--64", "-o", &format!("{stem}.o"), &format!("{stem}.s")])
        .status()
        .expect("run GNU as");
    assert!(status.success(), "GNU as failed for {stem}");
}

fn archive(dir: &Path, name: &str, members: &[&str]) {
    let mut command = Command::new("ar");
    command.current_dir(dir).args(["rcs", name]);
    command.args(members);
    let status = command.status().expect("run GNU ar");
    assert!(status.success(), "GNU ar failed for {name}");
}

#[test]
fn cli_nested_archive_groups_match_gnu_fixpoint_semantics() {
    if !have_gnu_toolchain() {
        return;
    }

    let dir = temp_dir();
    assemble(
        &dir,
        "start",
        ".globl _start\n.type _start,@function\n_start:\n  mov $60,%rax\n  xor %rdi,%rdi\n  syscall\n  .quad foo\n",
    );
    assemble(
        &dir,
        "foo",
        ".globl foo\n.type foo,@function\nfoo:\n  ret\n  .quad bar\n",
    );
    assemble(
        &dir,
        "bar",
        ".globl bar\n.type bar,@function\nbar:\n  ret\n  .quad baz\n",
    );
    assemble(
        &dir,
        "baz",
        ".globl baz\n.type baz,@function\nbaz:\n  ret\n",
    );
    archive(&dir, "liba.a", &["foo.o", "baz.o"]);
    archive(&dir, "libb.a", &["bar.o"]);

    let nested = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .current_dir(&dir)
        .args([
            "link",
            "-o",
            "nested.out",
            "start.o",
            "--start-group",
            "liba.a",
            "--start-group",
            "libb.a",
            "--end-group",
            "--end-group",
        ])
        .output()
        .expect("run linker with nested archive groups");
    assert!(
        nested.status.success(),
        "nested grouped link failed: {}",
        String::from_utf8_lossy(&nested.stderr)
    );
    assert!(String::from_utf8_lossy(&nested.stdout).contains("objects=4"));

    let gnu = Command::new("ld")
        .current_dir(&dir)
        .args([
            "-o",
            "gnu.out",
            "start.o",
            "--start-group",
            "liba.a",
            "--start-group",
            "libb.a",
            "--end-group",
            "--end-group",
        ])
        .output()
        .expect("run GNU ld with nested archive groups");
    assert!(
        gnu.status.success(),
        "GNU ld nested grouped link failed: {}",
        String::from_utf8_lossy(&gnu.stderr)
    );

    for output in ["nested.out", "gnu.out"] {
        let header = Command::new("readelf")
            .current_dir(&dir)
            .args(["-hW", output])
            .output()
            .expect("run GNU readelf");
        assert!(header.status.success());
        let stdout = String::from_utf8_lossy(&header.stdout);
        assert!(stdout.contains("Type:                              EXEC"));
    }

    #[cfg(target_os = "linux")]
    for output in ["nested.out", "gnu.out"] {
        let status = Command::new(dir.join(output))
            .status()
            .expect("execute nested-group static ELF");
        assert!(status.success(), "{output} returned {status}");
    }

    fs::remove_dir_all(dir).expect("remove temporary test directory");
}
