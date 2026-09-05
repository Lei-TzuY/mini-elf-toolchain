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
        "mini-elf-toolchain-cli-library-search-{}-{nonce}",
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

fn archive(dir: &Path, output: &Path, members: &[&str]) {
    let mut command = Command::new("ar");
    command.current_dir(dir).args(["rcs"]);
    command.arg(output);
    command.args(members);
    let status = command.status().expect("run GNU ar");
    assert!(status.success(), "GNU ar failed for {}", output.display());
}

#[test]
fn cli_library_search_preserves_group_order_like_gnu_ld() {
    if !have_gnu_toolchain() {
        return;
    }

    let dir = temp_dir();
    let libs = dir.join("libs");
    fs::create_dir(&libs).expect("create library directory");
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
    archive(&dir, &libs.join("liba.a"), &["foo.o", "baz.o"]);
    archive(&dir, &libs.join("libb.a"), &["bar.o"]);

    let linked = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .current_dir(&dir)
        .args([
            "link",
            "-o",
            "searched.out",
            "start.o",
            "-L",
            libs.to_str().expect("UTF-8 library path"),
            "--start-group",
            "-la",
            "-lb",
            "--end-group",
        ])
        .output()
        .expect("run linker with library search");
    assert!(
        linked.status.success(),
        "library-search link failed: {}",
        String::from_utf8_lossy(&linked.stderr)
    );
    assert!(String::from_utf8_lossy(&linked.stdout).contains("objects=4"));

    let gnu = Command::new("ld")
        .current_dir(&dir)
        .args([
            "-o",
            "gnu.out",
            "start.o",
            "-L",
            libs.to_str().expect("UTF-8 library path"),
            "--start-group",
            "-la",
            "-lb",
            "--end-group",
        ])
        .output()
        .expect("run GNU ld with library search");
    assert!(
        gnu.status.success(),
        "GNU ld library-search link failed: {}",
        String::from_utf8_lossy(&gnu.stderr)
    );

    let header = Command::new("readelf")
        .current_dir(&dir)
        .args(["-hW", "searched.out"])
        .output()
        .expect("run GNU readelf");
    assert!(header.status.success());
    let stdout = String::from_utf8_lossy(&header.stdout);
    assert!(stdout.contains("Type:                              EXEC"));
    assert!(stdout.contains("Entry point address:               0x400000"));

    let missing = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .current_dir(&dir)
        .args([
            "link",
            "-o",
            "missing.out",
            "start.o",
            &format!("-L{}", libs.display()),
            "-ldoes_not_exist",
        ])
        .output()
        .expect("run linker with missing library");
    assert!(!missing.status.success());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("libdoes_not_exist.a"));
    assert!(!dir.join("missing.out").exists());

    #[cfg(target_os = "linux")]
    {
        let status = Command::new(dir.join("searched.out"))
            .status()
            .expect("execute searched static ELF");
        assert!(status.success(), "searched executable returned {status}");
    }

    fs::remove_dir_all(dir).expect("remove temporary test directory");
}

#[test]
fn cli_exact_library_search_matches_gnu_ld() {
    if !have_gnu_toolchain() {
        return;
    }

    let dir = temp_dir();
    let libs = dir.join("libs");
    fs::create_dir(&libs).expect("create library directory");
    assemble(
        &dir,
        "start",
        ".globl _start\n.type _start,@function\n_start:\n  call helper\n  mov $60,%rax\n  xor %rdi,%rdi\n  syscall\n",
    );
    assemble(
        &dir,
        "helper",
        ".globl helper\n.type helper,@function\nhelper:\n  ret\n",
    );
    archive(&dir, &libs.join("custom-support.a"), &["helper.o"]);

    let search_path = libs.to_str().expect("UTF-8 library path");
    let linked = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .current_dir(&dir)
        .args([
            "link",
            "-o",
            "exact.out",
            "start.o",
            "-L",
            search_path,
            "-l:custom-support.a",
        ])
        .output()
        .expect("run linker with exact library search");
    assert!(
        linked.status.success(),
        "exact library-search link failed: {}",
        String::from_utf8_lossy(&linked.stderr)
    );
    assert!(String::from_utf8_lossy(&linked.stdout).contains("objects=2"));

    let gnu = Command::new("ld")
        .current_dir(&dir)
        .args([
            "-o",
            "gnu-exact.out",
            "start.o",
            "-L",
            search_path,
            "-l:custom-support.a",
        ])
        .output()
        .expect("run GNU ld with exact library search");
    assert!(
        gnu.status.success(),
        "GNU ld exact library-search link failed: {}",
        String::from_utf8_lossy(&gnu.stderr)
    );

    let header = Command::new("readelf")
        .current_dir(&dir)
        .args(["-hW", "exact.out"])
        .output()
        .expect("run GNU readelf");
    assert!(header.status.success());
    let stdout = String::from_utf8_lossy(&header.stdout);
    assert!(stdout.contains("Type:                              EXEC"));
    assert!(stdout.contains("Entry point address:               0x400000"));

    let missing = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .current_dir(&dir)
        .args([
            "link",
            "-o",
            "missing-exact.out",
            "start.o",
            "-L",
            search_path,
            "-l:missing-custom.a",
        ])
        .output()
        .expect("run linker with missing exact library");
    assert!(!missing.status.success());
    let stderr = String::from_utf8_lossy(&missing.stderr);
    assert!(stderr.contains("missing-custom.a"));
    assert!(!stderr.contains("libmissing-custom.a.a"));
    assert!(!dir.join("missing-exact.out").exists());

    #[cfg(target_os = "linux")]
    {
        let status = Command::new(dir.join("exact.out"))
            .status()
            .expect("execute exact-search static ELF");
        assert!(status.success(), "exact-search executable returned {status}");
    }

    fs::remove_dir_all(dir).expect("remove temporary test directory");
}
