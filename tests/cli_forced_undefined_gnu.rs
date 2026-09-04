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
        && command_reports("nm", "GNU nm")
        && command_reports("readelf", "GNU readelf")
}

fn temp_dir() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "mini-elf-toolchain-cli-forced-undefined-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&path).expect("create temp directory");
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

#[test]
fn cli_forced_undefined_extracts_otherwise_unused_archive_member_like_gnu_ld() {
    if !have_gnu_toolchain() {
        return;
    }

    let dir = temp_dir();
    assemble(
        &dir,
        "start",
        ".globl _start\n.type _start,@function\n_start:\n  mov $60,%rax\n  xor %rdi,%rdi\n  syscall\n",
    );
    assemble(
        &dir,
        "helper",
        ".globl helper\n.type helper,@function\nhelper:\n  ret\n",
    );
    let archive = Command::new("ar")
        .current_dir(&dir)
        .args(["rcs", "libextra.a", "helper.o"])
        .status()
        .expect("run GNU ar");
    assert!(archive.success());

    let plain = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .current_dir(&dir)
        .args(["link", "-o", "plain.out", "--map", "plain.map", "start.o", "libextra.a"])
        .output()
        .expect("run plain link");
    assert!(plain.status.success());
    assert!(String::from_utf8_lossy(&plain.stdout).contains("objects=1"));
    let plain_map = fs::read_to_string(dir.join("plain.map")).expect("read plain map");
    assert!(!plain_map.contains("helper"));

    let forced = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .current_dir(&dir)
        .args([
            "link",
            "-o",
            "forced.out",
            "--map",
            "forced.map",
            "-uhelper",
            "start.o",
            "libextra.a",
        ])
        .output()
        .expect("run forced link");
    assert!(
        forced.status.success(),
        "forced link failed: {}",
        String::from_utf8_lossy(&forced.stderr)
    );
    assert!(String::from_utf8_lossy(&forced.stdout).contains("objects=2"));
    let forced_map = fs::read_to_string(dir.join("forced.map")).expect("read forced map");
    assert!(forced_map.contains("helper"));

    let long_form = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .current_dir(&dir)
        .args([
            "link",
            "-o",
            "long.out",
            "--undefined",
            "helper",
            "start.o",
            "libextra.a",
        ])
        .output()
        .expect("run long forced link");
    assert!(long_form.status.success());
    assert!(String::from_utf8_lossy(&long_form.stdout).contains("objects=2"));

    let gnu = Command::new("ld")
        .current_dir(&dir)
        .args(["-o", "gnu.out", "-u", "helper", "start.o", "libextra.a"])
        .output()
        .expect("run GNU ld");
    assert!(
        gnu.status.success(),
        "GNU ld failed: {}",
        String::from_utf8_lossy(&gnu.stderr)
    );
    let nm = Command::new("nm")
        .current_dir(&dir)
        .arg("gnu.out")
        .output()
        .expect("run GNU nm");
    assert!(nm.status.success());
    assert!(String::from_utf8_lossy(&nm.stdout).contains(" helper"));

    let header = Command::new("readelf")
        .current_dir(&dir)
        .args(["-hW", "forced.out"])
        .output()
        .expect("run GNU readelf");
    assert!(header.status.success());
    let header = String::from_utf8_lossy(&header.stdout);
    assert!(header.contains("Type:                              EXEC"));
    assert!(header.contains("Entry point address:               0x400000"));

    #[cfg(target_os = "linux")]
    {
        let status = Command::new(dir.join("forced.out"))
            .status()
            .expect("execute forced-link ELF");
        assert!(status.success(), "forced executable returned {status}");
    }

    fs::remove_dir_all(dir).expect("remove temp directory");
}
