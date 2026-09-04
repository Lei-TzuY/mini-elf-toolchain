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
        .expect("clock must be after Unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "mini-elf-toolchain-cli-whole-archive-{}-{nonce}",
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

#[test]
fn cli_whole_archive_forces_unindexed_members_like_gnu_ld() {
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
        .args(["rcS", "libextra.a", "helper.o"])
        .status()
        .expect("run GNU ar without symbol index");
    assert!(archive.success(), "GNU ar failed");

    let ordinary = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .current_dir(&dir)
        .args(["link", "-o", "ordinary.out", "start.o", "libextra.a"])
        .output()
        .expect("run ordinary archive link");
    assert!(!ordinary.status.success());
    assert!(String::from_utf8_lossy(&ordinary.stderr).contains("symbol index"));
    assert!(!dir.join("ordinary.out").exists());

    let whole = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .current_dir(&dir)
        .args([
            "link",
            "-o",
            "whole.out",
            "--map",
            "whole.map",
            "start.o",
            "--whole-archive",
            "libextra.a",
            "--no-whole-archive",
        ])
        .output()
        .expect("run whole-archive link");
    assert!(
        whole.status.success(),
        "whole-archive link failed: {}",
        String::from_utf8_lossy(&whole.stderr)
    );
    assert!(String::from_utf8_lossy(&whole.stdout).contains("objects=2"));
    let link_map = fs::read_to_string(dir.join("whole.map")).expect("read link map");
    assert!(link_map.contains("helper"));

    let gnu = Command::new("ld")
        .current_dir(&dir)
        .args([
            "-o",
            "gnu.out",
            "start.o",
            "--whole-archive",
            "libextra.a",
            "--no-whole-archive",
        ])
        .output()
        .expect("run GNU ld whole-archive link");
    assert!(
        gnu.status.success(),
        "GNU ld whole-archive link failed: {}",
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
        .args(["-hW", "whole.out"])
        .output()
        .expect("run GNU readelf");
    assert!(header.status.success());
    let stdout = String::from_utf8_lossy(&header.stdout);
    assert!(stdout.contains("Type:                              EXEC"));
    assert!(stdout.contains("Entry point address:               0x400000"));

    #[cfg(target_os = "linux")]
    {
        let status = Command::new(dir.join("whole.out"))
            .status()
            .expect("execute whole-archive static ELF");
        assert!(
            status.success(),
            "whole-archive executable returned {status}"
        );
    }

    fs::write(dir.join("bad.txt"), b"not an ELF object").expect("write malformed member");
    let bad_archive = Command::new("ar")
        .current_dir(&dir)
        .args(["rcS", "libbad.a", "bad.txt"])
        .status()
        .expect("run GNU ar for malformed-member archive");
    assert!(bad_archive.success());
    let malformed = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .current_dir(&dir)
        .args([
            "link",
            "-o",
            "bad.out",
            "start.o",
            "--whole-archive",
            "libbad.a",
            "--no-whole-archive",
        ])
        .output()
        .expect("run whole-archive malformed-member link");
    assert!(!malformed.status.success());
    let stderr = String::from_utf8_lossy(&malformed.stderr);
    assert!(stderr.contains("archive member"));
    assert!(stderr.contains("ET_REL"));
    assert!(!dir.join("bad.out").exists());

    fs::remove_dir_all(dir).expect("remove temporary test directory");
}
