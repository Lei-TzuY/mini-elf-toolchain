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

fn have_toolchain() -> bool {
    command_reports("llvm-ar", "LLVM")
        && command_reports("as", "GNU assembler")
        && command_reports("readelf", "GNU readelf")
}

fn temp_dir() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock must be after Unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "mini-elf-toolchain-cli-bsd-archive-{}-{nonce}",
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
fn cli_whole_archive_links_llvm_bsd_extended_member_name() {
    if !have_toolchain() {
        return;
    }

    let dir = temp_dir();
    assemble(
        &dir,
        "start",
        ".globl _start\n.type _start,@function\n_start:\n  mov $60,%rax\n  xor %rdi,%rdi\n  syscall\n",
    );
    let long_stem = "long_member_name_helper";
    assemble(
        &dir,
        long_stem,
        ".globl helper\n.type helper,@function\nhelper:\n  ret\n",
    );

    let archive = Command::new("llvm-ar")
        .current_dir(&dir)
        .args([
            "--format=bsd",
            "rcS",
            "libbsd.a",
            &format!("{long_stem}.o"),
        ])
        .output()
        .expect("run llvm-ar");
    assert!(
        archive.status.success(),
        "llvm-ar BSD archive creation failed: {}",
        String::from_utf8_lossy(&archive.stderr)
    );

    let listing = Command::new("llvm-ar")
        .current_dir(&dir)
        .args(["t", "libbsd.a"])
        .output()
        .expect("list BSD archive");
    assert!(listing.status.success());
    assert_eq!(
        String::from_utf8_lossy(&listing.stdout).trim(),
        format!("{long_stem}.o")
    );

    let linked = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .current_dir(&dir)
        .args([
            "link",
            "-o",
            "bsd.out",
            "--map",
            "bsd.map",
            "start.o",
            "--whole-archive",
            "libbsd.a",
            "--no-whole-archive",
        ])
        .output()
        .expect("link BSD archive");
    assert!(
        linked.status.success(),
        "BSD whole-archive link failed: {}",
        String::from_utf8_lossy(&linked.stderr)
    );
    assert!(String::from_utf8_lossy(&linked.stdout).contains("objects=2"));
    let map = fs::read_to_string(dir.join("bsd.map")).expect("read link map");
    assert!(map.contains("helper"));

    let header = Command::new("readelf")
        .current_dir(&dir)
        .args(["-hW", "bsd.out"])
        .output()
        .expect("run GNU readelf");
    assert!(header.status.success());
    let stdout = String::from_utf8_lossy(&header.stdout);
    assert!(stdout.contains("Type:                              EXEC"));
    assert!(stdout.contains("Entry point address:               0x400000"));

    #[cfg(target_os = "linux")]
    {
        let status = Command::new(dir.join("bsd.out"))
            .status()
            .expect("execute BSD whole-archive output");
        assert!(status.success(), "BSD archive executable returned {status}");
    }

    fs::remove_dir_all(dir).expect("remove temporary test directory");
}
