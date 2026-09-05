use std::fs;
use std::path::PathBuf;
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
    command_reports("as", "GNU assembler")
        && command_reports("ld", "GNU ld")
        && command_reports("readelf", "GNU readelf")
}

fn temp_dir() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock must be after Unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "mini-elf-toolchain-cli-linker-script-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&path).expect("create temporary test directory");
    path
}

#[test]
fn bounded_linker_script_image_base_matches_gnu_ld_and_executes() {
    if !have_gnu_toolchain() {
        return;
    }

    let dir = temp_dir();
    fs::write(
        dir.join("start.s"),
        ".globl _start\n.type _start,@function\n_start:\n  mov $60,%rax\n  xor %rdi,%rdi\n  syscall\n",
    )
    .expect("write assembly source");
    fs::write(dir.join("base.ld"), "SECTIONS { . = 0x800000; }\n").expect("write linker script");
    fs::write(
        dir.join("overflow.ld"),
        "SECTIONS { . = 0x10000000000000000; }\n",
    )
    .expect("write overflowing linker script");
    fs::write(dir.join("second.ld"), "SECTIONS { . = 0x900000; }\n")
        .expect("write second linker script");

    let assembled = Command::new("as")
        .current_dir(&dir)
        .args(["--64", "-o", "start.o", "start.s"])
        .status()
        .expect("run GNU as");
    assert!(assembled.success());

    let linked = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .current_dir(&dir)
        .args(["link", "-o", "script.out", "-T", "base.ld", "start.o"])
        .output()
        .expect("run linker with bounded linker script");
    assert!(
        linked.status.success(),
        "bounded script link failed: {}",
        String::from_utf8_lossy(&linked.stderr)
    );

    let gnu = Command::new("ld")
        .current_dir(&dir)
        .args(["-o", "gnu.out", "-T", "base.ld", "start.o"])
        .output()
        .expect("run GNU ld with linker script");
    assert!(
        gnu.status.success(),
        "GNU ld script link failed: {}",
        String::from_utf8_lossy(&gnu.stderr)
    );

    for output in ["script.out", "gnu.out"] {
        let header = Command::new("readelf")
            .current_dir(&dir)
            .args(["-hW", output])
            .output()
            .expect("run GNU readelf");
        assert!(header.status.success());
        let stdout = String::from_utf8_lossy(&header.stdout);
        assert!(stdout.contains("Type:                              EXEC"));
        assert!(stdout.contains("Entry point address:               0x800000"));
    }

    let overflow = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .current_dir(&dir)
        .args([
            "link",
            "-o",
            "overflow.out",
            "--script",
            "overflow.ld",
            "start.o",
        ])
        .output()
        .expect("run linker with overflowing script");
    assert!(!overflow.status.success());
    assert!(String::from_utf8_lossy(&overflow.stderr).contains("unsigned 64-bit"));
    assert!(!dir.join("overflow.out").exists());

    let conflict = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .current_dir(&dir)
        .args([
            "link",
            "-o",
            "conflict.out",
            "--image-base",
            "0x800000",
            "-T",
            "base.ld",
            "start.o",
        ])
        .output()
        .expect("run linker with conflicting image-base sources");
    assert!(!conflict.status.success());
    assert!(String::from_utf8_lossy(&conflict.stderr).contains("cannot combine --image-base"));
    assert!(!dir.join("conflict.out").exists());

    let duplicate = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .current_dir(&dir)
        .args([
            "link",
            "-o",
            "duplicate.out",
            "-T",
            "base.ld",
            "--script",
            "second.ld",
            "start.o",
        ])
        .output()
        .expect("run linker with duplicate scripts");
    assert!(!duplicate.status.success());
    assert!(String::from_utf8_lossy(&duplicate.stderr).contains("duplicate -T/--script"));
    assert!(!dir.join("duplicate.out").exists());

    #[cfg(target_os = "linux")]
    {
        let status = Command::new(dir.join("script.out"))
            .status()
            .expect("execute script-linked static ELF");
        assert!(
            status.success(),
            "script-linked executable returned {status}"
        );
    }

    fs::remove_dir_all(dir).expect("remove temporary test directory");
}
