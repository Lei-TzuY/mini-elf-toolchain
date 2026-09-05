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
        "mini-elf-toolchain-cli-image-base-equals-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&path).expect("create temporary test directory");
    path
}

#[test]
fn image_base_equals_matches_gnu_and_rejects_malformed_values_before_output() {
    if !have_gnu_toolchain() {
        return;
    }

    let dir = temp_dir();
    fs::write(
        dir.join("start.s"),
        ".globl _start\n.type _start,@function\n_start:\n  mov $60,%rax\n  xor %rdi,%rdi\n  syscall\n",
    )
    .expect("write assembly source");
    assert!(Command::new("as")
        .current_dir(&dir)
        .args(["--64", "-o", "start.o", "start.s"])
        .status()
        .expect("run GNU as")
        .success());

    let custom = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .current_dir(&dir)
        .args([
            "link",
            "-o",
            "custom.out",
            "--image-base=0x800000",
            "start.o",
        ])
        .output()
        .expect("run mini linker");
    assert!(
        custom.status.success(),
        "mini linker failed: {}",
        String::from_utf8_lossy(&custom.stderr)
    );

    let gnu = Command::new("ld")
        .current_dir(&dir)
        .args(["-o", "gnu.out", "-Ttext", "0x800000", "start.o"])
        .output()
        .expect("run GNU ld");
    assert!(
        gnu.status.success(),
        "GNU ld failed: {}",
        String::from_utf8_lossy(&gnu.stderr)
    );

    for output in ["custom.out", "gnu.out"] {
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

    #[cfg(target_os = "linux")]
    assert!(Command::new(dir.join("custom.out"))
        .status()
        .expect("execute custom output")
        .success());

    for (output, value, expected) in [
        ("empty.out", "--image-base=", "image base cannot be empty"),
        (
            "overflow.out",
            "--image-base=0x10000000000000000",
            "invalid image base",
        ),
    ] {
        let failed = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
            .current_dir(&dir)
            .args(["link", "-o", output, value, "start.o"])
            .output()
            .expect("run malformed equals form");
        assert_eq!(failed.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&failed.stderr).contains(expected));
        assert!(!dir.join(output).exists());
    }

    fs::remove_dir_all(dir).expect("remove temporary test directory");
}
