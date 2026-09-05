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
        "mini-elf-toolchain-cli-linker-script-sequence-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&path).expect("create temporary test directory");
    path
}

#[test]
fn location_counter_then_text_section_matches_gnu_ld_and_executes() {
    if !have_gnu_toolchain() {
        return;
    }

    let dir = temp_dir();
    fs::write(
        dir.join("start.s"),
        ".globl _start\n.type _start,@function\n_start:\n  mov $60,%rax\n  xor %rdi,%rdi\n  syscall\n",
    )
    .expect("write assembly source");
    fs::write(
        dir.join("sequence.ld"),
        "SECTIONS { . = 0x900000; .text : { *(.text) } }\n",
    )
    .expect("write sequenced linker script");
    fs::write(
        dir.join("overflow.ld"),
        "SECTIONS { . = 0x10000000000000000; .text : { *(.text) } }\n",
    )
    .expect("write overflowing linker script");
    fs::write(
        dir.join("extra.ld"),
        "SECTIONS { . = 0x900000; .text : { *(.text) } .data : { *(.data) } }\n",
    )
    .expect("write unsupported extra-section linker script");

    let assembled = Command::new("as")
        .current_dir(&dir)
        .args(["--64", "-o", "start.o", "start.s"])
        .status()
        .expect("run GNU as");
    assert!(assembled.success());

    let linked = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .current_dir(&dir)
        .args([
            "link",
            "-o",
            "sequence.out",
            "-T",
            "sequence.ld",
            "start.o",
        ])
        .output()
        .expect("run linker with sequenced script");
    assert!(
        linked.status.success(),
        "sequenced linker-script link failed: {}",
        String::from_utf8_lossy(&linked.stderr)
    );

    let gnu = Command::new("ld")
        .current_dir(&dir)
        .args(["-o", "gnu.out", "-T", "sequence.ld", "start.o"])
        .output()
        .expect("run GNU ld with sequenced script");
    assert!(
        gnu.status.success(),
        "GNU ld sequenced script link failed: {}",
        String::from_utf8_lossy(&gnu.stderr)
    );

    for output in ["sequence.out", "gnu.out"] {
        let header = Command::new("readelf")
            .current_dir(&dir)
            .args(["-hW", output])
            .output()
            .expect("run GNU readelf");
        assert!(header.status.success());
        let stdout = String::from_utf8_lossy(&header.stdout);
        assert!(stdout.contains("Type:                              EXEC"));
        assert!(stdout.contains("Entry point address:               0x900000"));
    }

    for (script, output) in [
        ("overflow.ld", "overflow.out"),
        ("extra.ld", "extra.out"),
    ] {
        let rejected = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
            .current_dir(&dir)
            .args(["link", "-o", output, "-T", script, "start.o"])
            .output()
            .expect("run linker with rejected sequenced script");
        assert!(!rejected.status.success());
        assert!(!dir.join(output).exists());
    }

    #[cfg(target_os = "linux")]
    {
        let status = Command::new(dir.join("sequence.out"))
            .status()
            .expect("execute sequenced-script static ELF");
        assert!(status.success(), "sequenced-script executable returned {status}");
    }

    fs::remove_dir_all(dir).expect("remove temporary test directory");
}
