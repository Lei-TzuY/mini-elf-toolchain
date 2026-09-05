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
        "mini-elf-toolchain-cli-linker-script-entry-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&path).expect("create temporary test directory");
    path
}

fn read_entry(dir: &std::path::Path, output: &str) -> String {
    let header = Command::new("readelf")
        .current_dir(dir)
        .args(["-hW", output])
        .output()
        .expect("run GNU readelf");
    assert!(header.status.success());
    String::from_utf8_lossy(&header.stdout)
        .lines()
        .find_map(|line| line.strip_prefix("  Entry point address:               "))
        .expect("readelf entry point line")
        .to_owned()
}

#[test]
fn linker_script_entry_matches_gnu_and_cli_entry_overrides_it() {
    if !have_gnu_toolchain() {
        return;
    }

    let dir = temp_dir();
    fs::write(
        dir.join("start.s"),
        ".globl _start\n.type _start,@function\n_start:\n  mov $60,%rax\n  mov $1,%rdi\n  syscall\n.org 0x40\n.globl custom_entry\n.type custom_entry,@function\ncustom_entry:\n  mov $60,%rax\n  xor %rdi,%rdi\n  syscall\n",
    )
    .expect("write assembly source");
    fs::write(
        dir.join("entry.ld"),
        "ENTRY(custom_entry)\nSECTIONS { . = 0x800000; }\n",
    )
    .expect("write linker script");
    fs::write(
        dir.join("bad-entry.ld"),
        "ENTRY(two words)\nSECTIONS { . = 0x800000; }\n",
    )
    .expect("write malformed linker script");

    let assembled = Command::new("as")
        .current_dir(&dir)
        .args(["--64", "-o", "start.o", "start.s"])
        .status()
        .expect("run GNU as");
    assert!(assembled.success());

    let linked = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .current_dir(&dir)
        .args(["link", "-o", "custom.out", "-T", "entry.ld", "start.o"])
        .output()
        .expect("run mini linker with ENTRY script");
    assert!(
        linked.status.success(),
        "ENTRY script link failed: {}",
        String::from_utf8_lossy(&linked.stderr)
    );

    let gnu = Command::new("ld")
        .current_dir(&dir)
        .args(["-o", "gnu.out", "-T", "entry.ld", "start.o"])
        .output()
        .expect("run GNU ld with ENTRY script");
    assert!(
        gnu.status.success(),
        "GNU ld ENTRY script failed: {}",
        String::from_utf8_lossy(&gnu.stderr)
    );

    assert_eq!(read_entry(&dir, "custom.out"), "0x800040");
    assert_eq!(read_entry(&dir, "gnu.out"), "0x800040");

    #[cfg(target_os = "linux")]
    {
        let status = Command::new(dir.join("custom.out"))
            .status()
            .expect("execute ENTRY-selected output");
        assert!(status.success(), "ENTRY-selected executable returned {status}");
    }

    let override_linked = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .current_dir(&dir)
        .args([
            "link",
            "-o",
            "override.out",
            "--entry",
            "_start",
            "-T",
            "entry.ld",
            "start.o",
        ])
        .output()
        .expect("run mini linker with CLI entry override");
    assert!(
        override_linked.status.success(),
        "CLI entry override failed: {}",
        String::from_utf8_lossy(&override_linked.stderr)
    );

    let gnu_override = Command::new("ld")
        .current_dir(&dir)
        .args(["-o", "gnu-override.out", "-e", "_start", "-T", "entry.ld", "start.o"])
        .output()
        .expect("run GNU ld with CLI entry override");
    assert!(gnu_override.status.success());
    assert_eq!(read_entry(&dir, "override.out"), "0x800000");
    assert_eq!(read_entry(&dir, "gnu-override.out"), "0x800000");

    #[cfg(target_os = "linux")]
    {
        let status = Command::new(dir.join("override.out"))
            .status()
            .expect("execute CLI-overridden output");
        assert_eq!(status.code(), Some(1));
    }

    let invalid = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .current_dir(&dir)
        .args([
            "link",
            "-o",
            "bad.out",
            "--script",
            "bad-entry.ld",
            "start.o",
        ])
        .output()
        .expect("run linker with malformed ENTRY script");
    assert!(!invalid.status.success());
    assert!(String::from_utf8_lossy(&invalid.stderr).contains("ENTRY expects exactly one symbol token"));
    assert!(!dir.join("bad.out").exists());

    fs::remove_dir_all(dir).expect("remove temporary test directory");
}
