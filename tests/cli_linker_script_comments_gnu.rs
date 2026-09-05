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
        "mini-elf-toolchain-cli-linker-script-comments-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&path).expect("create temporary test directory");
    path
}

fn entry_address(dir: &std::path::Path, output: &str) -> String {
    let header = Command::new("readelf")
        .current_dir(dir)
        .args(["-hW", output])
        .output()
        .expect("run GNU readelf");
    assert!(header.status.success());
    let stdout = String::from_utf8_lossy(&header.stdout);
    assert!(stdout.contains("Type:                              EXEC"));
    stdout
        .lines()
        .find_map(|line| line.strip_prefix("  Entry point address:               "))
        .expect("readelf entry point line")
        .to_owned()
}

#[test]
fn c_style_linker_script_comments_match_gnu_ld_and_execute() {
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
        dir.join("comments.ld"),
        "/* header */\nENTRY(/* before */ _start /* after */)\nSECTIONS {\n  /* base */ . = 0x900000;\n  .text : { *(/* selector */ .text .text.*) } /* output */\n}\n/* tail */\n",
    )
    .expect("write commented linker script");
    fs::write(
        dir.join("unterminated.ld"),
        "SECTIONS { . = 0x900000; /* unterminated\n",
    )
    .expect("write malformed linker script");

    let assembled = Command::new("as")
        .current_dir(&dir)
        .args(["--64", "-o", "start.o", "start.s"])
        .status()
        .expect("run GNU as");
    assert!(assembled.success());

    let ours = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .current_dir(&dir)
        .args([
            "link",
            "-o",
            "ours.out",
            "--script",
            "comments.ld",
            "start.o",
        ])
        .output()
        .expect("run linker with commented script");
    assert!(
        ours.status.success(),
        "commented script link failed: {}",
        String::from_utf8_lossy(&ours.stderr)
    );

    let gnu = Command::new("ld")
        .current_dir(&dir)
        .args(["-o", "gnu.out", "-T", "comments.ld", "start.o"])
        .output()
        .expect("run GNU ld with commented script");
    assert!(
        gnu.status.success(),
        "GNU ld commented script failed: {}",
        String::from_utf8_lossy(&gnu.stderr)
    );

    assert_eq!(entry_address(&dir, "ours.out"), "0x900000");
    assert_eq!(entry_address(&dir, "gnu.out"), "0x900000");

    let malformed = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .current_dir(&dir)
        .args([
            "link",
            "-o",
            "malformed.out",
            "-Tunterminated.ld",
            "start.o",
        ])
        .output()
        .expect("run linker with unterminated comment");
    assert!(!malformed.status.success());
    assert!(String::from_utf8_lossy(&malformed.stderr)
        .contains("unterminated linker-script comment"));
    assert!(!dir.join("malformed.out").exists());

    #[cfg(target_os = "linux")]
    {
        let status = Command::new(dir.join("ours.out"))
            .status()
            .expect("execute commented-script static ELF");
        assert!(status.success(), "commented-script executable returned {status}");
    }

    fs::remove_dir_all(dir).expect("remove temporary test directory");
}
