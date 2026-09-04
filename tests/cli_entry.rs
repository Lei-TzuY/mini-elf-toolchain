use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn command_available(program: &str) -> bool {
    Command::new(program).arg("--version").output().is_ok()
}

fn temp_dir() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock must be after Unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "mini-elf-toolchain-cli-entry-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&path).expect("create temporary test directory");
    path
}

fn assemble_object(dir: &Path) -> Option<PathBuf> {
    if !command_available("as") || !command_available("objcopy") {
        return None;
    }

    let source = dir.join("entry.s");
    let assembled = dir.join("entry-all.o");
    let stripped = dir.join("entry.o");
    fs::write(
        &source,
        ".global custom_entry\n.section .text\n.byte 0x90, 0x90, 0x90, 0x90\ncustom_entry:\n    mov $60, %rax\n    xor %rdi, %rdi\n    syscall\n",
    )
    .expect("write assembly input");

    let as_status = Command::new("as")
        .args(["--64", "-o"])
        .arg(&assembled)
        .arg(&source)
        .status()
        .expect("run assembler");
    assert!(as_status.success(), "assembler failed");

    let objcopy_status = Command::new("objcopy")
        .args(["--remove-section=.data", "--remove-section=.bss"])
        .arg(&assembled)
        .arg(&stripped)
        .status()
        .expect("run objcopy");
    assert!(objcopy_status.success(), "objcopy failed");

    Some(stripped)
}

#[test]
fn cli_entry_selects_named_symbol_and_matches_gnu_readelf() {
    if !command_available("readelf") {
        return;
    }

    let dir = temp_dir();
    let Some(input) = assemble_object(&dir) else {
        let _ = fs::remove_dir_all(dir);
        return;
    };
    let output = dir.join("linked");

    let link = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&output)
        .args(["--entry", "custom_entry"])
        .arg(&input)
        .output()
        .expect("run mini-elf-toolchain link");
    assert!(
        link.status.success(),
        "link failed: {}",
        String::from_utf8_lossy(&link.stderr)
    );

    let header = Command::new("readelf")
        .args(["-hW"])
        .arg(&output)
        .output()
        .expect("run readelf -hW");
    assert!(header.status.success());
    assert!(String::from_utf8_lossy(&header.stdout)
        .contains("Entry point address:               0x400004"));

    #[cfg(target_os = "linux")]
    {
        let status = Command::new(&output)
            .status()
            .expect("execute linked static ELF");
        assert!(status.success(), "linked executable returned {status}");
    }

    fs::remove_dir_all(dir).expect("remove temporary test directory");
}

#[test]
fn cli_entry_reports_missing_symbol_without_writing_output() {
    let dir = temp_dir();
    let Some(input) = assemble_object(&dir) else {
        let _ = fs::remove_dir_all(dir);
        return;
    };
    let output = dir.join("linked-missing");

    let link = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&output)
        .args(["--entry", "does_not_exist"])
        .arg(&input)
        .output()
        .expect("run mini-elf-toolchain link");

    assert!(!link.status.success());
    assert!(!output.exists());
    assert!(String::from_utf8_lossy(&link.stderr).contains("does_not_exist"));

    fs::remove_dir_all(dir).expect("remove temporary test directory");
}
