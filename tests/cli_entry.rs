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

fn readelf_entry(path: &Path) -> String {
    let header = Command::new("readelf")
        .args(["-hW"])
        .arg(path)
        .output()
        .expect("run readelf -hW");
    assert!(header.status.success());
    String::from_utf8(header.stdout).expect("readelf output must be UTF-8")
}

#[test]
fn cli_entry_selects_named_symbol_and_matches_gnu_ld() {
    if !command_available("readelf") || !command_available("ld") {
        return;
    }

    let dir = temp_dir();
    let Some(input) = assemble_object(&dir) else {
        let _ = fs::remove_dir_all(dir);
        return;
    };
    let split_output = dir.join("linked-split");
    let attached_output = dir.join("linked-attached");
    let gnu_output = dir.join("linked-gnu");

    for (output, entry_args) in [
        (&split_output, vec!["-e", "custom_entry"]),
        (&attached_output, vec!["-ecustom_entry"]),
    ] {
        let link = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
            .args(["link", "-o"])
            .arg(output)
            .args(entry_args)
            .arg(&input)
            .output()
            .expect("run mini-elf-toolchain link");
        assert!(
            link.status.success(),
            "link failed: {}",
            String::from_utf8_lossy(&link.stderr)
        );
    }

    let gnu_link = Command::new("ld")
        .args(["-static", "-Ttext=0x400000", "-e", "custom_entry", "-o"])
        .arg(&gnu_output)
        .arg(&input)
        .output()
        .expect("run GNU ld");
    assert!(
        gnu_link.status.success(),
        "GNU ld failed: {}",
        String::from_utf8_lossy(&gnu_link.stderr)
    );

    for output in [&split_output, &attached_output, &gnu_output] {
        let header = readelf_entry(output);
        assert!(header.contains("Entry point address:               0x400004"));
    }

    #[cfg(target_os = "linux")]
    for output in [&split_output, &attached_output, &gnu_output] {
        let status = Command::new(output)
            .status()
            .expect("execute linked static ELF");
        assert!(status.success(), "linked executable returned {status}");
    }

    fs::remove_dir_all(dir).expect("remove temporary test directory");
}

#[test]
fn cli_entry_short_forms_reject_malformed_and_duplicate_values_before_io() {
    let binary = env!("CARGO_BIN_EXE_mini-elf-toolchain");

    let missing = Command::new(binary)
        .args(["link", "-o", "never-written", "-e"])
        .output()
        .expect("run missing short entry case");
    assert!(!missing.status.success());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("missing entry symbol after -e"));

    let duplicate = Command::new(binary)
        .args([
            "link",
            "-o",
            "never-written",
            "-ecustom_entry",
            "--entry",
            "other_entry",
            "missing-input.o",
        ])
        .output()
        .expect("run duplicate short entry case");
    assert!(!duplicate.status.success());
    assert!(String::from_utf8_lossy(&duplicate.stderr).contains("duplicate --entry option"));
    assert!(!Path::new("never-written").exists());
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
