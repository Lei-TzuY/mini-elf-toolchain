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
        "mini-elf-toolchain-cli-output-equals-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&path).expect("create temporary test directory");
    path
}

fn assemble_object(dir: &Path) -> Option<PathBuf> {
    if !command_available("as") {
        return None;
    }

    let source = dir.join("start.s");
    let object = dir.join("start.o");
    fs::write(
        &source,
        ".global _start\n.section .text\n_start:\n    mov $60, %rax\n    xor %rdi, %rdi\n    syscall\n",
    )
    .expect("write assembly input");

    let status = Command::new("as")
        .args(["--64", "-o"])
        .arg(&object)
        .arg(&source)
        .status()
        .expect("run GNU as");
    assert!(status.success(), "GNU as failed");
    Some(object)
}

fn readelf_header(path: &Path) -> String {
    let output = Command::new("readelf")
        .args(["-hW"])
        .arg(path)
        .output()
        .expect("run GNU readelf");
    assert!(output.status.success(), "readelf failed");
    String::from_utf8(output.stdout).expect("readelf output must be UTF-8")
}

#[test]
fn cli_output_equals_matches_gnu_ld_and_executes() {
    if !command_available("ld") || !command_available("readelf") {
        return;
    }

    let dir = temp_dir();
    let Some(input) = assemble_object(&dir) else {
        let _ = fs::remove_dir_all(dir);
        return;
    };
    let mini_output = dir.join("mini-linked");
    let gnu_output = dir.join("gnu-linked");

    let mini = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .arg("link")
        .arg(format!("--output={}", mini_output.display()))
        .arg(&input)
        .output()
        .expect("run mini-elf-toolchain link");
    assert!(
        mini.status.success(),
        "mini linker failed: {}",
        String::from_utf8_lossy(&mini.stderr)
    );

    let gnu = Command::new("ld")
        .args(["-static", "-Ttext=0x400000"])
        .arg(format!("--output={}", gnu_output.display()))
        .arg(&input)
        .output()
        .expect("run GNU ld");
    assert!(
        gnu.status.success(),
        "GNU ld failed: {}",
        String::from_utf8_lossy(&gnu.stderr)
    );

    for output in [&mini_output, &gnu_output] {
        let header = readelf_header(output);
        assert!(header.contains("Type:                              EXEC"));
        assert!(header.contains("Entry point address:               0x400000"));
    }

    #[cfg(target_os = "linux")]
    for output in [&mini_output, &gnu_output] {
        let status = Command::new(output)
            .status()
            .expect("execute linked static ELF");
        assert!(status.success(), "linked executable returned {status}");
    }

    fs::remove_dir_all(dir).expect("remove temporary test directory");
}

#[test]
fn cli_output_equals_rejects_empty_path_before_input_io() {
    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "--output=", "missing-input.o"])
        .output()
        .expect("run empty output path case");

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("output path cannot be empty"));
}
