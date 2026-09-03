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
        "mini-elf-toolchain-cli-link-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&path).expect("create temporary test directory");
    path
}

fn assemble_minimal_start(dir: &Path) -> Option<PathBuf> {
    if !command_available("as") || !command_available("objcopy") {
        return None;
    }

    let source = dir.join("start.s");
    let assembled = dir.join("start-all.o");
    let stripped = dir.join("start.o");
    fs::write(
        &source,
        ".global _start\n.section .text\n_start:\n    mov $60, %rax\n    xor %rdi, %rdi\n    syscall\n",
    )
    .expect("write assembly input");

    let as_status = Command::new("as")
        .args(["--64", "-o"])
        .arg(&assembled)
        .arg(&source)
        .status()
        .expect("run GNU as");
    assert!(as_status.success(), "GNU as failed");

    let objcopy_status = Command::new("objcopy")
        .args(["--remove-section=.data", "--remove-section=.bss"])
        .arg(&assembled)
        .arg(&stripped)
        .status()
        .expect("run GNU objcopy");
    assert!(objcopy_status.success(), "GNU objcopy failed");

    Some(stripped)
}

#[test]
fn cli_links_gnu_object_and_readelf_accepts_result() {
    if !command_available("readelf") {
        return;
    }

    let dir = temp_dir();
    let Some(input) = assemble_minimal_start(&dir) else {
        let _ = fs::remove_dir_all(dir);
        return;
    };
    let output = dir.join("linked");

    let link = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&output)
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
    let header_stdout = String::from_utf8_lossy(&header.stdout);
    assert!(header_stdout.contains("Type:                              EXEC"));
    assert!(
        header_stdout.contains("Machine:                           Advanced Micro Devices X86-64")
    );
    assert!(header_stdout.contains("Entry point address:               0x400000"));

    let program_headers = Command::new("readelf")
        .args(["-lW"])
        .arg(&output)
        .output()
        .expect("run readelf -lW");
    assert!(program_headers.status.success());
    let program_stdout = String::from_utf8_lossy(&program_headers.stdout);
    assert!(program_stdout.lines().any(|line| {
        line.contains("LOAD") && line.contains("0x0000000000400000") && line.contains("R E")
    }));

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
fn cli_link_reports_non_relocatable_input_without_writing_output() {
    let dir = temp_dir();
    let input = dir.join("bad.o");
    let output = dir.join("linked");
    fs::write(&input, b"not an elf").expect("write malformed input");

    let link = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&output)
        .arg(&input)
        .output()
        .expect("run mini-elf-toolchain link");

    assert!(!link.status.success());
    assert!(!output.exists());
    let stderr = String::from_utf8_lossy(&link.stderr);
    assert!(stderr.contains("error:"));
    assert!(stderr.contains("bad.o"));

    fs::remove_dir_all(dir).expect("remove temporary test directory");
}
