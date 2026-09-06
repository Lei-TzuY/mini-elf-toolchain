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
        "mini-elf-toolchain-cli-gotpcrel64-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&path).expect("create temporary test directory");
    path
}

fn readelf(path: &Path, args: &[&str]) -> String {
    let output = Command::new("readelf")
        .args(args)
        .arg(path)
        .output()
        .expect("run GNU readelf");
    assert!(output.status.success(), "readelf failed");
    String::from_utf8(output.stdout).expect("readelf output must be UTF-8")
}

#[test]
fn cli_links_gnu_gotpcrel64_through_synthetic_got() {
    if !command_available("as") || !command_available("ld") || !command_available("readelf") {
        return;
    }

    let dir = temp_dir();
    let source = dir.join("start.s");
    let input = dir.join("start.o");
    let mini_output = dir.join("mini-linked");
    let gnu_output = dir.join("gnu-linked");

    fs::write(
        &source,
        ".global _start\n.global target\n.section .text\n_start:\n    mov $60, %rax\n    xor %rdi, %rdi\n    syscall\ntarget:\n    nop\n.section .data\ngot_disp:\n    .quad target@GOTPCREL\n",
    )
    .expect("write assembly input");

    let assembled = Command::new("as")
        .args(["--64", "-o"])
        .arg(&input)
        .arg(&source)
        .status()
        .expect("run GNU as");
    assert!(assembled.success(), "GNU as failed");

    let relocations = readelf(&input, &["-rW"]);
    assert!(
        relocations.contains("R_X86_64_GOTPCREL64"),
        "GNU as did not emit GOTPCREL64:\n{relocations}"
    );

    let mini = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&mini_output)
        .arg(&input)
        .output()
        .expect("run mini-elf-toolchain link");
    assert!(
        mini.status.success(),
        "mini linker failed: {}",
        String::from_utf8_lossy(&mini.stderr)
    );

    let gnu = Command::new("ld")
        .args(["-static", "--no-relax", "-Ttext=0x400000", "-o"])
        .arg(&gnu_output)
        .arg(&input)
        .output()
        .expect("run GNU ld");
    assert!(
        gnu.status.success(),
        "GNU ld failed: {}",
        String::from_utf8_lossy(&gnu.stderr)
    );

    for output in [&mini_output, &gnu_output] {
        let header = readelf(output, &["-hW"]);
        assert!(header.contains("Type:                              EXEC"));
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
