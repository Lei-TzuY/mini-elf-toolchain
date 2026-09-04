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
    command_reports("as", "GNU assembler") && command_reports("readelf", "GNU readelf")
}

fn temp_dir() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock must be after Unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "mini-elf-toolchain-cli-relocations-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&path).expect("create temporary test directory");
    path
}

#[test]
fn cli_links_gnu_r_x86_64_32_and_32s_relocations() {
    if !have_gnu_toolchain() {
        return;
    }

    let dir = temp_dir();
    let source = dir.join("absolute32.s");
    let object = dir.join("absolute32.o");
    let output = dir.join("linked");
    fs::write(
        &source,
        ".global _start\n.section .text\n_start:\n    mov $target, %eax\n    mov $target, %rax\n    mov $60, %eax\n    xor %edi, %edi\n    syscall\ntarget:\n    ret\n",
    )
    .expect("write assembly input");

    let assemble = Command::new("as")
        .args(["--64", "-o"])
        .arg(&object)
        .arg(&source)
        .status()
        .expect("run GNU as");
    assert!(assemble.success(), "GNU as failed");

    let relocations = Command::new("readelf")
        .args(["-rW"])
        .arg(&object)
        .output()
        .expect("run GNU readelf -rW");
    assert!(relocations.status.success());
    let relocation_stdout = String::from_utf8_lossy(&relocations.stdout);
    assert!(
        relocation_stdout.contains("R_X86_64_32 "),
        "GNU as fixture did not contain R_X86_64_32: {relocation_stdout}"
    );
    assert!(
        relocation_stdout.contains("R_X86_64_32S"),
        "GNU as fixture did not contain R_X86_64_32S: {relocation_stdout}"
    );

    let link = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&output)
        .arg(&object)
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
        .expect("run GNU readelf -hW");
    assert!(header.status.success());
    assert!(String::from_utf8_lossy(&header.stdout)
        .contains("Entry point address:               0x400000"));

    #[cfg(target_os = "linux")]
    {
        let status = Command::new(&output)
            .status()
            .expect("execute linked static ELF");
        assert!(status.success(), "linked executable returned {status}");
    }

    fs::remove_dir_all(dir).expect("remove temporary test directory");
}
