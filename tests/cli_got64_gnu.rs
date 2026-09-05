use std::fs;
use std::path::{Path, PathBuf};
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
        "mini-elf-toolchain-cli-got64-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&path).expect("create temporary test directory");
    path
}

fn assemble(dir: &Path, stem: &str, source: &str) {
    fs::write(dir.join(format!("{stem}.s")), source).expect("write assembly source");
    let output = Command::new("as")
        .current_dir(dir)
        .args(["--64", "-o", &format!("{stem}.o"), &format!("{stem}.s")])
        .output()
        .expect("run GNU as");
    assert!(
        output.status.success(),
        "GNU as failed for {stem}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn cli_builds_static_got_offsets_for_gnu_got64() {
    if !have_gnu_toolchain() {
        return;
    }

    let dir = temp_dir();
    assemble(
        &dir,
        "start",
        ".globl _start\n.type _start,@function\n.extern alpha\n.extern helper\n_start:\n  cmpq $8, helper_got_offset(%rip)\n  jne .Lbad\n  cmpq $0, alpha_got_offset(%rip)\n  jne .Lbad\n  mov $60,%rax\n  xor %rdi,%rdi\n  syscall\n.Lbad:\n  mov $60,%rax\n  mov $1,%rdi\n  syscall\n.section .data\n.align 8\nhelper_got_offset:\n  .quad 0\n  .reloc helper_got_offset, R_X86_64_GOT64, helper\nalpha_got_offset:\n  .quad 0\n  .reloc alpha_got_offset, R_X86_64_GOT64, alpha\n",
    );
    assemble(
        &dir,
        "defs",
        ".globl alpha\n.type alpha,@object\n.data\n.align 8\nalpha:\n  .quad 0x1111\n.size alpha, .-alpha\n.globl helper\n.type helper,@function\n.text\nhelper:\n  ret\n.size helper, .-helper\n",
    );

    let relocations = Command::new("readelf")
        .current_dir(&dir)
        .args(["-rW", "start.o"])
        .output()
        .expect("run GNU readelf on input");
    assert!(relocations.status.success());
    let relocation_stdout = String::from_utf8_lossy(&relocations.stdout);
    assert!(
        relocation_stdout.matches("R_X86_64_GOT64").count() >= 2,
        "assembler did not produce both GOT64 relocations: {relocation_stdout}"
    );

    let ours = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .current_dir(&dir)
        .args(["link", "-o", "ours.out", "start.o", "defs.o"])
        .output()
        .expect("run mini linker");
    assert!(
        ours.status.success(),
        "mini linker failed: {}",
        String::from_utf8_lossy(&ours.stderr)
    );

    let gnu = Command::new("ld")
        .current_dir(&dir)
        .args(["--no-relax", "-o", "gnu.out", "start.o", "defs.o"])
        .output()
        .expect("run GNU ld");
    assert!(
        gnu.status.success(),
        "GNU ld failed: {}",
        String::from_utf8_lossy(&gnu.stderr)
    );

    for output in ["ours.out", "gnu.out"] {
        let header = Command::new("readelf")
            .current_dir(&dir)
            .args(["-hW", output])
            .output()
            .expect("run GNU readelf on output");
        assert!(header.status.success());
        let stdout = String::from_utf8_lossy(&header.stdout);
        assert!(stdout.contains("Type:                              EXEC"));
    }

    #[cfg(target_os = "linux")]
    {
        let status = Command::new(dir.join("ours.out"))
            .status()
            .expect("execute linked GOT64 ELF");
        assert!(status.success(), "GOT64 executable returned {status}");
    }

    fs::remove_dir_all(dir).expect("remove temporary test directory");
}
