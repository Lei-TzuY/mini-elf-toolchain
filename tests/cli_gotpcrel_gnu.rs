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
        "mini-elf-toolchain-cli-gotpcrel-{}-{nonce}",
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
fn cli_builds_static_got_for_gnu_gotpcrel_family() {
    if !have_gnu_toolchain() {
        return;
    }

    let dir = temp_dir();
    assemble(
        &dir,
        "start",
        ".globl _start\n.type _start,@function\n.extern helper\n_start:\n  .byte 0x48,0x8b,0x05\n.Lgotdisp:\n  .long 0\n  .reloc .Lgotdisp, R_X86_64_REX_GOTPCRELX, helper-4\n  lea helper(%rip),%rcx\n  cmp %rcx,%rax\n  jne .Lbad\n  mov $60,%rax\n  xor %rdi,%rdi\n  syscall\n.Lbad:\n  mov $60,%rax\n  mov $1,%rdi\n  syscall\n.Lplain_gotpcrelx:\n  .long 0\n  .reloc .Lplain_gotpcrelx, R_X86_64_GOTPCRELX, helper-4\n",
    );
    assemble(
        &dir,
        "helper",
        ".globl helper\n.type helper,@function\nhelper:\n  ret\n.size helper, .-helper\n",
    );

    let relocations = Command::new("readelf")
        .current_dir(&dir)
        .args(["-rW", "start.o"])
        .output()
        .expect("run GNU readelf on input");
    assert!(relocations.status.success());
    let relocation_stdout = String::from_utf8_lossy(&relocations.stdout);
    assert!(
        relocation_stdout.contains("R_X86_64_REX_GOTPCRELX"),
        "assembler did not produce REX_GOTPCRELX: {relocation_stdout}"
    );
    assert!(
        relocation_stdout.contains("R_X86_64_GOTPCRELX"),
        "assembler did not produce GOTPCRELX: {relocation_stdout}"
    );

    let ours = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .current_dir(&dir)
        .args(["link", "-o", "ours.out", "start.o", "helper.o"])
        .output()
        .expect("run mini linker");
    assert!(
        ours.status.success(),
        "mini linker failed: {}",
        String::from_utf8_lossy(&ours.stderr)
    );

    let gnu = Command::new("ld")
        .current_dir(&dir)
        .args(["--no-relax", "-o", "gnu.out", "start.o", "helper.o"])
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
            .expect("execute linked GOTPCREL-family ELF");
        assert!(
            status.success(),
            "GOTPCREL-family executable returned {status}"
        );
    }

    fs::remove_dir_all(dir).expect("remove temporary test directory");
}
