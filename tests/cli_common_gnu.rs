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
        && command_reports("nm", "GNU nm")
        && command_reports("readelf", "GNU readelf")
}

fn temp_dir() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock must be after Unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "mini-elf-toolchain-cli-common-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&path).expect("create temporary test directory");
    path
}

fn assemble(dir: &Path, stem: &str, source: &str) {
    fs::write(dir.join(format!("{stem}.s")), source).expect("write assembly source");
    let status = Command::new("as")
        .current_dir(dir)
        .args(["--64", "-o", &format!("{stem}.o"), &format!("{stem}.s")])
        .status()
        .expect("run GNU as");
    assert!(status.success(), "GNU as failed for {stem}");
}

#[test]
fn cli_allocates_and_relocates_gnu_common_symbols() {
    if !have_gnu_toolchain() {
        return;
    }

    let dir = temp_dir();
    assemble(
        &dir,
        "start",
        ".globl _start\n.type _start,@function\n.comm shared,8,8\n_start:\n  lea shared(%rip),%rax\n  movq $0x1234,(%rax)\n  mov $60,%rax\n  xor %rdi,%rdi\n  syscall\n",
    );
    assemble(
        &dir,
        "common",
        ".comm shared,32,32\n.comm extra,4,4\n",
    );

    let input_symbols = Command::new("readelf")
        .current_dir(&dir)
        .args(["-sW", "start.o"])
        .output()
        .expect("run GNU readelf on common input");
    assert!(input_symbols.status.success());
    let input_symbols = String::from_utf8_lossy(&input_symbols.stdout);
    assert!(input_symbols.contains("COM"));
    assert!(input_symbols.contains("shared"));

    let linked = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .current_dir(&dir)
        .args([
            "link",
            "-o",
            "ours.out",
            "--map",
            "ours.map",
            "start.o",
            "common.o",
        ])
        .output()
        .expect("run common-symbol linker");
    assert!(
        linked.status.success(),
        "common-symbol link failed: {}",
        String::from_utf8_lossy(&linked.stderr)
    );

    let link_map = fs::read_to_string(dir.join("ours.map")).expect("read link map");
    let shared_line = link_map
        .lines()
        .find(|line| line.ends_with(" shared"))
        .expect("shared symbol in link map");
    assert!(shared_line.contains("0x0000000000000020"));
    let extra_line = link_map
        .lines()
        .find(|line| line.ends_with(" extra"))
        .expect("extra symbol in link map");
    assert!(extra_line.contains("0x0000000000000004"));

    let program_headers = Command::new("readelf")
        .current_dir(&dir)
        .args(["-lW", "ours.out"])
        .output()
        .expect("run GNU readelf on linked executable");
    assert!(program_headers.status.success());
    assert!(String::from_utf8_lossy(&program_headers.stdout).contains(" RW "));

    let gnu = Command::new("ld")
        .current_dir(&dir)
        .args(["-o", "gnu.out", "start.o", "common.o"])
        .output()
        .expect("run GNU ld");
    assert!(
        gnu.status.success(),
        "GNU ld common-symbol link failed: {}",
        String::from_utf8_lossy(&gnu.stderr)
    );

    let nm = Command::new("nm")
        .current_dir(&dir)
        .args(["-S", "gnu.out"])
        .output()
        .expect("run GNU nm");
    assert!(nm.status.success());
    let nm = String::from_utf8_lossy(&nm.stdout);
    assert!(nm.lines().any(|line| line.contains("0000000000000020 B shared")));
    assert!(nm.lines().any(|line| line.contains("0000000000000004 B extra")));

    #[cfg(target_os = "linux")]
    {
        let status = Command::new(dir.join("ours.out"))
            .status()
            .expect("execute common-symbol static ELF");
        assert!(status.success(), "common-symbol executable returned {status}");
    }

    fs::remove_dir_all(dir).expect("remove temporary test directory");
}
