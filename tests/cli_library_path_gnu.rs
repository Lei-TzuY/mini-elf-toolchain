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
        "mini-elf-toolchain-library-path-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&path).expect("create temporary test directory");
    path
}

fn assemble(dir: &Path, name: &str, source: &str) -> PathBuf {
    let source_path = dir.join(format!("{name}.s"));
    let object_path = dir.join(format!("{name}.o"));
    fs::write(&source_path, source).expect("write assembly input");
    let status = Command::new("as")
        .args(["--64", "-o"])
        .arg(&object_path)
        .arg(&source_path)
        .status()
        .expect("run GNU assembler");
    assert!(status.success(), "assembler failed for {name}");
    object_path
}

#[test]
fn library_path_equals_matches_gnu_archive_search_and_executes() {
    if !["as", "ar", "ld", "nm", "readelf"]
        .into_iter()
        .all(command_available)
    {
        return;
    }

    let dir = temp_dir();
    let lib_dir = dir.join("lib");
    fs::create_dir_all(&lib_dir).expect("create library directory");

    let start = assemble(
        &dir,
        "start",
        ".global _start\n.extern helper\n.section .text\n_start:\n    call helper\n    mov $60, %rax\n    xor %rdi, %rdi\n    syscall\n",
    );
    let helper = assemble(
        &dir,
        "helper",
        ".global helper\n.section .text\nhelper:\n    ret\n",
    );
    let archive = lib_dir.join("libhelper.a");
    let ar_status = Command::new("ar")
        .arg("rcs")
        .arg(&archive)
        .arg(&helper)
        .status()
        .expect("run GNU ar");
    assert!(ar_status.success(), "GNU ar failed");

    let ours = dir.join("ours");
    let library_path = format!("--library-path={}", lib_dir.display());
    let link = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&ours)
        .arg(&library_path)
        .arg(&start)
        .arg("-lhelper")
        .output()
        .expect("run mini-elf-toolchain link");
    assert!(
        link.status.success(),
        "mini linker failed: {}",
        String::from_utf8_lossy(&link.stderr)
    );

    let gnu = dir.join("gnu");
    let gnu_link = Command::new("ld")
        .args(["-o"])
        .arg(&gnu)
        .arg(&library_path)
        .arg(&start)
        .arg("-lhelper")
        .output()
        .expect("run GNU ld");
    assert!(
        gnu_link.status.success(),
        "GNU ld failed: {}",
        String::from_utf8_lossy(&gnu_link.stderr)
    );

    for output in [&ours, &gnu] {
        let header = Command::new("readelf")
            .args(["-hW"])
            .arg(output)
            .output()
            .expect("run readelf");
        assert!(header.status.success());
        assert!(String::from_utf8_lossy(&header.stdout).contains("Type:                              EXEC"));

        let symbols = Command::new("nm")
            .arg(output)
            .output()
            .expect("run nm");
        assert!(symbols.status.success());
        assert!(String::from_utf8_lossy(&symbols.stdout).contains(" helper"));
    }

    #[cfg(target_os = "linux")]
    {
        for output in [&ours, &gnu] {
            let status = Command::new(output)
                .status()
                .expect("execute linked static ELF");
            assert!(status.success(), "linked executable returned {status}");
        }
    }

    fs::remove_dir_all(dir).expect("remove temporary test directory");
}
