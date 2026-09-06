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
    command_reports("ar", "GNU ar")
        && command_reports("as", "GNU assembler")
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
        "mini-elf-toolchain-cli-push-pop-state-{}-{nonce}",
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

fn archive(dir: &Path, name: &str, object: &str) {
    let status = Command::new("ar")
        .current_dir(dir)
        .args(["rcs", name, object])
        .status()
        .expect("run GNU ar");
    assert!(status.success(), "GNU ar failed for {name}");
}

#[test]
fn cli_push_pop_state_scopes_whole_archive_like_gnu_ld() {
    if !have_gnu_toolchain() {
        return;
    }

    let dir = temp_dir();
    assemble(
        &dir,
        "start",
        ".globl _start\n.type _start,@function\n_start:\n  mov $60,%rax\n  xor %rdi,%rdi\n  syscall\n",
    );
    assemble(
        &dir,
        "forced",
        ".globl forced_marker\n.type forced_marker,@function\nforced_marker:\n  ret\n",
    );
    assemble(
        &dir,
        "lazy",
        ".globl lazy_marker\n.type lazy_marker,@function\nlazy_marker:\n  ret\n",
    );
    archive(&dir, "libforced.a", "forced.o");
    archive(&dir, "liblazy.a", "lazy.o");

    let mini = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .current_dir(&dir)
        .args([
            "link",
            "-o",
            "mini.out",
            "--map",
            "mini.map",
            "start.o",
            "--push-state",
            "--whole-archive",
            "libforced.a",
            "--pop-state",
            "liblazy.a",
        ])
        .output()
        .expect("run mini linker");
    assert!(
        mini.status.success(),
        "mini linker failed: {}",
        String::from_utf8_lossy(&mini.stderr)
    );
    assert!(String::from_utf8_lossy(&mini.stdout).contains("objects=2"));

    let mini_map = fs::read_to_string(dir.join("mini.map")).expect("read mini link map");
    assert!(mini_map.contains("forced_marker"));
    assert!(!mini_map.contains("lazy_marker"));

    let gnu = Command::new("ld")
        .current_dir(&dir)
        .args([
            "-o",
            "gnu.out",
            "start.o",
            "--push-state",
            "--whole-archive",
            "libforced.a",
            "--pop-state",
            "liblazy.a",
        ])
        .output()
        .expect("run GNU ld");
    assert!(
        gnu.status.success(),
        "GNU ld failed: {}",
        String::from_utf8_lossy(&gnu.stderr)
    );

    let nm = Command::new("nm")
        .current_dir(&dir)
        .arg("gnu.out")
        .output()
        .expect("run GNU nm");
    assert!(nm.status.success());
    let symbols = String::from_utf8_lossy(&nm.stdout);
    assert!(symbols.contains(" forced_marker"));
    assert!(!symbols.contains(" lazy_marker"));

    for output in ["mini.out", "gnu.out"] {
        let header = Command::new("readelf")
            .current_dir(&dir)
            .args(["-hW", output])
            .output()
            .expect("run GNU readelf");
        assert!(header.status.success());
        assert!(String::from_utf8_lossy(&header.stdout)
            .contains("Type:                              EXEC"));
    }

    #[cfg(target_os = "linux")]
    for output in ["mini.out", "gnu.out"] {
        let status = Command::new(dir.join(output))
            .status()
            .expect("execute static ELF");
        assert!(status.success(), "{output} returned {status}");
    }

    fs::remove_dir_all(dir).expect("remove temporary test directory");
}
