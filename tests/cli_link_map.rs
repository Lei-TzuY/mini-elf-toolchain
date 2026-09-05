use std::fs;
use std::path::PathBuf;
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
        "mini-elf-toolchain-cli-link-map-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&path).expect("create temporary test directory");
    path
}

fn assemble_start(dir: &std::path::Path) -> PathBuf {
    let source = dir.join("start.s");
    let assembled = dir.join("start-all.o");
    let input = dir.join("start.o");

    fs::write(
        &source,
        ".global _start\n.section .text\n_start:\n    mov $60, %rax\n    xor %rdi, %rdi\n    syscall\n",
    )
    .expect("write assembly input");
    assert!(Command::new("as")
        .args(["--64", "-o"])
        .arg(&assembled)
        .arg(&source)
        .status()
        .expect("run GNU as")
        .success());
    assert!(Command::new("objcopy")
        .args(["--remove-section=.data", "--remove-section=.bss"])
        .arg(&assembled)
        .arg(&input)
        .status()
        .expect("run GNU objcopy")
        .success());

    input
}

#[test]
fn cli_writes_deterministic_link_map_for_gnu_object() {
    if !command_available("as") || !command_available("objcopy") {
        return;
    }

    let dir = temp_dir();
    let input = assemble_start(&dir);
    let output = dir.join("linked");
    let map = dir.join("linked.map");

    let link = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&output)
        .arg("--map")
        .arg(&map)
        .arg(&input)
        .output()
        .expect("run mini-elf-toolchain link");
    assert!(
        link.status.success(),
        "link failed: {}",
        String::from_utf8_lossy(&link.stderr)
    );

    let rendered = fs::read_to_string(&map).expect("read link map");
    assert!(rendered.starts_with("ENTRY _start 0x0000000000400000\nSECTIONS\n"));
    assert!(rendered.contains("obj=0"));
    assert!(rendered.contains("SYMBOLS\n"));
    assert!(rendered.contains("bind=1 obj=0"));
    assert!(rendered.contains(" _start\n"));
    assert!(rendered.contains("SEGMENTS\n"));
    assert!(rendered.contains("vaddr=0x0000000000400000"));
    assert!(rendered.contains(" RX\n"));

    fs::remove_dir_all(dir).expect("remove temporary test directory");
}

#[test]
fn attached_map_form_matches_gnu_cli_semantics() {
    if !command_available("as")
        || !command_available("objcopy")
        || !command_available("ld")
        || !command_available("readelf")
    {
        return;
    }

    let dir = temp_dir();
    let input = assemble_start(&dir);
    let ours = dir.join("ours");
    let ours_map = dir.join("ours.map");
    let gnu = dir.join("gnu");
    let gnu_map = dir.join("gnu.map");

    let ours_link = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&ours)
        .arg(format!("-Map={}", ours_map.display()))
        .arg(&input)
        .output()
        .expect("run mini-elf-toolchain link");
    assert!(
        ours_link.status.success(),
        "link failed: {}",
        String::from_utf8_lossy(&ours_link.stderr)
    );

    let gnu_link = Command::new("ld")
        .arg("-o")
        .arg(&gnu)
        .arg(format!("-Map={}", gnu_map.display()))
        .arg(&input)
        .output()
        .expect("run GNU ld");
    assert!(
        gnu_link.status.success(),
        "GNU ld failed: {}",
        String::from_utf8_lossy(&gnu_link.stderr)
    );

    for executable in [&ours, &gnu] {
        let header = Command::new("readelf")
            .args(["-h"])
            .arg(executable)
            .output()
            .expect("run GNU readelf");
        assert!(header.status.success());
        let header = String::from_utf8_lossy(&header.stdout);
        assert!(header.contains("Type:                              EXEC"));
    }

    let ours_rendered = fs::read_to_string(&ours_map).expect("read our link map");
    let gnu_rendered = fs::read_to_string(&gnu_map).expect("read GNU link map");
    assert!(ours_rendered.contains("_start"));
    assert!(gnu_rendered.contains("_start"));

    #[cfg(target_os = "linux")]
    {
        assert!(Command::new(&ours).status().expect("run our executable").success());
        assert!(Command::new(&gnu).status().expect("run GNU executable").success());
    }

    fs::remove_dir_all(dir).expect("remove temporary test directory");
}
