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

#[test]
fn cli_writes_deterministic_link_map_for_gnu_object() {
    if !command_available("as") || !command_available("objcopy") {
        return;
    }

    let dir = temp_dir();
    let source = dir.join("start.s");
    let assembled = dir.join("start-all.o");
    let input = dir.join("start.o");
    let output = dir.join("linked");
    let map = dir.join("linked.map");

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
