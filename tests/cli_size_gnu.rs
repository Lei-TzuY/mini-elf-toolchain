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
        "mini-elf-toolchain-cli-size-{}-{nonce}",
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

fn contains_size_payload(bytes: &[u8], size: u64) -> bool {
    let mut expected = Vec::new();
    expected.extend_from_slice(&(size as u32).to_le_bytes());
    expected.extend_from_slice(&size.to_le_bytes());
    bytes.windows(expected.len()).any(|window| window == expected)
}

#[test]
fn cli_links_gnu_size32_and_size64_against_resolved_definition_size() {
    if !have_gnu_toolchain() {
        return;
    }

    let dir = temp_dir();
    assemble(
        &dir,
        "start",
        ".globl _start\n.type _start,@function\n_start:\n  mov $60,%rax\n  xor %rdi,%rdi\n  syscall\n  .long helper@SIZE\n  .quad helper@SIZE\n",
    );
    assemble(
        &dir,
        "helper",
        ".globl helper\n.type helper,@function\nhelper:\n  nop\n  nop\n  ret\n.size helper, .-helper\n",
    );

    let relocations = Command::new("readelf")
        .current_dir(&dir)
        .args(["-rW", "start.o"])
        .output()
        .expect("run GNU readelf on relocatable input");
    assert!(relocations.status.success());
    let relocations = String::from_utf8_lossy(&relocations.stdout);
    assert!(relocations.contains("R_X86_64_SIZE32"));
    assert!(relocations.contains("R_X86_64_SIZE64"));

    let linked = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .current_dir(&dir)
        .args(["link", "-o", "ours.out", "start.o", "helper.o"])
        .output()
        .expect("run mini linker");
    assert!(
        linked.status.success(),
        "SIZE relocation link failed: {}",
        String::from_utf8_lossy(&linked.stderr)
    );

    let gnu = Command::new("ld")
        .current_dir(&dir)
        .args(["-o", "gnu.out", "start.o", "helper.o"])
        .output()
        .expect("run GNU ld");
    assert!(
        gnu.status.success(),
        "GNU ld SIZE relocation link failed: {}",
        String::from_utf8_lossy(&gnu.stderr)
    );

    let ours = fs::read(dir.join("ours.out")).expect("read mini-linker output");
    let gnu = fs::read(dir.join("gnu.out")).expect("read GNU output");
    assert!(contains_size_payload(&ours, 3));
    assert!(contains_size_payload(&gnu, 3));

    let header = Command::new("readelf")
        .current_dir(&dir)
        .args(["-hW", "ours.out"])
        .output()
        .expect("run GNU readelf on linked output");
    assert!(header.status.success());
    assert!(String::from_utf8_lossy(&header.stdout).contains("Type:                              EXEC"));

    #[cfg(target_os = "linux")]
    {
        let status = Command::new(dir.join("ours.out"))
            .status()
            .expect("execute linked static ELF");
        assert!(status.success(), "SIZE-relocation executable returned {status}");
    }

    fs::remove_dir_all(dir).expect("remove temporary test directory");
}
