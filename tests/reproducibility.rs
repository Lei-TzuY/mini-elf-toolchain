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

fn have_gnu_archive_toolchain() -> bool {
    command_reports("ar", "GNU ar")
        && command_reports("as", "GNU assembler")
        && command_reports("objcopy", "GNU objcopy")
}

fn temp_dir() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock must be after Unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "mini-elf-toolchain-reproducibility-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&path).expect("create temporary test directory");
    path
}

fn assemble_object(dir: &Path, stem: &str, source_text: &str) -> PathBuf {
    let source = dir.join(format!("{stem}.s"));
    let assembled = dir.join(format!("{stem}-all.o"));
    let stripped = dir.join(format!("{stem}.o"));
    fs::write(&source, source_text).expect("write assembly input");

    let as_status = Command::new("as")
        .args(["--64", "-o"])
        .arg(&assembled)
        .arg(&source)
        .status()
        .expect("run GNU as");
    assert!(as_status.success(), "GNU as failed for {stem}");

    let objcopy_status = Command::new("objcopy")
        .args(["--remove-section=.data", "--remove-section=.bss"])
        .arg(&assembled)
        .arg(&stripped)
        .status()
        .expect("run GNU objcopy");
    assert!(objcopy_status.success(), "GNU objcopy failed for {stem}");

    stripped
}

fn make_archive(dir: &Path, member: &Path) -> PathBuf {
    let archive = dir.join("libhelper.a");
    let status = Command::new("ar")
        .args(["rcs"])
        .arg(&archive)
        .arg(member)
        .status()
        .expect("run GNU ar");
    assert!(status.success(), "GNU ar failed");
    archive
}

fn run_link(input: &Path, archive: &Path, output: &Path, map: &Path) {
    let link = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(output)
        .args(["--map"])
        .arg(map)
        .arg(input)
        .arg(archive)
        .output()
        .expect("run mini-elf-toolchain link");
    assert!(
        link.status.success(),
        "link failed: {}",
        String::from_utf8_lossy(&link.stderr)
    );
}

#[test]
fn repeated_static_links_are_byte_for_byte_reproducible() {
    if !have_gnu_archive_toolchain() {
        return;
    }

    let dir = temp_dir();
    let start = assemble_object(
        &dir,
        "start",
        ".global _start\n.extern helper\n.section .text\n_start:\n    .quad helper\n    mov $60, %rax\n    xor %rdi, %rdi\n    syscall\n",
    );
    let helper = assemble_object(
        &dir,
        "helper",
        ".global helper\n.section .text\nhelper:\n    ret\n",
    );
    let archive = make_archive(&dir, &helper);

    let output_a = dir.join("linked-a");
    let output_b = dir.join("linked-b");
    let map_a = dir.join("linked-a.map");
    let map_b = dir.join("linked-b.map");

    run_link(&start, &archive, &output_a, &map_a);
    run_link(&start, &archive, &output_b, &map_b);

    assert_eq!(
        fs::read(&output_a).expect("read first executable"),
        fs::read(&output_b).expect("read second executable"),
        "identical ordered inputs must emit identical executable bytes"
    );
    assert_eq!(
        fs::read(&map_a).expect("read first link map"),
        fs::read(&map_b).expect("read second link map"),
        "identical ordered inputs must emit identical link maps"
    );

    fs::remove_dir_all(dir).expect("remove temporary test directory");
}
