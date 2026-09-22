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

fn have_gnu_archive_tools() -> bool {
    command_reports("as", "GNU assembler")
        && command_reports("ar", "GNU ar")
        && command_reports("nm", "GNU nm")
}

fn have_link_tools() -> bool {
    have_gnu_archive_tools()
        && command_reports("objcopy", "GNU objcopy")
        && command_reports("readelf", "GNU readelf")
}

fn temp_dir(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after Unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "mini-elf-toolchain-ar-create-{label}-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&path).unwrap();
    path
}

fn assemble(dir: &Path, stem: &str, source: &str) -> PathBuf {
    let asm = dir.join(format!("{stem}.s"));
    let object = dir.join(format!("{stem}.o"));
    fs::write(&asm, source).unwrap();
    let status = Command::new("as")
        .args(["--64", "-o"])
        .arg(&object)
        .arg(&asm)
        .status()
        .unwrap();
    assert!(status.success(), "GNU as failed for {stem}");
    object
}

fn assemble_link_object(dir: &Path, stem: &str, source: &str) -> PathBuf {
    let assembled = assemble(dir, &format!("{stem}-all"), source);
    let object = dir.join(format!("{stem}.o"));
    let status = Command::new("objcopy")
        .args(["--remove-section=.data", "--remove-section=.bss"])
        .arg(&assembled)
        .arg(&object)
        .status()
        .unwrap();
    assert!(status.success(), "GNU objcopy failed for {stem}");
    object
}

#[test]
fn creates_indexed_archive_recognized_by_gnu_tools() {
    if !have_gnu_archive_tools() {
        return;
    }

    let dir = temp_dir("gnu");
    let short = assemble(
        &dir,
        "short",
        ".globl short_symbol\n.section .text\nshort_symbol:\n  ret\n",
    );
    let long = assemble(
        &dir,
        "very_long_archive_member_name",
        ".globl long_symbol\n.section .text\nlong_symbol:\n  ret\n",
    );
    let archive = dir.join("libcreated.a");

    let create = Command::new(env!("CARGO_BIN_EXE_mini-elf-ar"))
        .args(["rcs"])
        .arg(&archive)
        .arg(&short)
        .arg(&long)
        .output()
        .unwrap();
    assert!(
        create.status.success(),
        "{}",
        String::from_utf8_lossy(&create.stderr)
    );
    assert!(create.stdout.is_empty());

    let listing = Command::new("ar")
        .arg("t")
        .arg(&archive)
        .output()
        .unwrap();
    assert!(listing.status.success());
    assert_eq!(
        listing.stdout,
        b"short.o\nvery_long_archive_member_name.o\n"
    );

    let ours = Command::new(env!("CARGO_BIN_EXE_mini-elf-armap"))
        .arg(&archive)
        .output()
        .unwrap();
    let gnu = Command::new("nm")
        .arg("-s")
        .arg(&archive)
        .output()
        .unwrap();
    assert!(
        ours.status.success(),
        "{}",
        String::from_utf8_lossy(&ours.stderr)
    );
    assert!(gnu.status.success(), "{}", String::from_utf8_lossy(&gnu.stderr));
    let gnu_stdout = String::from_utf8_lossy(&gnu.stdout);
    let gnu_index = gnu_stdout
        .split("\n\n")
        .next()
        .expect("GNU nm should print an archive index");
    assert_eq!(String::from_utf8_lossy(&ours.stdout).trim_end(), gnu_index);
    let map = String::from_utf8_lossy(&ours.stdout);
    assert!(map.contains("short_symbol in short.o"));
    assert!(map.contains("long_symbol in very_long_archive_member_name.o"));

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn created_archive_lazy_links_through_toolchain() {
    if !have_link_tools() {
        return;
    }

    let dir = temp_dir("link");
    let start = assemble_link_object(
        &dir,
        "start",
        ".globl _start\n.extern helper\n.section .text\n_start:\n  mov $60, %rax\n  xor %rdi, %rdi\n  syscall\n  .quad helper\n",
    );
    let helper = assemble_link_object(
        &dir,
        "helper",
        ".globl helper\n.section .text\nhelper:\n  ret\n",
    );
    let archive = dir.join("libhelper.a");

    let create = Command::new(env!("CARGO_BIN_EXE_mini-elf-ar"))
        .args(["rcs"])
        .arg(&archive)
        .arg(&helper)
        .output()
        .unwrap();
    assert!(
        create.status.success(),
        "{}",
        String::from_utf8_lossy(&create.stderr)
    );

    let executable = dir.join("linked");
    let link = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&executable)
        .arg(&start)
        .arg(&archive)
        .output()
        .unwrap();
    assert!(
        link.status.success(),
        "{}",
        String::from_utf8_lossy(&link.stderr)
    );
    assert!(String::from_utf8_lossy(&link.stdout).contains("objects=2"));

    let readelf = Command::new("readelf")
        .args(["-hW"])
        .arg(&executable)
        .output()
        .unwrap();
    assert!(readelf.status.success());
    assert!(String::from_utf8_lossy(&readelf.stdout).contains("Type:                              EXEC"));

    #[cfg(target_os = "linux")]
    {
        let status = Command::new(&executable).status().unwrap();
        assert!(status.success(), "created-archive executable returned {status}");
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn creation_is_deterministic() {
    if !command_reports("as", "GNU assembler") {
        return;
    }

    let dir = temp_dir("deterministic");
    let member = assemble(
        &dir,
        "member",
        ".globl exported\n.section .text\nexported:\n  ret\n",
    );
    let first = dir.join("first.a");
    let second = dir.join("second.a");

    for archive in [&first, &second] {
        let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-ar"))
            .args(["rcs"])
            .arg(archive)
            .arg(&member)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    assert_eq!(fs::read(&first).unwrap(), fs::read(&second).unwrap());
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn invalid_later_member_fails_before_creating_archive() {
    if !command_reports("as", "GNU assembler") {
        return;
    }

    let dir = temp_dir("invalid");
    let valid = assemble(
        &dir,
        "valid",
        ".globl valid_symbol\n.section .text\nvalid_symbol:\n  ret\n",
    );
    let invalid = dir.join("invalid.o");
    fs::write(&invalid, b"not an ELF object").unwrap();
    let archive = dir.join("should-not-exist.a");

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-ar"))
        .args(["rcs"])
        .arg(&archive)
        .arg(&valid)
        .arg(&invalid)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid.o"));
    assert!(!archive.exists());

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn refuses_to_replace_existing_archive() {
    let dir = temp_dir("existing");
    let archive = dir.join("existing.a");
    fs::write(&archive, b"keep").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-ar"))
        .args(["rcs"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("refusing to overwrite"));
    assert_eq!(fs::read(&archive).unwrap(), b"keep");

    let _ = fs::remove_dir_all(dir);
}
