use std::fs;
use std::process::Command;

fn temp_path(name: &str) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!("mini-elf-nm-{name}-{}", std::process::id()));
    path
}

#[test]
fn just_symbols_matches_gnu_nm_for_real_object() {
    if Command::new("as").arg("--version").output().is_err()
        || Command::new("nm").arg("--version").output().is_err()
    {
        return;
    }

    let source = temp_path("just-symbols.s");
    let object = temp_path("just-symbols.o");
    fs::write(
        &source,
        ".globl beta\n.globl alpha\n.text\nalpha:\n  nop\nbeta:\n  ret\n",
    )
    .unwrap();
    assert!(Command::new("as")
        .arg("-o")
        .arg(&object)
        .arg(&source)
        .status()
        .unwrap()
        .success());

    let gnu = Command::new("nm").arg("-j").arg(&object).output().unwrap();
    assert!(gnu.status.success());
    let ours = Command::new(env!("CARGO_BIN_EXE_mini-elf-nm"))
        .arg("-j")
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        ours.status.success(),
        "{}",
        String::from_utf8_lossy(&ours.stderr)
    );
    assert_eq!(ours.stdout, gnu.stdout);

    let long = Command::new(env!("CARGO_BIN_EXE_mini-elf-nm"))
        .arg("--just-symbols")
        .arg(&object)
        .output()
        .unwrap();
    assert!(long.status.success());
    assert_eq!(long.stdout, gnu.stdout);

    let _ = fs::remove_file(source);
    let _ = fs::remove_file(object);
}

#[test]
fn just_symbols_keeps_stdout_atomic_for_malformed_input() {
    let good_source = temp_path("just-symbols-good.s");
    let good_object = temp_path("just-symbols-good.o");
    let bad = temp_path("just-symbols-bad.o");
    if Command::new("as").arg("--version").output().is_err() {
        return;
    }
    fs::write(&good_source, ".globl alpha\n.text\nalpha:\n  ret\n").unwrap();
    assert!(Command::new("as")
        .arg("-o")
        .arg(&good_object)
        .arg(&good_source)
        .status()
        .unwrap()
        .success());
    fs::write(&bad, b"\x7fELF").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-nm"))
        .arg("--just-symbols")
        .arg(&good_object)
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());

    let _ = fs::remove_file(good_source);
    let _ = fs::remove_file(good_object);
    let _ = fs::remove_file(bad);
}
