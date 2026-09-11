use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_dir() -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "mini-elf-needed-resolve-{}-{stamp}",
        std::process::id()
    ));
    fs::create_dir_all(&path).unwrap();
    path
}

fn run(command: &mut Command) -> Output {
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "command failed: status={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn assemble(dir: &Path, stem: &str, symbol: &str) -> PathBuf {
    let source = dir.join(format!("{stem}.s"));
    let object = dir.join(format!("{stem}.o"));
    fs::write(
        &source,
        format!(
            ".text\n.globl {symbol}\n.type {symbol},@function\n{symbol}:\n  ret\n.size {symbol}, .-{symbol}\n"
        ),
    )
    .unwrap();
    run(Command::new("as")
        .arg("--64")
        .arg("-o")
        .arg(&object)
        .arg(&source));
    object
}

fn build_dependency(
    dir: &Path,
    stem: &str,
    symbol: &str,
    hash_style: &str,
    soname: &str,
) -> PathBuf {
    let object = assemble(dir, stem, symbol);
    let image = dir.join(format!("lib{stem}.so"));
    run(Command::new("ld")
        .arg("-shared")
        .arg(format!("--hash-style={hash_style}"))
        .arg("-soname")
        .arg(soname)
        .arg("-o")
        .arg(&image)
        .arg(&object));
    image
}

fn build_root(dir: &Path, libraries: &[&str]) -> PathBuf {
    let object = assemble(dir, "root", "root_marker");
    let image = dir.join("root.so");
    let mut command = Command::new("ld");
    command
        .arg("-shared")
        .arg("--hash-style=gnu")
        .arg("-o")
        .arg(&image)
        .arg(&object)
        .arg("-L")
        .arg(dir)
        .arg("--no-as-needed");
    for library in libraries {
        command.arg(format!("-l{library}"));
    }
    run(&mut command);
    image
}

fn tool() -> &'static str {
    env!("CARGO_BIN_EXE_mini-elf-needed-resolve")
}

#[test]
fn resolves_across_direct_needed_scope_in_declared_order() {
    let dir = temp_dir();
    let first = build_dependency(&dir, "first", "public_api", "sysv", "libfirst.so");
    let second = build_dependency(&dir, "second", "public_api", "gnu", "libsecond.so");
    let root = build_root(&dir, &["first", "second"]);

    let dynamic = run(Command::new("readelf").arg("-dW").arg(&root));
    let dynamic = String::from_utf8(dynamic.stdout).unwrap();
    let first_needed = dynamic.find("Shared library: [libfirst.so]").unwrap();
    let second_needed = dynamic.find("Shared library: [libsecond.so]").unwrap();
    assert!(first_needed < second_needed);

    let output = run(Command::new(tool()).arg("public_api").arg(&root).arg(&dir));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("direct_dependencies=2"));
    assert!(stdout.contains(&format!("file={}", first.to_string_lossy())));
    assert!(stdout.contains("hash=sysv"));
    assert!(!stdout.contains(&format!("file={}", second.to_string_lossy())));

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn falls_through_to_later_mixed_hash_dependency() {
    let dir = temp_dir();
    build_dependency(&dir, "first", "first_only", "sysv", "libfirst.so");
    let second = build_dependency(&dir, "second", "public_api", "gnu", "libsecond.so");
    let root = build_root(&dir, &["first", "second"]);

    let output = run(Command::new(tool()).arg("public_api").arg(&root).arg(&dir));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains(&format!("file={}", second.to_string_lossy())));
    assert!(stdout.contains("hash=gnu"));

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn missing_direct_dependency_fails_before_resolution_output() {
    let dir = temp_dir();
    let first = build_dependency(&dir, "first", "public_api", "gnu", "libfirst.so");
    let root = build_root(&dir, &["first"]);
    fs::remove_file(first).unwrap();

    let output = Command::new(tool())
        .arg("public_api")
        .arg(&root)
        .arg(&dir)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("libfirst.so"));

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn malformed_earlier_dependency_fails_closed() {
    let dir = temp_dir();
    let first = build_dependency(&dir, "first", "first_only", "sysv", "libfirst.so");
    build_dependency(&dir, "second", "public_api", "gnu", "libsecond.so");
    let root = build_root(&dir, &["first", "second"]);

    let mut bytes = fs::read(&first).unwrap();
    bytes[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
    fs::write(&first, bytes).unwrap();

    let output = Command::new(tool())
        .arg("public_api")
        .arg(&root)
        .arg(&dir)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.is_empty());

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rejects_needed_names_that_escape_the_library_directory() {
    let dir = temp_dir();
    build_dependency(&dir, "evil", "public_api", "gnu", "../evil.so");
    let root = build_root(&dir, &["evil"]);

    let dynamic = run(Command::new("readelf").arg("-dW").arg(&root));
    assert!(String::from_utf8(dynamic.stdout)
        .unwrap()
        .contains("Shared library: [../evil.so]"));

    let output = Command::new(tool())
        .arg("public_api")
        .arg(&root)
        .arg(&dir)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("plain library basename"));

    fs::remove_dir_all(dir).unwrap();
}
