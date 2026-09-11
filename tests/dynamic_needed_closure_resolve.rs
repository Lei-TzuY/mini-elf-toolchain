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
        "mini-elf-needed-closure-resolve-{}-{stamp}",
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

fn build_shared(
    dir: &Path,
    stem: &str,
    symbol: &str,
    hash_style: &str,
    dependencies: &[&str],
) -> PathBuf {
    let object = assemble(dir, stem, symbol);
    let image = dir.join(format!("lib{stem}.so"));
    let mut command = Command::new("ld");
    command
        .arg("-shared")
        .arg(format!("--hash-style={hash_style}"))
        .arg("-soname")
        .arg(format!("lib{stem}.so"))
        .arg("-o")
        .arg(&image)
        .arg(&object)
        .arg("-L")
        .arg(dir)
        .arg("--no-as-needed");
    for dependency in dependencies {
        command.arg(format!("-l{dependency}"));
    }
    run(&mut command);
    image
}

fn build_root(dir: &Path, dependencies: &[&str]) -> PathBuf {
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
    for dependency in dependencies {
        command.arg(format!("-l{dependency}"));
    }
    run(&mut command);
    image
}

fn tool() -> &'static str {
    env!("CARGO_BIN_EXE_mini-elf-needed-closure-resolve")
}

#[test]
fn resolves_symbol_from_transitive_dependency() {
    let dir = temp_dir();
    let leaf = build_shared(&dir, "leaf", "public_api", "gnu", &[]);
    let first = build_shared(&dir, "first", "first_marker", "sysv", &["leaf"]);
    let root = build_root(&dir, &["first"]);

    let first_dynamic = run(Command::new("readelf").arg("-dW").arg(&first));
    assert!(String::from_utf8(first_dynamic.stdout)
        .unwrap()
        .contains("Shared library: [libleaf.so]"));

    let output = run(Command::new(tool()).arg("public_api").arg(&root).arg(&dir));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("dependencies=2"));
    assert!(stdout.contains(&format!("file={}", leaf.to_string_lossy())));
    assert!(stdout.contains("hash=gnu"));

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn breadth_first_scope_prefers_direct_dependency_over_grandchild() {
    let dir = temp_dir();
    let leaf = build_shared(&dir, "leaf", "public_api", "gnu", &[]);
    build_shared(&dir, "first", "first_marker", "sysv", &["leaf"]);
    let second = build_shared(&dir, "second", "public_api", "sysv", &[]);
    let root = build_root(&dir, &["first", "second"]);

    let output = run(Command::new(tool()).arg("public_api").arg(&root).arg(&dir));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("dependencies=3"));
    assert!(stdout.contains(&format!("file={}", second.to_string_lossy())));
    assert!(!stdout.contains(&format!("file={}", leaf.to_string_lossy())));

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn shared_transitive_dependency_is_deduplicated() {
    let dir = temp_dir();
    let leaf = build_shared(&dir, "leaf", "public_api", "gnu", &[]);
    build_shared(&dir, "first", "first_marker", "sysv", &["leaf"]);
    build_shared(&dir, "second", "second_marker", "gnu", &["leaf"]);
    let root = build_root(&dir, &["first", "second"]);

    let output = run(Command::new(tool()).arg("public_api").arg(&root).arg(&dir));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("dependencies=3"));
    assert!(stdout.contains(&format!("file={}", leaf.to_string_lossy())));

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn missing_transitive_dependency_fails_before_resolution_output() {
    let dir = temp_dir();
    let leaf = build_shared(&dir, "leaf", "public_api", "gnu", &[]);
    build_shared(&dir, "first", "first_marker", "sysv", &["leaf"]);
    let root = build_root(&dir, &["first"]);
    fs::remove_file(leaf).unwrap();

    let output = Command::new(tool())
        .arg("public_api")
        .arg(&root)
        .arg(&dir)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("libleaf.so"));

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn malformed_transitive_dependency_fails_closed() {
    let dir = temp_dir();
    let leaf = build_shared(&dir, "leaf", "public_api", "gnu", &[]);
    build_shared(&dir, "first", "first_marker", "sysv", &["leaf"]);
    let root = build_root(&dir, &["first"]);

    let mut bytes = fs::read(&leaf).unwrap();
    bytes[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
    fs::write(&leaf, bytes).unwrap();

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
