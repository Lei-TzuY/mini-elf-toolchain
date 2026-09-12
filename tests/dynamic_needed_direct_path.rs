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
        "mini-elf-needed-direct-path-{}-{stamp}",
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

fn assemble(work: &Path, stem: &str, symbol: &str) -> PathBuf {
    let source = work.join(format!("{stem}.s"));
    let object = work.join(format!("{stem}.o"));
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

fn build_leaf(work: &Path, output: &Path, soname: &str) -> PathBuf {
    fs::create_dir_all(output.parent().unwrap()).unwrap();
    let object = assemble(work, "leaf", "public_api");
    run(Command::new("ld")
        .arg("-shared")
        .arg("--hash-style=gnu")
        .arg("-soname")
        .arg(soname)
        .arg("-o")
        .arg(output)
        .arg(&object));
    output.to_path_buf()
}

fn build_root(work: &Path, output_dir: &Path, dependency: &Path) -> PathBuf {
    fs::create_dir_all(output_dir).unwrap();
    let object = assemble(work, "root", "root_marker");
    let root = output_dir.join("libroot.so");
    run(Command::new("ld")
        .arg("-shared")
        .arg("--hash-style=gnu")
        .arg("-soname")
        .arg("libroot.so")
        .arg("-o")
        .arg(&root)
        .arg(&object)
        .arg("--no-as-needed")
        .arg(dependency));
    root
}

fn tool() -> &'static str {
    env!("CARGO_BIN_EXE_mini-elf-needed-runpath-resolve")
}

#[test]
fn resolves_origin_anchored_direct_needed_path_without_searching_fallback() {
    let dir = temp_dir();
    let root_dir = dir.join("root");
    let direct_dir = root_dir.join("lib64").join("x86_64");
    let fallback = dir.join("fallback");
    fs::create_dir_all(&fallback).unwrap();

    let leaf = build_leaf(
        &dir,
        &direct_dir.join("libleaf.so"),
        "$ORIGIN/$LIB/$PLATFORM/libleaf.so",
    );
    let root = build_root(&dir, &root_dir, &leaf);

    let dynamic = run(Command::new("readelf").arg("-dW").arg(&root));
    let dynamic = String::from_utf8(dynamic.stdout).unwrap();
    assert!(dynamic.contains("(NEEDED)"));
    assert!(dynamic.contains("$ORIGIN/$LIB/$PLATFORM/libleaf.so"));

    let output = run(Command::new(tool())
        .arg("public_api")
        .arg(&root)
        .arg(&fallback));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("dependencies=1"));
    assert!(stdout.contains("runpath-directories=0"));
    assert!(stdout.contains("rpath-directories=0"));
    assert!(stdout.contains(&format!("file={}", leaf.to_string_lossy())));

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn resolves_absolute_direct_needed_path_without_searching_fallback() {
    let dir = temp_dir();
    let root_dir = dir.join("root");
    let direct_dir = dir.join("absolute");
    let fallback = dir.join("fallback");
    fs::create_dir_all(&fallback).unwrap();

    let leaf_path = direct_dir.join("libleaf.so");
    let soname = leaf_path.to_string_lossy().into_owned();
    let leaf = build_leaf(&dir, &leaf_path, &soname);
    let root = build_root(&dir, &root_dir, &leaf);

    let dynamic = run(Command::new("readelf").arg("-dW").arg(&root));
    let dynamic = String::from_utf8(dynamic.stdout).unwrap();
    assert!(dynamic.contains("(NEEDED)"));
    assert!(dynamic.contains(&soname));

    let output = run(Command::new(tool())
        .arg("public_api")
        .arg(&root)
        .arg(&fallback));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("dependencies=1"));
    assert!(stdout.contains("loader-path-directories=0"));
    assert!(stdout.contains("runpath-directories=0"));
    assert!(stdout.contains("rpath-directories=0"));
    assert!(stdout.contains(&format!("file={}", leaf.to_string_lossy())));

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rejects_absolute_direct_needed_path_that_resolves_to_directory() {
    let dir = temp_dir();
    let root_dir = dir.join("root");
    let leaf_dir = dir.join("leaf");
    let fallback = dir.join("fallback");
    fs::create_dir_all(&leaf_dir).unwrap();
    fs::create_dir_all(&fallback).unwrap();

    let leaf_file = dir.join("build").join("libleaf.so");
    let soname = leaf_dir.to_string_lossy().into_owned();
    let leaf = build_leaf(&dir, &leaf_file, &soname);
    let root = build_root(&dir, &root_dir, &leaf);

    let dynamic = run(Command::new("readelf").arg("-dW").arg(&root));
    let dynamic = String::from_utf8(dynamic.stdout).unwrap();
    assert!(dynamic.contains(&soname));

    let output = Command::new(tool())
        .arg("public_api")
        .arg(&root)
        .arg(&fallback)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("resolved to non-file"));

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rejects_direct_needed_path_that_escapes_origin() {
    let dir = temp_dir();
    let root_dir = dir.join("root");
    let outside = dir.join("outside");
    let fallback = dir.join("fallback");
    fs::create_dir_all(&fallback).unwrap();

    let leaf = build_leaf(
        &dir,
        &outside.join("libleaf.so"),
        "$ORIGIN/../outside/libleaf.so",
    );
    let root = build_root(&dir, &root_dir, &leaf);

    let output = Command::new(tool())
        .arg("public_api")
        .arg(&root)
        .arg(&fallback)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("safe relative path"));

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rejects_unsupported_token_in_direct_needed_path() {
    let dir = temp_dir();
    let root_dir = dir.join("root");
    let direct_dir = root_dir.join("deps");
    let fallback = dir.join("fallback");
    fs::create_dir_all(&fallback).unwrap();

    let leaf = build_leaf(
        &dir,
        &direct_dir.join("libleaf.so"),
        "$ORIGIN/$UNKNOWN/libleaf.so",
    );
    let root = build_root(&dir, &root_dir, &leaf);

    let output = Command::new(tool())
        .arg("public_api")
        .arg(&root)
        .arg(&fallback)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("dynamic token placement"));

    fs::remove_dir_all(dir).unwrap();
}
