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
        "mini-elf-needed-cwd-direct-{}-{stamp}",
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

fn build_root(work: &Path, dependency: &Path) -> PathBuf {
    let object = assemble(work, "root", "root_marker");
    let root = work.join("libroot.so");
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
    env!("CARGO_BIN_EXE_mini-elf-needed-absolute-runpath-resolve")
}

#[test]
fn resolves_normalized_cwd_relative_direct_needed_path_without_search_layers() {
    let dir = temp_dir();
    let deps = dir.join("deps");
    let fallback = dir.join("fallback");
    fs::create_dir_all(&fallback).unwrap();

    let leaf = build_leaf(&dir, &deps.join("libleaf.so"), "deps/libleaf.so");
    let root = build_root(&dir, &leaf);

    let dynamic = run(Command::new("readelf").arg("-dW").arg(&root));
    let dynamic = String::from_utf8(dynamic.stdout).unwrap();
    assert!(dynamic.contains("(NEEDED)"));
    assert!(dynamic.contains("deps/libleaf.so"));

    let output = run(Command::new(tool())
        .current_dir(&dir)
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
fn rejects_parent_traversal_in_cwd_relative_direct_needed_path_atomically() {
    let dir = temp_dir();
    let deps = dir.join("deps");
    let fallback = dir.join("fallback");
    fs::create_dir_all(&fallback).unwrap();

    let leaf = build_leaf(&dir, &deps.join("libleaf.so"), "deps/../deps/libleaf.so");
    let root = build_root(&dir, &leaf);

    let dynamic = run(Command::new("readelf").arg("-dW").arg(&root));
    let dynamic = String::from_utf8(dynamic.stdout).unwrap();
    assert!(dynamic.contains("deps/../deps/libleaf.so"));

    let output = Command::new(tool())
        .current_dir(&dir)
        .arg("public_api")
        .arg(&root)
        .arg(&fallback)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("not a normalized relative path"));

    fs::remove_dir_all(dir).unwrap();
}
