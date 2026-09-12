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
        "mini-elf-needed-nodefaultlib-{}-{stamp}",
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

fn build_dependency(work: &Path, directory: &Path) -> PathBuf {
    fs::create_dir_all(directory).unwrap();
    let object = assemble(work, "dependency", "dep_api");
    let image = directory.join("libdep.so");
    run(Command::new("ld")
        .arg("-shared")
        .arg("--hash-style=gnu")
        .arg("-soname")
        .arg("libdep.so")
        .arg("-o")
        .arg(&image)
        .arg(&object));
    image
}

fn build_root(work: &Path, link_dir: &Path) -> PathBuf {
    let object = assemble(work, "root", "root_api");
    let image = work.join("libroot.so");
    run(Command::new("ld")
        .arg("-shared")
        .arg("--hash-style=gnu")
        .arg("-z")
        .arg("nodefaultlib")
        .arg("--no-as-needed")
        .arg("-L")
        .arg(link_dir)
        .arg("-ldep")
        .arg("-o")
        .arg(&image)
        .arg(&object));
    image
}

fn tool() -> &'static str {
    env!("CARGO_BIN_EXE_mini-elf-needed-nodefaultlib-resolve")
}

#[test]
fn nodefaultlib_suppresses_fallback_directory() {
    let dir = temp_dir();
    let fallback = dir.join("fallback");
    build_dependency(&dir, &fallback);
    let root = build_root(&dir, &fallback);

    let dynamic = run(Command::new("readelf").arg("-dW").arg(&root));
    let dynamic = String::from_utf8(dynamic.stdout).unwrap();
    assert!(dynamic.contains("FLAGS_1"));
    assert!(dynamic.contains("NODEFLIB"));

    let output = Command::new(tool())
        .arg("dep_api")
        .arg(&root)
        .arg(&fallback)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("DF_1_NODEFLIB suppressed fallback directory"));
    assert!(stderr.contains("cannot resolve DT_NEEDED dependency 'libdep.so'"));

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn nodefaultlib_keeps_explicit_loader_path_search() {
    let dir = temp_dir();
    let loader = dir.join("loader");
    let fallback = dir.join("fallback");
    fs::create_dir_all(&fallback).unwrap();
    let dependency = build_dependency(&dir, &loader);
    let root = build_root(&dir, &loader);

    let output = run(Command::new(tool())
        .arg("--ld-library-path")
        .arg(&loader)
        .arg("dep_api")
        .arg(&root)
        .arg(&fallback));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("DF_1_NODEFLIB"));
    assert!(stdout.contains("loader-path-directories=1"));
    assert!(stdout.contains(&format!("file={}", dependency.to_string_lossy())));

    fs::remove_dir_all(dir).unwrap();
}
