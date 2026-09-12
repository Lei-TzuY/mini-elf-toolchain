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
        "mini-elf-needed-loader-token-{}-{stamp}",
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
    let source = work.join(format!("{stem}-{symbol}.s"));
    let object = work.join(format!("{stem}-{symbol}.o"));
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
    work: &Path,
    output_dir: &Path,
    stem: &str,
    symbol: &str,
    dependencies: &[&str],
    link_dirs: &[&Path],
) -> PathBuf {
    fs::create_dir_all(output_dir).unwrap();
    let object = assemble(work, stem, symbol);
    let image = output_dir.join(format!("lib{stem}.so"));
    let mut command = Command::new("ld");
    command
        .arg("-shared")
        .arg("--hash-style=gnu")
        .arg("-soname")
        .arg(format!("lib{stem}.so"))
        .arg("-o")
        .arg(&image)
        .arg(&object)
        .arg("--no-as-needed");
    for directory in link_dirs {
        command.arg("-L").arg(directory);
    }
    for dependency in dependencies {
        command.arg(format!("-l{dependency}"));
    }
    run(&mut command);
    image
}

fn tool() -> &'static str {
    env!("CARGO_BIN_EXE_mini-elf-needed-loader-token-resolve")
}

#[test]
fn origin_lib_platform_loader_path_resolves_dependency() {
    let dir = temp_dir();
    let root_dir = dir.join("root");
    let token_dir = root_dir.join("lib64").join("x86_64");
    let fallback = dir.join("fallback");
    fs::create_dir_all(&fallback).unwrap();

    let choice = build_shared(&dir, &token_dir, "choice", "public_api", &[], &[]);
    let root = build_shared(
        &dir,
        &root_dir,
        "root",
        "root_marker",
        &["choice"],
        &[&token_dir],
    );

    let dynamic = run(Command::new("readelf").arg("-dW").arg(&root));
    let dynamic = String::from_utf8(dynamic.stdout).unwrap();
    assert!(dynamic.contains("(NEEDED)"));
    assert!(dynamic.contains("libchoice.so"));
    assert!(!dynamic.contains("(RUNPATH)"));
    assert!(!dynamic.contains("(RPATH)"));

    let output = run(Command::new(tool())
        .arg("--ld-library-path")
        .arg("${ORIGIN}/${LIB}/${PLATFORM}")
        .arg("public_api")
        .arg(&root)
        .arg(&fallback));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("dependencies=1"));
    assert!(stdout.contains("loader-path-directories=1"));
    assert!(stdout.contains(&format!("file={}", choice.to_string_lossy())));

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn ordinary_loader_path_is_preserved() {
    let dir = temp_dir();
    let root_dir = dir.join("root");
    let loader_dir = dir.join("loader");
    let fallback = dir.join("fallback");
    fs::create_dir_all(&fallback).unwrap();

    let choice = build_shared(&dir, &loader_dir, "choice", "public_api", &[], &[]);
    let root = build_shared(
        &dir,
        &root_dir,
        "root",
        "root_marker",
        &["choice"],
        &[&loader_dir],
    );

    let output = run(Command::new(tool())
        .arg("--ld-library-path")
        .arg(&loader_dir)
        .arg("public_api")
        .arg(&root)
        .arg(&fallback));
    assert!(String::from_utf8(output.stdout)
        .unwrap()
        .contains(&format!("file={}", choice.to_string_lossy())));

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn parent_traversal_in_tokenized_loader_path_fails_closed() {
    let dir = temp_dir();
    let root_dir = dir.join("root");
    let fallback = dir.join("fallback");
    fs::create_dir_all(&root_dir).unwrap();
    fs::create_dir_all(&fallback).unwrap();

    let output = Command::new(tool())
        .arg("--ld-library-path")
        .arg("$ORIGIN/../escape")
        .arg("public_api")
        .arg(root_dir.join("missing-root.so"))
        .arg(&fallback)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("escapes"));

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn embedded_loader_path_token_fails_closed() {
    let dir = temp_dir();
    let root_dir = dir.join("root");
    let fallback = dir.join("fallback");
    fs::create_dir_all(&root_dir).unwrap();
    fs::create_dir_all(&fallback).unwrap();

    let output = Command::new(tool())
        .arg("--ld-library-path")
        .arg("$ORIGIN/pre$LIB")
        .arg("public_api")
        .arg(root_dir.join("missing-root.so"))
        .arg(&fallback)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("dynamic token placement"));

    fs::remove_dir_all(dir).unwrap();
}
