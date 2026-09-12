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
        "mini-elf-needed-loader-path-{}-{stamp}",
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
    path_tag: Option<(&str, bool)>,
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
    if let Some((path, use_runpath)) = path_tag {
        command.arg(if use_runpath {
            "--enable-new-dtags"
        } else {
            "--disable-new-dtags"
        });
        command.arg(format!("--rpath={path}"));
    }
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
    env!("CARGO_BIN_EXE_mini-elf-needed-runpath-resolve")
}

#[test]
fn explicit_loader_path_precedes_local_runpath() {
    let dir = temp_dir();
    let root_dir = dir.join("root");
    let runpath_dir = root_dir.join("runpath");
    let loader_dir = dir.join("loader");
    let fallback = dir.join("fallback");
    fs::create_dir_all(&fallback).unwrap();

    let loader_choice = build_shared(&dir, &loader_dir, "choice", "loader_api", &[], &[], None);
    build_shared(&dir, &runpath_dir, "choice", "runpath_api", &[], &[], None);
    let root = build_shared(
        &dir,
        &root_dir,
        "root",
        "root_marker",
        &["choice"],
        &[&runpath_dir],
        Some(("$ORIGIN/runpath", true)),
    );

    let dynamic = run(Command::new("readelf").arg("-dW").arg(&root));
    assert!(String::from_utf8(dynamic.stdout)
        .unwrap()
        .contains("(RUNPATH)"));

    let output = run(Command::new(tool())
        .arg("--ld-library-path")
        .arg(&loader_dir)
        .arg("loader_api")
        .arg(&root)
        .arg(&fallback));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("loader-path-directories=1"));
    assert!(stdout.contains(&format!("file={}", loader_choice.to_string_lossy())));

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn legacy_rpath_precedes_explicit_loader_path() {
    let dir = temp_dir();
    let root_dir = dir.join("root");
    let rpath_dir = root_dir.join("rpath");
    let loader_dir = dir.join("loader");
    let fallback = dir.join("fallback");
    fs::create_dir_all(&fallback).unwrap();

    let rpath_choice = build_shared(&dir, &rpath_dir, "choice", "rpath_api", &[], &[], None);
    build_shared(&dir, &loader_dir, "choice", "loader_api", &[], &[], None);
    let root = build_shared(
        &dir,
        &root_dir,
        "root",
        "root_marker",
        &["choice"],
        &[&rpath_dir],
        Some(("$ORIGIN/rpath", false)),
    );

    let dynamic = run(Command::new("readelf").arg("-dW").arg(&root));
    assert!(String::from_utf8(dynamic.stdout)
        .unwrap()
        .contains("(RPATH)"));

    let output = run(Command::new(tool())
        .arg("--ld-library-path")
        .arg(&loader_dir)
        .arg("rpath_api")
        .arg(&root)
        .arg(&fallback));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains(&format!("file={}", rpath_choice.to_string_lossy())));

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn empty_loader_path_component_fails_closed() {
    let dir = temp_dir();
    let loader_dir = dir.join("loader");
    let fallback = dir.join("fallback");
    fs::create_dir_all(&loader_dir).unwrap();
    fs::create_dir_all(&fallback).unwrap();

    let value = format!("{}::{}", loader_dir.display(), loader_dir.display());
    let output = Command::new(tool())
        .arg("--ld-library-path")
        .arg(value)
        .arg("public_api")
        .arg(dir.join("missing-root.so"))
        .arg(&fallback)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("empty directory entry"));

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn non_directory_loader_path_entry_fails_closed() {
    let dir = temp_dir();
    let not_dir = dir.join("not-a-directory");
    let fallback = dir.join("fallback");
    fs::write(&not_dir, b"not a directory").unwrap();
    fs::create_dir_all(&fallback).unwrap();

    let output = Command::new(tool())
        .arg("--ld-library-path")
        .arg(&not_dir)
        .arg("public_api")
        .arg(dir.join("missing-root.so"))
        .arg(&fallback)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("is not a directory"));

    fs::remove_dir_all(dir).unwrap();
}
