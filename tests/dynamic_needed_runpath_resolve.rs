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
        "mini-elf-needed-runpath-resolve-{}-{stamp}",
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

fn build_shared(
    work: &Path,
    output_dir: &Path,
    stem: &str,
    symbol: &str,
    dependencies: &[&str],
    link_dirs: &[&Path],
    runpath: Option<&str>,
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
    if let Some(runpath) = runpath {
        command
            .arg("--enable-new-dtags")
            .arg(format!("--rpath={runpath}"));
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
fn resolves_transitive_dependency_through_each_parents_origin_runpath() {
    let dir = temp_dir();
    let root_dir = dir.join("root");
    let plugins = root_dir.join("plugins");
    let leaves = plugins.join("leaf");
    let fallback = dir.join("fallback");
    fs::create_dir_all(&fallback).unwrap();

    let leaf = build_shared(&dir, &leaves, "leaf", "public_api", &[], &[], None);
    let first = build_shared(
        &dir,
        &plugins,
        "first",
        "first_marker",
        &["leaf"],
        &[&leaves],
        Some("$ORIGIN/leaf"),
    );
    let root = build_shared(
        &dir,
        &root_dir,
        "root",
        "root_marker",
        &["first"],
        &[&plugins],
        Some("$ORIGIN/plugins"),
    );

    for image in [&root, &first] {
        let dynamic = run(Command::new("readelf").arg("-dW").arg(image));
        assert!(String::from_utf8(dynamic.stdout)
            .unwrap()
            .contains("(RUNPATH)"));
    }

    let output = run(
        Command::new(tool())
            .arg("public_api")
            .arg(&root)
            .arg(&fallback),
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("dependencies=2"));
    assert!(stdout.contains("runpath-directories=2"));
    assert!(stdout.contains(&format!("file={}", leaf.to_string_lossy())));

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn falls_back_to_explicit_library_directory_without_runpath() {
    let dir = temp_dir();
    let root_dir = dir.join("root");
    let fallback = dir.join("fallback");
    let first = build_shared(&dir, &fallback, "first", "public_api", &[], &[], None);
    let root = build_shared(
        &dir,
        &root_dir,
        "root",
        "root_marker",
        &["first"],
        &[&fallback],
        None,
    );

    let output = run(
        Command::new(tool())
            .arg("public_api")
            .arg(&root)
            .arg(&fallback),
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("dependencies=1"));
    assert!(stdout.contains("runpath-directories=0"));
    assert!(stdout.contains(&format!("file={}", first.to_string_lossy())));

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rejects_origin_runpath_that_escapes_parent_directory() {
    let dir = temp_dir();
    let root_dir = dir.join("root");
    let fallback = dir.join("fallback");
    build_shared(&dir, &fallback, "first", "public_api", &[], &[], None);
    let root = build_shared(
        &dir,
        &root_dir,
        "root",
        "root_marker",
        &["first"],
        &[&fallback],
        Some("$ORIGIN/../escape"),
    );

    let output = Command::new(tool())
        .arg("public_api")
        .arg(&root)
        .arg(&fallback)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("escapes"));

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn malformed_runpath_discovered_dependency_fails_closed() {
    let dir = temp_dir();
    let root_dir = dir.join("root");
    let plugins = root_dir.join("plugins");
    let fallback = dir.join("fallback");
    fs::create_dir_all(&fallback).unwrap();

    let first = build_shared(&dir, &plugins, "first", "public_api", &[], &[], None);
    let root = build_shared(
        &dir,
        &root_dir,
        "root",
        "root_marker",
        &["first"],
        &[&plugins],
        Some("$ORIGIN/plugins"),
    );
    let mut bytes = fs::read(&first).unwrap();
    bytes[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
    fs::write(&first, bytes).unwrap();

    let output = Command::new(tool())
        .arg("public_api")
        .arg(&root)
        .arg(&fallback)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.is_empty());

    fs::remove_dir_all(dir).unwrap();
}
