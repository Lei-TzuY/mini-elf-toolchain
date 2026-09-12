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
        "mini-elf-needed-rpath-resolve-{}-{stamp}",
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
    rpath: Option<&str>,
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
    if let Some(rpath) = rpath {
        command
            .arg("--disable-new-dtags")
            .arg(format!("--rpath={rpath}"));
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
fn resolves_transitive_dependency_through_each_parents_origin_rpath() {
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
        let dynamic = String::from_utf8(dynamic.stdout).unwrap();
        assert!(dynamic.contains("(RPATH)"));
        assert!(!dynamic.contains("(RUNPATH)"));
    }

    let output = run(Command::new(tool())
        .arg("public_api")
        .arg(&root)
        .arg(&fallback));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("dependencies=2"));
    assert!(stdout.contains("runpath-directories=0"));
    assert!(stdout.contains("rpath-directories=2"));
    assert!(stdout.contains(&format!("file={}", leaf.to_string_lossy())));

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rejects_origin_rpath_that_escapes_parent_directory() {
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
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("DT_RPATH"));
    assert!(stderr.contains("escapes"));

    fs::remove_dir_all(dir).unwrap();
}
