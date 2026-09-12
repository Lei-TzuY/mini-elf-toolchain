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
        "mini-elf-absolute-search-paths-{}-{stamp}",
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
    search_path: Option<(&str, bool)>,
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
    if let Some((path, new_dtags)) = search_path {
        command.arg(if new_dtags {
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
    env!("CARGO_BIN_EXE_mini-elf-needed-absolute-runpath-resolve")
}

#[test]
fn resolves_dependency_through_absolute_runpath() {
    let dir = temp_dir();
    let root_dir = dir.join("root");
    let libraries = dir.join("libraries");
    let fallback = dir.join("fallback");
    fs::create_dir_all(&fallback).unwrap();

    let dependency = build_shared(&dir, &libraries, "dep", "public_api", &[], &[], None);
    let absolute = libraries.to_string_lossy().into_owned();
    let root = build_shared(
        &dir,
        &root_dir,
        "root",
        "root_marker",
        &["dep"],
        &[&libraries],
        Some((&absolute, true)),
    );

    let dynamic = run(Command::new("readelf").arg("-dW").arg(&root));
    let dynamic = String::from_utf8(dynamic.stdout).unwrap();
    assert!(dynamic.contains("(RUNPATH)"));
    assert!(dynamic.contains(&absolute));

    let output = run(Command::new(tool())
        .arg("public_api")
        .arg(&root)
        .arg(&fallback));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("dependencies=1"));
    assert!(stdout.contains("runpath-directories=1"));
    assert!(stdout.contains(&format!("file={}", dependency.to_string_lossy())));

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn inherits_absolute_rpath_for_transitive_dependency() {
    let dir = temp_dir();
    let root_dir = dir.join("root");
    let libraries = dir.join("libraries");
    let middle_dir = dir.join("middle");
    let fallback = dir.join("fallback");
    fs::create_dir_all(&fallback).unwrap();

    let leaf = build_shared(&dir, &libraries, "leaf", "public_api", &[], &[], None);
    let middle = build_shared(
        &dir,
        &middle_dir,
        "middle",
        "middle_marker",
        &["leaf"],
        &[&libraries],
        None,
    );
    let absolute = format!("{}:{}", middle_dir.display(), libraries.display());
    let root = build_shared(
        &dir,
        &root_dir,
        "root",
        "root_marker",
        &["middle"],
        &[&middle_dir],
        Some((&absolute, false)),
    );

    let dynamic = run(Command::new("readelf").arg("-dW").arg(&root));
    let dynamic = String::from_utf8(dynamic.stdout).unwrap();
    assert!(dynamic.contains("(RPATH)"));
    assert!(dynamic.contains(&absolute));

    let output = run(Command::new(tool())
        .arg("public_api")
        .arg(&root)
        .arg(&fallback));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("dependencies=2"));
    assert!(stdout.contains("rpath-directories=2"));
    assert!(stdout.contains(&format!("file={}", leaf.to_string_lossy())));
    assert!(middle.exists());

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rejects_non_normalized_absolute_runpath_before_stdout() {
    let dir = temp_dir();
    let root_dir = dir.join("root");
    let libraries = dir.join("libraries");
    let fallback = dir.join("fallback");
    fs::create_dir_all(&fallback).unwrap();

    build_shared(&dir, &libraries, "dep", "public_api", &[], &[], None);
    let malformed = format!("{}/../libraries", libraries.display());
    let root = build_shared(
        &dir,
        &root_dir,
        "root",
        "root_marker",
        &["dep"],
        &[&libraries],
        Some((&malformed, true)),
    );

    let output = Command::new(tool())
        .arg("public_api")
        .arg(&root)
        .arg(&fallback)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("normalized absolute path"));

    fs::remove_dir_all(dir).unwrap();
}
