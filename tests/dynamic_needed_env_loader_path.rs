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
        "mini-elf-needed-env-{}-{stamp}",
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
    runpath: Option<&Path>,
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
    if let Some(directory) = runpath {
        command.arg("-rpath").arg(directory);
    }
    for dependency in dependencies {
        command.arg(format!("-l{dependency}"));
    }
    run(&mut command);
    image
}

fn tool() -> &'static str {
    env!("CARGO_BIN_EXE_mini-elf-needed-env-resolve")
}

#[test]
fn ambient_loader_path_precedes_runpath() {
    let dir = temp_dir();
    let root_dir = dir.join("root");
    let env_dir = dir.join("env");
    let runpath_dir = dir.join("runpath");
    let fallback = dir.join("fallback");
    fs::create_dir_all(&fallback).unwrap();

    let env_dependency = build_shared(&dir, &env_dir, "dep", "public_api", &[], &[], None);
    build_shared(&dir, &runpath_dir, "dep", "other_api", &[], &[], None);
    let root = build_shared(
        &dir,
        &root_dir,
        "root",
        "root_marker",
        &["dep"],
        &[&runpath_dir],
        Some(&runpath_dir),
    );

    let dynamic = run(Command::new("readelf").arg("-dW").arg(&root));
    let dynamic = String::from_utf8(dynamic.stdout).unwrap();
    assert!(dynamic.contains("(RUNPATH)"));
    assert!(dynamic.contains(runpath_dir.to_string_lossy().as_ref()));

    let output = run(Command::new(tool())
        .env("LD_LIBRARY_PATH", &env_dir)
        .arg("public_api")
        .arg(&root)
        .arg(&fallback));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("dependencies=1"));
    assert!(stdout.contains(&format!("file={}", env_dependency.to_string_lossy())));

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn empty_ambient_loader_path_component_resolves_from_cwd() {
    let dir = temp_dir();
    let root_dir = dir.join("root");
    let cwd = dir.join("cwd");
    let fallback = dir.join("fallback");
    fs::create_dir_all(&fallback).unwrap();

    let dependency = build_shared(&dir, &cwd, "dep", "public_api", &[], &[], None);
    let root = build_shared(
        &dir,
        &root_dir,
        "root",
        "root_marker",
        &["dep"],
        &[&cwd],
        None,
    );

    let output = run(Command::new(tool())
        .current_dir(&cwd)
        .env("LD_LIBRARY_PATH", "")
        .arg("public_api")
        .arg(&root)
        .arg(&fallback));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains(&format!("file={}", dependency.to_string_lossy())));

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn unset_ambient_loader_path_keeps_fallback_search() {
    let dir = temp_dir();
    let root_dir = dir.join("root");
    let fallback = dir.join("fallback");

    let dependency = build_shared(&dir, &fallback, "dep", "public_api", &[], &[], None);
    let root = build_shared(
        &dir,
        &root_dir,
        "root",
        "root_marker",
        &["dep"],
        &[&fallback],
        None,
    );

    let output = run(Command::new(tool())
        .env_remove("LD_LIBRARY_PATH")
        .arg("public_api")
        .arg(&root)
        .arg(&fallback));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains(&format!("file={}", dependency.to_string_lossy())));

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn malformed_ambient_loader_path_fails_before_stdout() {
    let dir = temp_dir();
    let root_dir = dir.join("root");
    let fallback = dir.join("fallback");
    fs::create_dir_all(&fallback).unwrap();
    let not_directory = dir.join("not-a-directory");
    fs::write(&not_directory, b"x").unwrap();

    let root = build_shared(&dir, &root_dir, "root", "root_marker", &[], &[], None);
    let output = Command::new(tool())
        .env("LD_LIBRARY_PATH", &not_directory)
        .arg("root_marker")
        .arg(&root)
        .arg(&fallback)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("not a directory"));

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn secure_mode_suppresses_ambient_loader_path() {
    let dir = temp_dir();
    let root_dir = dir.join("root");
    let env_dir = dir.join("env");
    let fallback = dir.join("fallback");

    build_shared(&dir, &env_dir, "dep", "ambient_api", &[], &[], None);
    let fallback_dependency =
        build_shared(&dir, &fallback, "dep", "secure_api", &[], &[], None);
    let root = build_shared(
        &dir,
        &root_dir,
        "root",
        "root_marker",
        &["dep"],
        &[&env_dir],
        None,
    );

    let dynamic = run(Command::new("readelf").arg("-dW").arg(&root));
    let dynamic = String::from_utf8(dynamic.stdout).unwrap();
    assert!(dynamic.contains("(NEEDED)"));
    assert!(dynamic.contains("libdep.so"));

    let output = run(Command::new(tool())
        .env("LD_LIBRARY_PATH", &env_dir)
        .arg("--secure")
        .arg("secure_api")
        .arg(&root)
        .arg(&fallback));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("dependencies=1"));
    assert!(stdout.contains(&format!(
        "file={}",
        fallback_dependency.to_string_lossy()
    )));

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn secure_mode_does_not_parse_malformed_ambient_loader_path() {
    let dir = temp_dir();
    let root_dir = dir.join("root");
    let fallback = dir.join("fallback");
    let not_directory = dir.join("not-a-directory");
    fs::write(&not_directory, b"x").unwrap();

    let dependency = build_shared(&dir, &fallback, "dep", "secure_api", &[], &[], None);
    let root = build_shared(
        &dir,
        &root_dir,
        "root",
        "root_marker",
        &["dep"],
        &[&fallback],
        None,
    );

    let output = run(Command::new(tool())
        .env("LD_LIBRARY_PATH", &not_directory)
        .arg("--secure")
        .arg("secure_api")
        .arg(&root)
        .arg(&fallback));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains(&format!("file={}", dependency.to_string_lossy())));

    fs::remove_dir_all(dir).unwrap();
}
