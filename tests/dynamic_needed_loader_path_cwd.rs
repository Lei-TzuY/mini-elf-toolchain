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
        "mini-elf-needed-loader-cwd-{}-{stamp}",
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
    env!("CARGO_BIN_EXE_mini-elf-needed-loader-cwd-resolve")
}

#[test]
fn empty_loader_path_component_resolves_from_process_cwd() {
    let dir = temp_dir();
    let root_dir = dir.join("root");
    let cwd = dir.join("cwd");
    let fallback = dir.join("fallback");
    fs::create_dir_all(&fallback).unwrap();

    let dependency = build_shared(&dir, &cwd, "dep", "public_api", &[], &[]);
    let root = build_shared(&dir, &root_dir, "root", "root_marker", &["dep"], &[&cwd]);

    let dynamic = run(Command::new("readelf").arg("-dW").arg(&root));
    let dynamic = String::from_utf8(dynamic.stdout).unwrap();
    assert!(dynamic.contains("(NEEDED)"));
    assert!(dynamic.contains("libdep.so"));

    let output = run(Command::new(tool())
        .current_dir(&cwd)
        .arg("--ld-library-path")
        .arg(":")
        .arg("public_api")
        .arg(&root)
        .arg(&fallback));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("dependencies=1"));
    assert!(stdout.contains(&format!("file={}", dependency.to_string_lossy())));

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn empty_component_precedes_later_explicit_directory() {
    let dir = temp_dir();
    let root_dir = dir.join("root");
    let cwd = dir.join("cwd");
    let later = dir.join("later");
    let fallback = dir.join("fallback");
    fs::create_dir_all(&fallback).unwrap();

    let cwd_dependency = build_shared(&dir, &cwd, "dep", "public_api", &[], &[]);
    build_shared(&dir, &later, "dep", "other_api", &[], &[]);
    let root = build_shared(&dir, &root_dir, "root", "root_marker", &["dep"], &[&cwd]);

    let loader_path = format!(":{}", later.display());
    let output = run(Command::new(tool())
        .current_dir(&cwd)
        .arg("--ld-library-path")
        .arg(loader_path)
        .arg("public_api")
        .arg(&root)
        .arg(&fallback));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains(&format!("file={}", cwd_dependency.to_string_lossy())));

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn non_directory_after_empty_component_fails_before_stdout() {
    let dir = temp_dir();
    let root_dir = dir.join("root");
    let cwd = dir.join("cwd");
    let fallback = dir.join("fallback");
    fs::create_dir_all(&fallback).unwrap();
    fs::create_dir_all(&cwd).unwrap();

    let dependency = build_shared(&dir, &cwd, "dep", "public_api", &[], &[]);
    let root = build_shared(&dir, &root_dir, "root", "root_marker", &["dep"], &[&cwd]);
    let not_directory = dir.join("not-a-directory");
    fs::write(&not_directory, b"x").unwrap();

    let loader_path = format!(":{}", not_directory.display());
    let output = Command::new(tool())
        .current_dir(&cwd)
        .arg("--ld-library-path")
        .arg(loader_path)
        .arg("public_api")
        .arg(&root)
        .arg(&fallback)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("not a directory"));
    assert!(dependency.is_file());

    fs::remove_dir_all(dir).unwrap();
}
