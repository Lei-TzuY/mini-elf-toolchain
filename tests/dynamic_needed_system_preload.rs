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
        "mini-elf-system-preload-{}-{stamp}",
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

fn build_shared(work: &Path, stem: &str, symbol: &str) -> PathBuf {
    let source = work.join(format!("{stem}.s"));
    let object = work.join(format!("{stem}.o"));
    let image = work.join(format!("lib{stem}.so"));
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
    run(Command::new("ld")
        .arg("-shared")
        .arg("--hash-style=both")
        .arg("-soname")
        .arg(format!("lib{stem}.so"))
        .arg("-o")
        .arg(&image)
        .arg(&object));
    image
}

fn tool() -> &'static str {
    env!("CARGO_BIN_EXE_mini-elf-needed-system-preload-resolve")
}

#[test]
fn system_preload_file_participates_in_global_scope() {
    let dir = temp_dir();
    let fallback = dir.join("fallback");
    fs::create_dir_all(&fallback).unwrap();
    let root = build_shared(&dir, "root", "root_marker");
    let system_preload = build_shared(&dir, "system_preload", "target");
    let preload_file = dir.join("ld.so.preload");
    fs::write(&preload_file, format!("{}\n", system_preload.display())).unwrap();

    let dynamic = run(Command::new("readelf").arg("-dW").arg(&system_preload));
    let dynamic = String::from_utf8(dynamic.stdout).unwrap();
    assert!(dynamic.contains("(SONAME)"));
    assert!(dynamic.contains("libsystem_preload.so"));

    let output = run(Command::new(tool())
        .env_remove("LD_PRELOAD")
        .arg(&preload_file)
        .arg("target")
        .arg(&root)
        .arg(&fallback));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("system preload file: entries=1"));
    assert!(stdout.contains("LD_PRELOAD dependency scope: root-first preloads=1"));
    assert!(stdout.contains(&format!("file={}", system_preload.to_string_lossy())));

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn ambient_preload_precedes_system_preload_file() {
    let dir = temp_dir();
    let fallback = dir.join("fallback");
    fs::create_dir_all(&fallback).unwrap();
    let root = build_shared(&dir, "root", "root_marker");
    let ambient = build_shared(&dir, "ambient", "target");
    let system = build_shared(&dir, "system", "target");
    let preload_file = dir.join("ld.so.preload");
    fs::write(&preload_file, format!("{}\n", system.display())).unwrap();

    let output = run(Command::new(tool())
        .env("LD_PRELOAD", &ambient)
        .arg(&preload_file)
        .arg("target")
        .arg(&root)
        .arg(&fallback));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("system preload file: entries=1"));
    assert!(stdout.contains("LD_PRELOAD dependency scope: root-first preloads=2"));
    assert!(stdout.contains(&format!("file={}", ambient.to_string_lossy())));
    assert!(!stdout.contains(&format!("file={}", system.to_string_lossy())));

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn secure_mode_suppresses_ambient_preload_but_keeps_system_file() {
    let dir = temp_dir();
    let fallback = dir.join("fallback");
    fs::create_dir_all(&fallback).unwrap();
    let root = build_shared(&dir, "root", "root_marker");
    let ambient = build_shared(&dir, "ambient_secure", "target");
    let system = build_shared(&dir, "system_secure", "target");
    let preload_file = dir.join("ld.so.preload");
    fs::write(&preload_file, format!("{}\n", system.display())).unwrap();

    let output = run(Command::new(tool())
        .env("LD_PRELOAD", &ambient)
        .arg("--secure")
        .arg(&preload_file)
        .arg("target")
        .arg(&root)
        .arg(&fallback));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("system preload file: entries=1 secure=true"));
    assert!(stdout.contains("LD_PRELOAD dependency scope: root-first preloads=1"));
    assert!(stdout.contains(&format!("file={}", system.to_string_lossy())));
    assert!(!stdout.contains(&format!("file={}", ambient.to_string_lossy())));

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn secure_mode_ignores_ld_library_path_for_bare_system_preload() {
    let dir = temp_dir();
    let fallback = dir.join("fallback");
    let loader_path = dir.join("loader-path");
    fs::create_dir_all(&fallback).unwrap();
    fs::create_dir_all(&loader_path).unwrap();
    let root = build_shared(&dir, "root", "root_marker");
    let fallback_preload = build_shared(&fallback, "candidate", "target");
    let loader_preload = build_shared(&loader_path, "candidate", "target");
    let preload_file = dir.join("ld.so.preload");
    fs::write(&preload_file, "libcandidate.so\n").unwrap();

    let output = run(Command::new(tool())
        .env_remove("LD_PRELOAD")
        .env("LD_LIBRARY_PATH", &loader_path)
        .arg("--secure")
        .arg(&preload_file)
        .arg("target")
        .arg(&root)
        .arg(&fallback));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("system preload file: entries=1 secure=true"));
    assert!(stdout.contains(&format!("file={}", fallback_preload.to_string_lossy())));
    assert!(!stdout.contains(&format!("file={}", loader_preload.to_string_lossy())));

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn unreadable_system_preload_file_fails_before_stdout_commit() {
    let dir = temp_dir();
    let fallback = dir.join("fallback");
    fs::create_dir_all(&fallback).unwrap();
    let root = build_shared(&dir, "root", "root_marker");
    let missing = dir.join("missing.preload");

    let output = Command::new(tool())
        .env_remove("LD_PRELOAD")
        .arg(&missing)
        .arg("target")
        .arg(&root)
        .arg(&fallback)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("cannot read system preload file"));

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn colon_in_system_preload_entry_is_rejected_atomically() {
    let dir = temp_dir();
    let fallback = dir.join("fallback");
    fs::create_dir_all(&fallback).unwrap();
    let root = build_shared(&dir, "root", "root_marker");
    let preload_file = dir.join("ld.so.preload");
    fs::write(&preload_file, "libfirst.so:libsecond.so\n").unwrap();

    let output = Command::new(tool())
        .env_remove("LD_PRELOAD")
        .arg(&preload_file)
        .arg("target")
        .arg(&root)
        .arg(&fallback)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("whitespace-separated entries only"));

    fs::remove_dir_all(dir).unwrap();
}
