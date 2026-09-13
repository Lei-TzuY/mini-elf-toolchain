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
        "mini-elf-needed-preload-{}-{stamp}",
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
        .arg("--hash-style=both")
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
    env!("CARGO_BIN_EXE_mini-elf-needed-preload-resolve")
}

#[test]
fn preload_symbol_precedes_needed_dependency() {
    let dir = temp_dir();
    let root_dir = dir.join("root");
    let preload_dir = dir.join("preload");
    let fallback = dir.join("fallback");

    let fallback_dependency = build_shared(&dir, &fallback, "dep", "target", &[], &[]);
    let preload = build_shared(&dir, &preload_dir, "preload", "target", &[], &[]);
    let root = build_shared(
        &dir,
        &root_dir,
        "root",
        "root_marker",
        &["dep"],
        &[&fallback],
    );

    let dynamic = run(Command::new("readelf").arg("-dW").arg(&root));
    let dynamic = String::from_utf8(dynamic.stdout).unwrap();
    assert!(dynamic.contains("(NEEDED)"));
    assert!(dynamic.contains("libdep.so"));

    let baseline = run(Command::new(tool())
        .env_remove("LD_PRELOAD")
        .env_remove("LD_LIBRARY_PATH")
        .arg("target")
        .arg(&root)
        .arg(&fallback));
    let baseline = String::from_utf8(baseline.stdout).unwrap();
    assert!(baseline.contains(&format!("file={}", fallback_dependency.to_string_lossy())));

    let output = run(Command::new(tool())
        .env("LD_PRELOAD", &preload)
        .env_remove("LD_LIBRARY_PATH")
        .arg("target")
        .arg(&root)
        .arg(&fallback));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("LD_PRELOAD scope: root-first preloads=1"));
    assert!(stdout.contains(&format!("file={}", preload.to_string_lossy())));
    assert!(!stdout.contains(&format!("file={}", fallback_dependency.to_string_lossy())));

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn root_symbol_precedes_preload_and_preloads_keep_declared_order() {
    let dir = temp_dir();
    let root_dir = dir.join("root");
    let preload_dir = dir.join("preload");
    let fallback = dir.join("fallback");
    fs::create_dir_all(&fallback).unwrap();

    let first = build_shared(&dir, &preload_dir, "first", "target", &[], &[]);
    let second = build_shared(&dir, &preload_dir, "second", "target", &[], &[]);
    let root_without_target = build_shared(&dir, &root_dir, "plain", "root_marker", &[], &[]);
    let preload_value = format!("{}:{}", first.display(), second.display());

    let output = run(Command::new(tool())
        .env("LD_PRELOAD", &preload_value)
        .arg("target")
        .arg(&root_without_target)
        .arg(&fallback));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("preloads=2"));
    assert!(stdout.contains(&format!("file={}", first.to_string_lossy())));
    assert!(!stdout.contains(&format!("file={}", second.to_string_lossy())));

    let root_with_target = build_shared(&dir, &root_dir, "winner", "target", &[], &[]);
    let output = run(Command::new(tool())
        .env("LD_PRELOAD", &preload_value)
        .arg("target")
        .arg(&root_with_target)
        .arg(&fallback));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains(&format!("file={}", root_with_target.to_string_lossy())));
    assert!(!stdout.contains(&format!("file={}", first.to_string_lossy())));

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn secure_mode_suppresses_preload_namespace() {
    let dir = temp_dir();
    let root_dir = dir.join("root");
    let preload_dir = dir.join("preload");
    let fallback = dir.join("fallback");

    let fallback_dependency = build_shared(&dir, &fallback, "dep", "target", &[], &[]);
    let preload = build_shared(&dir, &preload_dir, "preload", "target", &[], &[]);
    let root = build_shared(
        &dir,
        &root_dir,
        "root",
        "root_marker",
        &["dep"],
        &[&fallback],
    );

    let output = run(Command::new(tool())
        .env("LD_PRELOAD", &preload)
        .env_remove("LD_LIBRARY_PATH")
        .arg("--secure")
        .arg("target")
        .arg(&root)
        .arg(&fallback));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(!stdout.contains("LD_PRELOAD scope"));
    assert!(stdout.contains(&format!("file={}", fallback_dependency.to_string_lossy())));

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn malformed_later_preload_fails_before_stdout() {
    let dir = temp_dir();
    let root_dir = dir.join("root");
    let preload_dir = dir.join("preload");
    let fallback = dir.join("fallback");
    fs::create_dir_all(&fallback).unwrap();

    let preload = build_shared(&dir, &preload_dir, "preload", "target", &[], &[]);
    let malformed = dir.join("not-elf.so");
    fs::write(&malformed, b"not an ELF image").unwrap();
    let root = build_shared(&dir, &root_dir, "root", "root_marker", &[], &[]);
    let preload_value = format!("{}:{}", preload.display(), malformed.display());

    let output = Command::new(tool())
        .env("LD_PRELOAD", &preload_value)
        .arg("target")
        .arg(&root)
        .arg(&fallback)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(
        !output.stderr.is_empty(),
        "malformed preload should produce a diagnostic"
    );

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn bare_and_non_normalized_preload_entries_fail_closed() {
    let dir = temp_dir();
    let root_dir = dir.join("root");
    let fallback = dir.join("fallback");
    fs::create_dir_all(&fallback).unwrap();
    let root = build_shared(&dir, &root_dir, "root", "root_marker", &[], &[]);

    let bare = Command::new(tool())
        .env("LD_PRELOAD", "libpreload.so")
        .arg("root_marker")
        .arg(&root)
        .arg(&fallback)
        .output()
        .unwrap();
    assert!(!bare.status.success());
    assert!(bare.stdout.is_empty());
    assert!(String::from_utf8_lossy(&bare.stderr).contains("bare library name"));

    let traversal = Command::new(tool())
        .current_dir(&dir)
        .env("LD_PRELOAD", "preload/../libpreload.so")
        .arg("root_marker")
        .arg(&root)
        .arg(&fallback)
        .output()
        .unwrap();
    assert!(!traversal.status.success());
    assert!(traversal.stdout.is_empty());
    assert!(String::from_utf8_lossy(&traversal.stderr).contains("not a normalized pathname"));

    fs::remove_dir_all(dir).unwrap();
}
