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
        "mini-elf-needed-preload-token-{}-{stamp}",
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

fn shared(work: &Path, output: &Path, stem: &str, symbol: &str) -> PathBuf {
    fs::create_dir_all(output).unwrap();
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
    let image = output.join(format!("lib{stem}.so"));
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
    env!("CARGO_BIN_EXE_mini-elf-needed-preload-token-resolve")
}

#[test]
fn origin_lib_platform_preload_path_resolves_before_dependencies() {
    let dir = temp_dir();
    let root_dir = dir.join("root");
    let preload_dir = root_dir.join("lib64").join("x86_64");
    let fallback = dir.join("fallback");
    fs::create_dir_all(&fallback).unwrap();

    let root = shared(&dir, &root_dir, "root", "root_marker");
    let preload = shared(&dir, &preload_dir, "preload", "target");
    let dynamic = run(Command::new("readelf").arg("-dW").arg(&preload));
    assert!(String::from_utf8(dynamic.stdout)
        .unwrap()
        .contains("(SONAME)"));

    let output = run(Command::new(tool())
        .env("LD_PRELOAD", "$ORIGIN/$LIB/$PLATFORM/libpreload.so")
        .env_remove("LD_LIBRARY_PATH")
        .arg("target")
        .arg(&root)
        .arg(&fallback));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("LD_PRELOAD scope: root-first preloads=1"));
    assert!(stdout.contains(&format!("file={}", preload.to_string_lossy())));

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn tokenized_preload_preserves_declared_order() {
    let dir = temp_dir();
    let root_dir = dir.join("root");
    let first_dir = root_dir.join("first");
    let second_dir = dir.join("second");
    let fallback = dir.join("fallback");
    fs::create_dir_all(&fallback).unwrap();

    let root = shared(&dir, &root_dir, "root", "root_marker");
    let first = shared(&dir, &first_dir, "first", "target");
    let second = shared(&dir, &second_dir, "second", "target");
    let value = format!("$ORIGIN/first/libfirst.so:{}", second.display());

    let output = run(Command::new(tool())
        .env("LD_PRELOAD", value)
        .arg("target")
        .arg(&root)
        .arg(&fallback));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("preloads=2"));
    assert!(stdout.contains(&format!("file={}", first.to_string_lossy())));
    assert!(!stdout.contains(&format!("file={}", second.to_string_lossy())));

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn malformed_or_unanchored_tokens_fail_before_stdout() {
    let dir = temp_dir();
    let root_dir = dir.join("root");
    let fallback = dir.join("fallback");
    fs::create_dir_all(&fallback).unwrap();
    let root = shared(&dir, &root_dir, "root", "root_marker");

    for value in [
        "$ORIGIN/../libpreload.so",
        "prefix/$ORIGIN/libpreload.so",
        "$PLATFORM",
    ] {
        let output = Command::new(tool())
            .env("LD_PRELOAD", value)
            .arg("root_marker")
            .arg(&root)
            .arg(&fallback)
            .output()
            .unwrap();
        assert!(!output.status.success(), "value={value}");
        assert!(output.stdout.is_empty(), "value={value}");
        assert!(!output.stderr.is_empty(), "value={value}");
    }

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn secure_mode_ignores_malformed_tokenized_preload() {
    let dir = temp_dir();
    let root_dir = dir.join("root");
    let fallback = dir.join("fallback");
    fs::create_dir_all(&fallback).unwrap();
    let root = shared(&dir, &root_dir, "root", "target");

    let output = run(Command::new(tool())
        .env("LD_PRELOAD", "$ORIGIN/../bad.so")
        .arg("--secure")
        .arg("target")
        .arg(&root)
        .arg(&fallback));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(!stdout.contains("LD_PRELOAD scope"));
    assert!(stdout.contains(&format!("file={}", root.to_string_lossy())));

    fs::remove_dir_all(dir).unwrap();
}
