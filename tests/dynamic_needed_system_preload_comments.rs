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
        "mini-elf-system-preload-comments-{}-{stamp}",
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
fn comments_are_ignored_without_changing_entry_order() {
    let dir = temp_dir();
    let fallback = dir.join("fallback");
    fs::create_dir_all(&fallback).unwrap();
    let root = build_shared(&dir, "root", "root_marker");
    let first = build_shared(&dir, "first", "target");
    let second = build_shared(&dir, "second", "target");
    let preload_file = dir.join("ld.so.preload");
    fs::write(
        &preload_file,
        format!(
            "# leading comment\n{} # first wins\n\n  # indented comment\n{}\n",
            first.display(),
            second.display()
        ),
    )
    .unwrap();

    let dynamic = run(Command::new("readelf").arg("-dW").arg(&first));
    let dynamic = String::from_utf8(dynamic.stdout).unwrap();
    assert!(dynamic.contains("(SONAME)"));
    assert!(dynamic.contains("libfirst.so"));

    let output = run(Command::new(tool())
        .env_remove("LD_PRELOAD")
        .arg(&preload_file)
        .arg("target")
        .arg(&root)
        .arg(&fallback));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("system preload file: entries=2"));
    assert!(stdout.contains("LD_PRELOAD dependency scope: root-first preloads=2"));
    assert!(stdout.contains(&format!("file={}", first.to_string_lossy())));
    assert!(!stdout.contains(&format!("file={}", second.to_string_lossy())));

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn colon_before_comment_is_still_rejected_atomically() {
    let dir = temp_dir();
    let fallback = dir.join("fallback");
    fs::create_dir_all(&fallback).unwrap();
    let root = build_shared(&dir, "root", "root_marker");
    let preload_file = dir.join("ld.so.preload");
    fs::write(
        &preload_file,
        "libfirst.so:libsecond.so # malformed entry\n",
    )
    .unwrap();

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
