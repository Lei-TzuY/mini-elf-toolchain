#![cfg(unix)]

use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_dir() -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "mini-elf-needed-preload-identity-{}-{stamp}",
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

fn build_shared(work: &Path, output_dir: &Path, stem: &str, symbol: &str) -> PathBuf {
    fs::create_dir_all(output_dir).unwrap();
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

    let image = output_dir.join(format!("lib{stem}.so"));
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

fn tools() -> [&'static str; 2] {
    [
        env!("CARGO_BIN_EXE_mini-elf-needed-preload-resolve"),
        env!("CARGO_BIN_EXE_mini-elf-needed-preload-deps-resolve"),
    ]
}

fn assert_aliases_deduplicate(preload_value: String, preload: &Path, root: &Path, fallback: &Path) {
    for tool in tools() {
        let output = run(Command::new(tool)
            .env("LD_PRELOAD", &preload_value)
            .env_remove("LD_LIBRARY_PATH")
            .arg("target")
            .arg(root)
            .arg(fallback));
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(stdout.contains("preloads=1"), "stdout={stdout}");
        assert!(stdout.contains(&format!("file={}", preload.to_string_lossy())));
    }
}

#[test]
fn symlink_aliases_share_one_preload_identity() {
    let dir = temp_dir();
    let root_dir = dir.join("root");
    let preload_dir = dir.join("preload");
    let fallback = dir.join("fallback");
    fs::create_dir_all(&fallback).unwrap();

    let root = build_shared(&dir, &root_dir, "root", "root_marker");
    let preload = build_shared(&dir, &preload_dir, "preload", "target");
    let alias = preload_dir.join("libpreload-alias.so");
    symlink(&preload, &alias).unwrap();

    let dynamic = run(Command::new("readelf").arg("-dW").arg(&preload));
    assert!(String::from_utf8(dynamic.stdout).unwrap().contains("libpreload.so"));

    assert_aliases_deduplicate(
        format!("{}:{}", preload.display(), alias.display()),
        &preload,
        &root,
        &fallback,
    );

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn hard_link_aliases_share_one_preload_identity() {
    let dir = temp_dir();
    let root_dir = dir.join("root");
    let preload_dir = dir.join("preload");
    let fallback = dir.join("fallback");
    fs::create_dir_all(&fallback).unwrap();

    let root = build_shared(&dir, &root_dir, "root", "root_marker");
    let preload = build_shared(&dir, &preload_dir, "preload", "target");
    let alias = preload_dir.join("libpreload-hardlink.so");
    fs::hard_link(&preload, &alias).unwrap();

    assert_aliases_deduplicate(
        format!("{}:{}", preload.display(), alias.display()),
        &preload,
        &root,
        &fallback,
    );

    fs::remove_dir_all(dir).unwrap();
}
