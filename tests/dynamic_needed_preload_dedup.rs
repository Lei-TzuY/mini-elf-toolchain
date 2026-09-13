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
        "mini-elf-needed-preload-dedup-{}-{stamp}",
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

fn preload_tool() -> &'static str {
    env!("CARGO_BIN_EXE_mini-elf-needed-preload-resolve")
}

fn preload_deps_tool() -> &'static str {
    env!("CARGO_BIN_EXE_mini-elf-needed-preload-deps-resolve")
}

#[test]
fn repeated_explicit_preload_path_is_loaded_once() {
    let dir = temp_dir();
    let root_dir = dir.join("root");
    let preload_dir = dir.join("preload");
    let fallback = dir.join("fallback");
    fs::create_dir_all(&fallback).unwrap();

    let root = build_shared(&dir, &root_dir, "root", "root_marker");
    let preload = build_shared(&dir, &preload_dir, "preload", "target");
    let preload_value = format!("{}:{}", preload.display(), preload.display());

    let dynamic = run(Command::new("readelf").arg("-dW").arg(&preload));
    let dynamic = String::from_utf8(dynamic.stdout).unwrap();
    assert!(dynamic.contains("(SONAME)"));
    assert!(dynamic.contains("libpreload.so"));

    let output = run(Command::new(preload_tool())
        .env("LD_PRELOAD", &preload_value)
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
fn pathname_and_bare_name_resolving_to_same_preload_share_one_scope() {
    let dir = temp_dir();
    let root_dir = dir.join("root");
    let preload_dir = dir.join("preload");
    let fallback = dir.join("fallback");
    fs::create_dir_all(&fallback).unwrap();

    let root = build_shared(&dir, &root_dir, "root", "root_marker");
    let preload = build_shared(&dir, &preload_dir, "preload", "target");
    let preload_value = format!("{}:libpreload.so", preload.display());

    for tool in [preload_tool(), preload_deps_tool()] {
        let output = run(Command::new(tool)
            .env("LD_PRELOAD", &preload_value)
            .env("LD_LIBRARY_PATH", &preload_dir)
            .arg("target")
            .arg(&root)
            .arg(&fallback));
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(stdout.contains("preloads=1"), "stdout={stdout}");
        assert!(stdout.contains(&format!("file={}", preload.to_string_lossy())));
    }

    fs::remove_dir_all(dir).unwrap();
}
