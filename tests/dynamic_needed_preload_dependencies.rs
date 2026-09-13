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
        "mini-elf-needed-preload-deps-{}-{stamp}",
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

fn build_shared_with_system_dependency(
    work: &Path,
    output_dir: &Path,
    stem: &str,
    symbol: &str,
    library: &str,
) -> (PathBuf, String) {
    fs::create_dir_all(output_dir).unwrap();
    let object = assemble(work, stem, symbol);
    let query = format!("-print-file-name={library}");
    let located = run(Command::new("cc").arg(query));
    let located = String::from_utf8(located.stdout).unwrap();
    let located = located.trim();
    assert_ne!(located, library, "compiler could not locate {library}");
    let system_library = PathBuf::from(located);
    assert!(system_library.is_file(), "missing system library {located}");

    let image = output_dir.join(format!("lib{stem}.so"));
    run(Command::new("ld")
        .arg("-shared")
        .arg("--hash-style=both")
        .arg("-soname")
        .arg(format!("lib{stem}.so"))
        .arg("-o")
        .arg(&image)
        .arg(&object)
        .arg("--no-as-needed")
        .arg(&system_library));
    (image, library.to_owned())
}

fn tool() -> &'static str {
    env!("CARGO_BIN_EXE_mini-elf-needed-preload-deps-resolve")
}

#[test]
fn preload_dependency_precedes_root_dependency() {
    let dir = temp_dir();
    let root_dir = dir.join("root");
    let preload_dir = dir.join("preload");
    let fallback = dir.join("fallback");

    let preload_dependency = build_shared(&dir, &fallback, "predep", "target", &[], &[]);
    let root_dependency = build_shared(&dir, &fallback, "rootdep", "target", &[], &[]);
    let preload = build_shared(
        &dir,
        &preload_dir,
        "preload",
        "preload_marker",
        &["predep"],
        &[&fallback],
    );
    let root = build_shared(
        &dir,
        &root_dir,
        "root",
        "root_marker",
        &["rootdep"],
        &[&fallback],
    );

    let dynamic = run(Command::new("readelf").arg("-dW").arg(&preload));
    let dynamic = String::from_utf8(dynamic.stdout).unwrap();
    assert!(dynamic.contains("(NEEDED)"));
    assert!(dynamic.contains("libpredep.so"));

    let output = run(Command::new(tool())
        .env("LD_PRELOAD", &preload)
        .env("LD_LIBRARY_PATH", &fallback)
        .arg("target")
        .arg(&root)
        .arg(&fallback));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("LD_PRELOAD dependency scope: root-first preloads=1"));
    assert!(stdout.contains(&format!("file={}", preload_dependency.to_string_lossy())));
    assert!(!stdout.contains(&format!("file={}", root_dependency.to_string_lossy())));

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn tokenized_preload_dependency_participates_in_scope() {
    let dir = temp_dir();
    let root_dir = dir.join("root");
    let preload_dir = root_dir.join("preloads");
    let fallback = dir.join("fallback");

    let preload_dependency = build_shared(&dir, &fallback, "predep", "target", &[], &[]);
    let preload = build_shared(
        &dir,
        &preload_dir,
        "preload",
        "preload_marker",
        &["predep"],
        &[&fallback],
    );
    let root = build_shared(&dir, &root_dir, "root", "root_marker", &[], &[]);

    let dynamic = run(Command::new("readelf").arg("-dW").arg(&preload));
    let dynamic = String::from_utf8(dynamic.stdout).unwrap();
    assert!(dynamic.contains("(NEEDED)"));
    assert!(dynamic.contains("libpredep.so"));

    let output = run(Command::new(tool())
        .env("LD_PRELOAD", "$ORIGIN/preloads/libpreload.so")
        .env("LD_LIBRARY_PATH", &fallback)
        .arg("target")
        .arg(&root)
        .arg(&fallback));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("LD_PRELOAD dependency scope: root-first preloads=1"));
    assert!(stdout.contains(&format!("file={}", preload_dependency.to_string_lossy())));

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn later_preload_image_precedes_earlier_preload_dependency() {
    let dir = temp_dir();
    let root_dir = dir.join("root");
    let preload_dir = dir.join("preload");
    let fallback = dir.join("fallback");

    let preload_dependency = build_shared(&dir, &fallback, "predep", "target", &[], &[]);
    let first = build_shared(
        &dir,
        &preload_dir,
        "first",
        "first_marker",
        &["predep"],
        &[&fallback],
    );
    let second = build_shared(&dir, &preload_dir, "second", "target", &[], &[]);
    let root = build_shared(&dir, &root_dir, "root", "root_marker", &[], &[]);
    let preload_value = format!("{}:{}", first.display(), second.display());

    let output = run(Command::new(tool())
        .env("LD_PRELOAD", &preload_value)
        .env("LD_LIBRARY_PATH", &fallback)
        .arg("target")
        .arg(&root)
        .arg(&fallback));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains(&format!("file={}", second.to_string_lossy())));
    assert!(!stdout.contains(&format!("file={}", preload_dependency.to_string_lossy())));

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn malformed_tokenized_preload_fails_before_stdout() {
    let dir = temp_dir();
    let root_dir = dir.join("root");
    let fallback = dir.join("fallback");
    fs::create_dir_all(&fallback).unwrap();
    let root = build_shared(&dir, &root_dir, "root", "root_marker", &[], &[]);

    let output = Command::new(tool())
        .env("LD_PRELOAD", "$ORIGIN/../bad.so")
        .arg("root_marker")
        .arg(&root)
        .arg(&fallback)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).starts_with("error: "));

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn malformed_preload_dependency_fails_before_stdout() {
    let dir = temp_dir();
    let root_dir = dir.join("root");
    let preload_dir = dir.join("preload");
    let fallback = dir.join("fallback");
    fs::create_dir_all(&fallback).unwrap();

    let (preload, needed_name) = build_shared_with_system_dependency(
        &dir,
        &preload_dir,
        "preload",
        "preload_marker",
        "libm.so.6",
    );
    let root = build_shared(&dir, &root_dir, "root", "target", &[], &[]);
    let malformed_dependency = fallback.join(&needed_name);
    fs::write(&malformed_dependency, b"not an ELF image").unwrap();

    let dynamic = run(Command::new("readelf").arg("-dW").arg(&preload));
    let dynamic = String::from_utf8(dynamic.stdout).unwrap();
    assert!(dynamic.contains("(NEEDED)"));
    assert!(dynamic.contains(&needed_name));

    let output = Command::new(tool())
        .env("LD_PRELOAD", &preload)
        .env_remove("LD_LIBRARY_PATH")
        .arg("target")
        .arg(&root)
        .arg(&fallback)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).starts_with("error: "));

    fs::remove_dir_all(dir).unwrap();
}
