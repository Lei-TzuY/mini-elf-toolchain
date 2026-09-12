use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

const PT_DYNAMIC: u32 = 2;
const DT_NEEDED: i64 = 1;
const DT_FLAGS_1: i64 = 0x6fff_fffb;

fn temp_dir() -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "mini-elf-needed-nodefaultlib-{}-{stamp}",
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

fn build_dependency(work: &Path, directory: &Path) -> PathBuf {
    fs::create_dir_all(directory).unwrap();
    let object = assemble(work, "dependency", "dep_api");
    let image = directory.join("libdep.so");
    run(Command::new("ld")
        .arg("-shared")
        .arg("--hash-style=gnu")
        .arg("-soname")
        .arg("libdep.so")
        .arg("-o")
        .arg(&image)
        .arg(&object));
    image
}

fn build_root(work: &Path, link_dir: &Path) -> PathBuf {
    let object = assemble(work, "root", "root_api");
    let image = work.join("libroot.so");
    run(Command::new("ld")
        .arg("-shared")
        .arg("--hash-style=gnu")
        .arg("-z")
        .arg("nodefaultlib")
        .arg("--no-as-needed")
        .arg("-L")
        .arg(link_dir)
        .arg("-ldep")
        .arg("-o")
        .arg(&image)
        .arg(&object));
    image
}

fn build_grandchild(work: &Path, directory: &Path) -> PathBuf {
    fs::create_dir_all(directory).unwrap();
    let object = assemble(work, "grandchild", "grand_api");
    let image = directory.join("libgrand.so");
    run(Command::new("ld")
        .arg("-shared")
        .arg("--hash-style=gnu")
        .arg("-soname")
        .arg("libgrand.so")
        .arg("-o")
        .arg(&image)
        .arg(&object));
    image
}

fn build_middle(work: &Path, directory: &Path, grandchild_dir: &Path, nodefaultlib: bool) -> PathBuf {
    fs::create_dir_all(directory).unwrap();
    let object = assemble(work, "middle", "middle_api");
    let image = directory.join("libmiddle.so");
    let mut command = Command::new("ld");
    command
        .arg("-shared")
        .arg("--hash-style=gnu")
        .arg("-soname")
        .arg("libmiddle.so");
    if nodefaultlib {
        command.arg("-z").arg("nodefaultlib");
    }
    command
        .arg("--no-as-needed")
        .arg("-L")
        .arg(grandchild_dir)
        .arg("-lgrand")
        .arg("-o")
        .arg(&image)
        .arg(&object);
    run(&mut command);
    image
}

fn build_chain_root(work: &Path, middle_dir: &Path, nodefaultlib: bool) -> PathBuf {
    let object = assemble(work, "chain-root", "chain_root_api");
    let image = work.join("libchain-root.so");
    let mut command = Command::new("ld");
    command.arg("-shared").arg("--hash-style=gnu");
    if nodefaultlib {
        command.arg("-z").arg("nodefaultlib");
    }
    command
        .arg("--no-as-needed")
        .arg("-L")
        .arg(middle_dir)
        .arg("-lmiddle")
        .arg("-o")
        .arg(&image)
        .arg(&object);
    run(&mut command);
    image
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn read_i64(bytes: &[u8], offset: usize) -> i64 {
    i64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn corrupt_first_needed_to_duplicate_flags_1(image: &Path) {
    let mut bytes = fs::read(image).unwrap();
    let program_header_offset = usize::try_from(read_u64(&bytes, 32)).unwrap();
    let program_header_size = usize::from(read_u16(&bytes, 54));
    let program_header_count = usize::from(read_u16(&bytes, 56));
    let dynamic = (0..program_header_count)
        .map(|index| program_header_offset + index * program_header_size)
        .find(|offset| read_u32(&bytes, *offset) == PT_DYNAMIC)
        .unwrap();
    let dynamic_offset = usize::try_from(read_u64(&bytes, dynamic + 8)).unwrap();
    let dynamic_size = usize::try_from(read_u64(&bytes, dynamic + 32)).unwrap();
    let mut needed_offset = None;
    let mut flags_1_value = None;
    for offset in (dynamic_offset..dynamic_offset + dynamic_size).step_by(16) {
        match read_i64(&bytes, offset) {
            DT_NEEDED if needed_offset.is_none() => needed_offset = Some(offset),
            DT_FLAGS_1 => flags_1_value = Some(read_u64(&bytes, offset + 8)),
            0 => break,
            _ => {}
        }
    }
    let needed_offset = needed_offset.expect("middle DSO should contain DT_NEEDED");
    let flags_1_value = flags_1_value.expect("middle DSO should contain DT_FLAGS_1");
    bytes[needed_offset..needed_offset + 8].copy_from_slice(&DT_FLAGS_1.to_le_bytes());
    bytes[needed_offset + 8..needed_offset + 16].copy_from_slice(&flags_1_value.to_le_bytes());
    fs::write(image, bytes).unwrap();
}

fn tool() -> &'static str {
    env!("CARGO_BIN_EXE_mini-elf-needed-nodefaultlib-resolve")
}

#[test]
fn nodefaultlib_suppresses_fallback_directory() {
    let dir = temp_dir();
    let fallback = dir.join("fallback");
    build_dependency(&dir, &fallback);
    let root = build_root(&dir, &fallback);

    let dynamic = run(Command::new("readelf").arg("-dW").arg(&root));
    let dynamic = String::from_utf8(dynamic.stdout).unwrap();
    assert!(dynamic.contains("FLAGS_1"));
    assert!(dynamic.contains("NODEFLIB"));

    let output = Command::new(tool())
        .arg("dep_api")
        .arg(&root)
        .arg(&fallback)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("DF_1_NODEFLIB suppressed fallback directory"));
    assert!(stderr.contains("cannot resolve DT_NEEDED dependency 'libdep.so'"));

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn nodefaultlib_keeps_explicit_loader_path_search() {
    let dir = temp_dir();
    let loader = dir.join("loader");
    let fallback = dir.join("fallback");
    fs::create_dir_all(&fallback).unwrap();
    let dependency = build_dependency(&dir, &loader);
    let root = build_root(&dir, &loader);

    let output = run(Command::new(tool())
        .arg("--ld-library-path")
        .arg(&loader)
        .arg("dep_api")
        .arg(&root)
        .arg(&fallback));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("nodefaultlib-objects=1"));
    assert!(stdout.contains("loader-path-directories=1"));
    assert!(stdout.contains(&format!("file={}", dependency.to_string_lossy())));

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn transitive_nodefaultlib_suppresses_only_the_marked_loaders_fallback_lookup() {
    let dir = temp_dir();
    let loader = dir.join("loader");
    let fallback = dir.join("fallback");
    build_grandchild(&dir, &fallback);
    let middle = build_middle(&dir, &loader, &fallback, true);
    let root = build_chain_root(&dir, &loader, false);

    let dynamic = run(Command::new("readelf").arg("-dW").arg(&middle));
    let dynamic = String::from_utf8(dynamic.stdout).unwrap();
    assert!(dynamic.contains("FLAGS_1"));
    assert!(dynamic.contains("NODEFLIB"));

    let output = Command::new(tool())
        .arg("--ld-library-path")
        .arg(&loader)
        .arg("grand_api")
        .arg(&root)
        .arg(&fallback)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("DF_1_NODEFLIB suppressed fallback directory"));
    assert!(stderr.contains(&format!("for loader '{}'", middle.display())));
    assert!(stderr.contains("cannot resolve DT_NEEDED dependency 'libgrand.so'"));

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn root_nodefaultlib_does_not_propagate_to_an_unmarked_child() {
    let dir = temp_dir();
    let loader = dir.join("loader");
    let fallback = dir.join("fallback");
    let grandchild = build_grandchild(&dir, &fallback);
    build_middle(&dir, &loader, &fallback, false);
    let root = build_chain_root(&dir, &loader, true);

    let output = run(Command::new(tool())
        .arg("--ld-library-path")
        .arg(&loader)
        .arg("grand_api")
        .arg(&root)
        .arg(&fallback));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("nodefaultlib-objects=1"));
    assert!(stdout.contains("dependencies=2"));
    assert!(stdout.contains(&format!("file={}", grandchild.to_string_lossy())));

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn malformed_transitive_dynamic_flags_fail_before_partial_output() {
    let dir = temp_dir();
    let loader = dir.join("loader");
    let fallback = dir.join("fallback");
    build_grandchild(&dir, &fallback);
    let middle = build_middle(&dir, &loader, &fallback, true);
    let root = build_chain_root(&dir, &loader, false);
    corrupt_first_needed_to_duplicate_flags_1(&middle);

    let output = Command::new(tool())
        .arg("--ld-library-path")
        .arg(&loader)
        .arg("middle_api")
        .arg(&root)
        .arg(&fallback)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("DT_FLAGS_1"));
    assert!(stderr.contains("multiple"));

    fs::remove_dir_all(dir).unwrap();
}
