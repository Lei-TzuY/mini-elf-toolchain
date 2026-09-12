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
        "mini-elf-needed-soname-identity-{}-{stamp}",
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
    filename: &str,
    soname: &str,
    symbol: &str,
    dependencies: &[&str],
    link_dirs: &[&Path],
    runpath: Option<&str>,
) -> PathBuf {
    fs::create_dir_all(output_dir).unwrap();
    let object = assemble(work, filename, symbol);
    let image = output_dir.join(filename);
    let mut command = Command::new("ld");
    command
        .arg("-shared")
        .arg("--hash-style=gnu")
        .arg("-soname")
        .arg(soname)
        .arg("-o")
        .arg(&image)
        .arg(&object)
        .arg("--no-as-needed");
    if let Some(runpath) = runpath {
        command
            .arg("--enable-new-dtags")
            .arg(format!("--rpath={runpath}"));
    }
    for directory in link_dirs {
        command.arg("-L").arg(directory);
    }
    for dependency in dependencies {
        command.arg(format!("-l:{dependency}"));
    }
    run(&mut command);
    image
}

fn replace_dynamic_name(path: &Path, old: &[u8], new: &[u8]) {
    assert_eq!(old.len(), new.len());
    let mut bytes = fs::read(path).unwrap();
    let matches = bytes
        .windows(old.len())
        .enumerate()
        .filter_map(|(offset, candidate)| (candidate == old).then_some(offset))
        .collect::<Vec<_>>();
    assert_eq!(matches.len(), 1, "expected one dynamic string match");
    let offset = matches[0];
    bytes[offset..offset + new.len()].copy_from_slice(new);
    fs::write(path, bytes).unwrap();
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

fn corrupt_soname_offset(path: &Path) {
    let mut bytes = fs::read(path).unwrap();
    let phoff = usize::try_from(read_u64(&bytes, 32)).unwrap();
    let phentsize = usize::from(read_u16(&bytes, 54));
    let phnum = usize::from(read_u16(&bytes, 56));
    let dynamic = (0..phnum)
        .map(|index| phoff + index * phentsize)
        .find(|offset| read_u32(&bytes, *offset) == 2)
        .unwrap();
    let dynamic_offset = usize::try_from(read_u64(&bytes, dynamic + 8)).unwrap();
    let dynamic_size = usize::try_from(read_u64(&bytes, dynamic + 32)).unwrap();
    let soname = (0..dynamic_size / 16)
        .map(|index| dynamic_offset + index * 16)
        .find(|offset| i64::from_le_bytes(bytes[*offset..*offset + 8].try_into().unwrap()) == 14)
        .unwrap();
    bytes[soname + 8..soname + 16].copy_from_slice(&u64::MAX.to_le_bytes());
    fs::write(path, bytes).unwrap();
}

fn tool() -> &'static str {
    env!("CARGO_BIN_EXE_mini-elf-needed-runpath-resolve")
}

#[test]
fn earlier_loaded_soname_suppresses_later_transitive_alias_lookup() {
    let dir = temp_dir();
    let root_dir = dir.join("root");
    let plugins = root_dir.join("plugins");
    let fallback = dir.join("fallback");
    fs::create_dir_all(&fallback).unwrap();

    let first = build_shared(
        &dir,
        &plugins,
        "libfirst.so",
        "libcanon.so",
        "public_api",
        &[],
        &[],
        None,
    );
    let bridge = build_shared(
        &dir,
        &plugins,
        "libbridge.so",
        "libbridge.so",
        "bridge_marker",
        &["libfirst.so"],
        &[&plugins],
        None,
    );
    let root = build_shared(
        &dir,
        &root_dir,
        "libroot.so",
        "libroot.so",
        "root_marker",
        &["libfirst.so", "libbridge.so"],
        &[&plugins],
        Some("$ORIGIN/plugins"),
    );

    replace_dynamic_name(&root, b"libcanon.so\0", b"libfirst.so\0");
    fs::write(fallback.join("libcanon.so"), b"not-an-elf").unwrap();

    let root_dynamic = run(Command::new("readelf").arg("-dW").arg(&root));
    let root_dynamic = String::from_utf8(root_dynamic.stdout).unwrap();
    assert!(root_dynamic.contains("Shared library: [libfirst.so]"));
    assert!(root_dynamic.contains("Shared library: [libbridge.so]"));

    let first_dynamic = run(Command::new("readelf").arg("-dW").arg(&first));
    assert!(String::from_utf8(first_dynamic.stdout)
        .unwrap()
        .contains("Library soname: [libcanon.so]"));
    let bridge_dynamic = run(Command::new("readelf").arg("-dW").arg(&bridge));
    assert!(String::from_utf8(bridge_dynamic.stdout)
        .unwrap()
        .contains("Shared library: [libcanon.so]"));

    let output = run(Command::new(tool())
        .arg("public_api")
        .arg(&root)
        .arg(&fallback));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("dependencies=2"));
    assert!(stdout.contains(&format!("file={}", first.to_string_lossy())));

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn malformed_soname_in_discovered_dependency_fails_closed() {
    let dir = temp_dir();
    let root_dir = dir.join("root");
    let plugins = root_dir.join("plugins");
    let fallback = dir.join("fallback");
    fs::create_dir_all(&fallback).unwrap();

    let first = build_shared(
        &dir,
        &plugins,
        "libfirst.so",
        "libfirst.so",
        "public_api",
        &[],
        &[],
        None,
    );
    let root = build_shared(
        &dir,
        &root_dir,
        "libroot.so",
        "libroot.so",
        "root_marker",
        &["libfirst.so"],
        &[&plugins],
        Some("$ORIGIN/plugins"),
    );
    corrupt_soname_offset(&first);

    let output = Command::new(tool())
        .arg("public_api")
        .arg(&root)
        .arg(&fallback)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("DT_SONAME name offset"));

    fs::remove_dir_all(dir).unwrap();
}
