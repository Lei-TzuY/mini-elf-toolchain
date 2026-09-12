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
        "mini-elf-soname-check-{}-{stamp}",
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

fn assemble(work: &Path) -> PathBuf {
    let source = work.join("input.s");
    let object = work.join("input.o");
    fs::write(
        &source,
        ".text\n.globl public_api\n.type public_api,@function\npublic_api:\n  ret\n.size public_api, .-public_api\n",
    )
    .unwrap();
    run(Command::new("as")
        .arg("--64")
        .arg("-o")
        .arg(&object)
        .arg(&source));
    object
}

fn build_shared(work: &Path, name: &str, soname: Option<&str>) -> PathBuf {
    let object = assemble(work);
    let output = work.join(name);
    let mut command = Command::new("ld");
    command
        .arg("-shared")
        .arg("--hash-style=gnu")
        .arg("-o")
        .arg(&output);
    if let Some(soname) = soname {
        command.arg("-soname").arg(soname);
    }
    command.arg(&object);
    run(&mut command);
    output
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
    env!("CARGO_BIN_EXE_mini-elf-soname-check")
}

#[test]
fn reports_gnu_emitted_soname() {
    let dir = temp_dir();
    let shared = build_shared(&dir, "libactual.so", Some("libpublic.so.7"));

    let readelf = run(Command::new("readelf").arg("-dW").arg(&shared));
    let readelf = String::from_utf8(readelf.stdout).unwrap();
    assert!(readelf.contains("(SONAME)"));
    assert!(readelf.contains("libpublic.so.7"));

    let output = run(Command::new(tool()).arg(&shared));
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "DT_SONAME: libpublic.so.7\n"
    );

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn reports_missing_soname_without_guessing_filename() {
    let dir = temp_dir();
    let shared = build_shared(&dir, "libwithout.so", None);

    let readelf = run(Command::new("readelf").arg("-dW").arg(&shared));
    assert!(!String::from_utf8(readelf.stdout).unwrap().contains("(SONAME)"));

    let output = run(Command::new(tool()).arg(&shared));
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "DT_SONAME: <none>\n"
    );

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rejects_soname_offset_outside_dynamic_string_table_atomically() {
    let dir = temp_dir();
    let shared = build_shared(&dir, "libbad.so", Some("libbad.so.1"));
    corrupt_soname_offset(&shared);

    let output = Command::new(tool()).arg(&shared).output().unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("DT_SONAME name offset"));
    assert!(stderr.contains("outside DT_STRSZ"));

    fs::remove_dir_all(dir).unwrap();
}
