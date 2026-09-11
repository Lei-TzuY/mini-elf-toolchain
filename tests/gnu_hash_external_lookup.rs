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
        "mini-elf-gnu-hash-external-lookup-{}-{stamp}",
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

fn build_gnu_hash_so(dir: &Path) -> PathBuf {
    let source = dir.join("fixture.s");
    let object = dir.join("fixture.o");
    let image = dir.join("fixture.so");
    fs::write(
        &source,
        ".text\n.globl public_api\n.type public_api,@function\npublic_api:\n  ret\n.size public_api, .-public_api\n",
    )
    .unwrap();
    run(Command::new("as").arg("--64").arg("-o").arg(&object).arg(&source));
    run(
        Command::new("ld")
            .arg("-shared")
            .arg("--hash-style=gnu")
            .arg("-o")
            .arg(&image)
            .arg(&object),
    );
    image
}

fn tool() -> &'static str {
    env!("CARGO_BIN_EXE_mini-elf-gnu-hash-external-lookup")
}

fn checked_lookup() -> &'static str {
    env!("CARGO_BIN_EXE_mini-elf-gnu-hash-lookup")
}

fn symbol_index(image: &Path) -> u32 {
    let output = run(Command::new(checked_lookup()).arg("public_api").arg(image));
    let stdout = String::from_utf8(output.stdout).unwrap();
    let marker = " index=";
    let start = stdout.find(marker).unwrap() + marker.len();
    let end = stdout[start..].find(' ').unwrap() + start;
    stdout[start..end].parse().unwrap()
}

fn dynsym_entry_offset(bytes: &[u8], index: u32) -> usize {
    let shoff = usize::try_from(u64::from_le_bytes(bytes[40..48].try_into().unwrap())).unwrap();
    let shentsize = usize::from(u16::from_le_bytes(bytes[58..60].try_into().unwrap()));
    let shnum = usize::from(u16::from_le_bytes(bytes[60..62].try_into().unwrap()));
    assert_eq!(shentsize, 64);
    for section in 0..shnum {
        let cursor = shoff + section * shentsize;
        let kind = u32::from_le_bytes(bytes[cursor + 4..cursor + 8].try_into().unwrap());
        if kind == 11 {
            let offset = usize::try_from(u64::from_le_bytes(
                bytes[cursor + 24..cursor + 32].try_into().unwrap(),
            ))
            .unwrap();
            let size = usize::try_from(u64::from_le_bytes(
                bytes[cursor + 32..cursor + 40].try_into().unwrap(),
            ))
            .unwrap();
            let entsize = usize::try_from(u64::from_le_bytes(
                bytes[cursor + 56..cursor + 64].try_into().unwrap(),
            ))
            .unwrap();
            assert_eq!(entsize, 24);
            let entry = offset + usize::try_from(index).unwrap() * entsize;
            assert!(entry + entsize <= offset + size);
            return entry;
        }
    }
    panic!("fixture is missing SHT_DYNSYM");
}

#[test]
fn resolves_default_visible_defined_global_from_real_gnu_hash_image() {
    let dir = temp_dir();
    let image = build_gnu_hash_so(&dir);

    let dynamic = run(Command::new("readelf").arg("-dW").arg(&image));
    let dynamic = String::from_utf8(dynamic.stdout).unwrap();
    assert!(dynamic.contains("GNU_HASH"));
    assert!(!dynamic.lines().any(|line| line.contains("(HASH)")));

    let symbols = run(Command::new("readelf").arg("--dyn-syms").arg("-W").arg(&image));
    let symbols = String::from_utf8(symbols.stdout).unwrap();
    assert!(symbols.lines().any(|line| {
        line.contains("GLOBAL") && line.contains("DEFAULT") && line.ends_with(" public_api")
    }));

    let output = run(Command::new(tool()).arg("public_api").arg(&image));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("GNU external lookup: symbol=public_api index="));
    assert!(stdout.contains("bind=1"));
    assert!(stdout.contains("visibility=0"));
    assert!(!stdout.contains("not-found"));

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rejects_hidden_local_and_undefined_matches_without_changing_hash_membership() {
    let dir = temp_dir();
    let image = build_gnu_hash_so(&dir);
    let index = symbol_index(&image);
    let original = fs::read(&image).unwrap();
    let entry = dynsym_entry_offset(&original, index);

    let hidden = dir.join("hidden.so");
    let mut bytes = original.clone();
    bytes[entry + 5] = (bytes[entry + 5] & !0x03) | 0x02;
    fs::write(&hidden, bytes).unwrap();
    let raw = run(Command::new(checked_lookup()).arg("public_api").arg(&hidden));
    assert!(String::from_utf8(raw.stdout).unwrap().contains("index="));
    let output = run(Command::new(tool()).arg("public_api").arg(&hidden));
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "GNU external lookup: symbol=public_api not-found\n"
    );

    let local = dir.join("local.so");
    let mut bytes = original.clone();
    bytes[entry + 4] &= 0x0f;
    fs::write(&local, bytes).unwrap();
    let output = run(Command::new(tool()).arg("public_api").arg(&local));
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "GNU external lookup: symbol=public_api not-found\n"
    );

    let undefined = dir.join("undefined.so");
    let mut bytes = original;
    bytes[entry + 6..entry + 8].copy_from_slice(&0u16.to_le_bytes());
    fs::write(&undefined, bytes).unwrap();
    let output = run(Command::new(tool()).arg("public_api").arg(&undefined));
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "GNU external lookup: symbol=public_api not-found\n"
    );

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn malformed_later_input_keeps_stdout_atomic() {
    let dir = temp_dir();
    let good = build_gnu_hash_so(&dir);
    let bad = dir.join("bad.so");
    let mut bytes = fs::read(&good).unwrap();
    bytes[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
    fs::write(&bad, bytes).unwrap();

    let output = Command::new(tool())
        .arg("public_api")
        .arg(&good)
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.is_empty());

    fs::remove_dir_all(dir).unwrap();
}
