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
        "mini-elf-sysv-hash-resolve-{}-{stamp}",
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

fn build_sysv_hash_so(dir: &Path, stem: &str) -> PathBuf {
    let source = dir.join(format!("{stem}.s"));
    let object = dir.join(format!("{stem}.o"));
    let image = dir.join(format!("{stem}.so"));
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
    run(Command::new("ld")
        .arg("-shared")
        .arg("--hash-style=sysv")
        .arg("-o")
        .arg(&image)
        .arg(&object));
    image
}

fn tool() -> &'static str {
    env!("CARGO_BIN_EXE_mini-elf-sysv-hash-resolve")
}

fn checked_lookup() -> &'static str {
    env!("CARGO_BIN_EXE_mini-elf-sysv-hash-lookup")
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
            let entsize = usize::try_from(u64::from_le_bytes(
                bytes[cursor + 56..cursor + 64].try_into().unwrap(),
            ))
            .unwrap();
            assert_eq!(entsize, 24);
            return offset + usize::try_from(index).unwrap() * entsize;
        }
    }
    panic!("fixture is missing SHT_DYNSYM");
}

#[test]
fn resolves_first_eligible_definition_in_explicit_input_order() {
    let dir = temp_dir();
    let first = build_sysv_hash_so(&dir, "first");
    let second = build_sysv_hash_so(&dir, "second");

    for image in [&first, &second] {
        let dynamic = run(Command::new("readelf").arg("-dW").arg(image));
        let dynamic = String::from_utf8(dynamic.stdout).unwrap();
        assert!(dynamic.lines().any(|line| line.contains("(HASH)")));
        assert!(!dynamic.contains("GNU_HASH"));
        let symbols = run(Command::new("readelf")
            .arg("--dyn-syms")
            .arg("-W")
            .arg(image));
        assert!(String::from_utf8(symbols.stdout)
            .unwrap()
            .lines()
            .any(|line| line.ends_with(" public_api")));
    }

    let output = run(Command::new(tool())
        .arg("public_api")
        .arg(&first)
        .arg(&second));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains(&format!("file={}", first.to_string_lossy())));
    assert!(!stdout.contains(&format!("file={}", second.to_string_lossy())));

    let output = run(Command::new(tool())
        .arg("public_api")
        .arg(&second)
        .arg(&first));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains(&format!("file={}", second.to_string_lossy())));
    assert!(!stdout.contains(&format!("file={}", first.to_string_lossy())));

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn skips_ineligible_earlier_match_and_resolves_later_definition() {
    let dir = temp_dir();
    let first = build_sysv_hash_so(&dir, "first");
    let second = build_sysv_hash_so(&dir, "second");
    let index = symbol_index(&first);
    let mut bytes = fs::read(&first).unwrap();
    let entry = dynsym_entry_offset(&bytes, index);
    bytes[entry + 5] = (bytes[entry + 5] & !0x03) | 0x02;
    fs::write(&first, bytes).unwrap();

    let output = run(Command::new(tool())
        .arg("public_api")
        .arg(&first)
        .arg(&second));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains(&format!("file={}", second.to_string_lossy())));
    assert!(!stdout.contains(&format!("file={}", first.to_string_lossy())));

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn returns_not_found_when_no_input_defines_symbol() {
    let dir = temp_dir();
    let first = build_sysv_hash_so(&dir, "first");
    let second = build_sysv_hash_so(&dir, "second");

    let output = run(Command::new(tool())
        .arg("missing_api")
        .arg(&first)
        .arg(&second));
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "SysV external resolve: symbol=missing_api not-found\n"
    );

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn malformed_earlier_input_fails_without_stdout() {
    let dir = temp_dir();
    let bad = build_sysv_hash_so(&dir, "bad");
    let good = build_sysv_hash_so(&dir, "good");
    let mut bytes = fs::read(&bad).unwrap();
    bytes[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
    fs::write(&bad, bytes).unwrap();

    let output = Command::new(tool())
        .arg("public_api")
        .arg(&bad)
        .arg(&good)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.is_empty());

    fs::remove_dir_all(dir).unwrap();
}
