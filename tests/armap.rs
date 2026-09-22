use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_dir(label: &str) -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "mini-elf-toolchain-{label}-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&path).unwrap();
    path
}

fn tool_available(tool: &str) -> bool {
    Command::new(tool).arg("--version").output().is_ok()
}

#[test]
fn armap_matches_gnu_nm_index_for_real_archive() {
    if !tool_available("as") || !tool_available("ar") || !tool_available("nm") {
        return;
    }
    let dir = temp_dir("armap");
    let assembly = dir.join("member.s");
    let object = dir.join("member.o");
    let archive = dir.join("libsample.a");
    fs::write(
        &assembly,
        ".text\n.globl exported\n.type exported,@function\nexported:\n  ret\n.size exported,.-exported\n",
    )
    .unwrap();
    assert!(Command::new("as")
        .arg("-o")
        .arg(&object)
        .arg(&assembly)
        .status()
        .unwrap()
        .success());
    assert!(Command::new("ar")
        .args(["rcs"])
        .arg(&archive)
        .arg(&object)
        .status()
        .unwrap()
        .success());

    let ours = Command::new(env!("CARGO_BIN_EXE_mini-elf-armap"))
        .arg(&archive)
        .output()
        .unwrap();
    assert!(
        ours.status.success(),
        "{}",
        String::from_utf8_lossy(&ours.stderr)
    );

    let gnu = Command::new("nm").arg("-s").arg(&archive).output().unwrap();
    assert!(gnu.status.success());
    let gnu_stdout = String::from_utf8_lossy(&gnu.stdout);
    let gnu_index = gnu_stdout
        .split("\n\n")
        .next()
        .expect("GNU nm should print an archive index");
    assert_eq!(String::from_utf8_lossy(&ours.stdout).trim_end(), gnu_index);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn armap_traverses_multiple_archives_in_order() {
    if !tool_available("as") || !tool_available("ar") || !tool_available("nm") {
        return;
    }
    let dir = temp_dir("armap-multiple");
    let mut archives = Vec::new();
    let mut expected = String::new();
    for (stem, symbol) in [("first", "alpha"), ("second", "beta")] {
        let assembly = dir.join(format!("{stem}.s"));
        let object = dir.join(format!("{stem}.o"));
        let archive = dir.join(format!("lib{stem}.a"));
        fs::write(
            &assembly,
            format!(".text\n.globl {symbol}\n.type {symbol},@function\n{symbol}:\n  ret\n.size {symbol},.-{symbol}\n"),
        )
        .unwrap();
        assert!(Command::new("as")
            .arg("-o")
            .arg(&object)
            .arg(&assembly)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("ar")
            .args(["rcs"])
            .arg(&archive)
            .arg(&object)
            .status()
            .unwrap()
            .success());
        let gnu = Command::new("nm").arg("-s").arg(&archive).output().unwrap();
        assert!(gnu.status.success());
        let gnu_stdout = String::from_utf8_lossy(&gnu.stdout);
        expected.push_str(
            gnu_stdout
                .split("\n\n")
                .next()
                .expect("GNU nm should print an archive index"),
        );
        expected.push('\n');
        archives.push(archive);
    }

    let ours = Command::new(env!("CARGO_BIN_EXE_mini-elf-armap"))
        .args(&archives)
        .output()
        .unwrap();
    assert!(
        ours.status.success(),
        "{}",
        String::from_utf8_lossy(&ours.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&ours.stdout), expected);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn armap_option_terminator_allows_help_named_archive() {
    if !tool_available("as") || !tool_available("ar") || !tool_available("nm") {
        return;
    }
    let dir = temp_dir("armap-option-terminator");
    let assembly = dir.join("member.s");
    let object = dir.join("member.o");
    let archive = dir.join("-h");
    fs::write(
        &assembly,
        ".text\n.globl option_symbol\noption_symbol:\n  ret\n",
    )
    .unwrap();
    assert!(Command::new("as")
        .arg("-o")
        .arg(&object)
        .arg(&assembly)
        .status()
        .unwrap()
        .success());
    assert!(Command::new("ar")
        .args(["rcs"])
        .arg(&archive)
        .arg(&object)
        .status()
        .unwrap()
        .success());

    let ours = Command::new(env!("CARGO_BIN_EXE_mini-elf-armap"))
        .current_dir(&dir)
        .args(["--", "-h"])
        .output()
        .unwrap();
    assert!(
        ours.status.success(),
        "{}",
        String::from_utf8_lossy(&ours.stderr)
    );
    let gnu = Command::new("nm")
        .current_dir(&dir)
        .args(["-s", "--", "-h"])
        .output()
        .unwrap();
    assert!(gnu.status.success());
    let gnu_stdout = String::from_utf8_lossy(&gnu.stdout);
    let gnu_index = gnu_stdout
        .split("\n\n")
        .next()
        .expect("GNU nm should print an archive index");
    assert_eq!(String::from_utf8_lossy(&ours.stdout).trim_end(), gnu_index);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn armap_rejects_malformed_index_without_partial_stdout() {
    let dir = temp_dir("armap-malformed");
    let archive = dir.join("bad.a");
    let mut bytes = b"!<arch>\n".to_vec();
    bytes.extend_from_slice(b"/               0           0     0     0       2         `\n");
    bytes.extend_from_slice(&[0, 0]);
    fs::write(&archive, bytes).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-armap"))
        .arg(&archive)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty(), "stdout must remain atomic");
    assert!(String::from_utf8_lossy(&output.stderr).contains("truncated archive symbol count"));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn armap_keeps_stdout_atomic_when_later_input_is_malformed() {
    if !tool_available("as") || !tool_available("ar") {
        return;
    }
    let dir = temp_dir("armap-multiple-malformed");
    let assembly = dir.join("good.s");
    let object = dir.join("good.o");
    let good = dir.join("libgood.a");
    let bad = dir.join("bad.a");
    fs::write(&assembly, ".text\n.globl good\ngood:\n  ret\n").unwrap();
    assert!(Command::new("as")
        .arg("-o")
        .arg(&object)
        .arg(&assembly)
        .status()
        .unwrap()
        .success());
    assert!(Command::new("ar")
        .args(["rcs"])
        .arg(&good)
        .arg(&object)
        .status()
        .unwrap()
        .success());
    let mut bytes = b"!<arch>\n".to_vec();
    bytes.extend_from_slice(b"/               0           0     0     0       2         `\n");
    bytes.extend_from_slice(&[0, 0]);
    fs::write(&bad, bytes).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-armap"))
        .arg(&good)
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty(), "stdout must remain atomic");
    assert!(String::from_utf8_lossy(&output.stderr).contains("truncated archive symbol count"));
    let _ = fs::remove_dir_all(dir);
}
