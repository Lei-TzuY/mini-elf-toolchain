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

fn append_ar_member(archive: &mut Vec<u8>, name: &str, data: &[u8]) {
    assert!(name.len() <= 15);
    let name_field = format!("{name}/");
    let header = format!(
        "{name_field:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
        0, 0, 0, 0, data.len()
    );
    assert_eq!(header.len(), 60);
    archive.extend_from_slice(header.as_bytes());
    archive.extend_from_slice(data);
    if data.len() % 2 != 0 {
        archive.push(b'\n');
    }
}

#[test]
fn rejects_malformed_archive_member_with_member_provenance() {
    let dir = temp_dir("nm-archive-malformed");
    let input = dir.join("bad.a");
    let mut archive = b"!<arch>\n".to_vec();
    append_ar_member(&mut archive, "broken.o", b"\x7fELF");
    fs::write(&input, archive).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-nm"))
        .arg(&input)
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("bad.a(broken.o)"), "{stderr}");
    assert!(stderr.contains("ELF64 header is truncated"), "{stderr}");

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn reports_symbols_from_gnu_archive_members_in_archive_order() {
    if !tool_available("as") || !tool_available("ar") || !tool_available("nm") {
        return;
    }

    let dir = temp_dir("nm-archive-gnu");
    let first_s = dir.join("first.s");
    let second_s = dir.join("second.s");
    let first_o = dir.join("first.o");
    let second_o = dir.join("second.o");
    let archive = dir.join("libsample.a");
    fs::write(
        &first_s,
        ".text\n.globl first_export\n.type first_export,@function\nfirst_export:\n  ret\n.size first_export, .-first_export\n",
    )
    .unwrap();
    fs::write(
        &second_s,
        ".data\n.globl second_export\n.type second_export,@object\n.size second_export,8\nsecond_export:\n  .quad 7\n",
    )
    .unwrap();

    for (source, object) in [(&first_s, &first_o), (&second_s, &second_o)] {
        let assembled = Command::new("as")
            .arg("-o")
            .arg(object)
            .arg(source)
            .output()
            .unwrap();
        assert!(
            assembled.status.success(),
            "{}",
            String::from_utf8_lossy(&assembled.stderr)
        );
    }

    let archived = Command::new("ar")
        .arg("crs")
        .arg(&archive)
        .arg(&first_o)
        .arg(&second_o)
        .output()
        .unwrap();
    assert!(
        archived.status.success(),
        "{}",
        String::from_utf8_lossy(&archived.stderr)
    );

    let mini = Command::new(env!("CARGO_BIN_EXE_mini-elf-nm"))
        .arg(&archive)
        .output()
        .unwrap();
    assert!(
        mini.status.success(),
        "{}",
        String::from_utf8_lossy(&mini.stderr)
    );
    let mini_stdout = String::from_utf8_lossy(&mini.stdout);
    let first_member = mini_stdout.find("first.o:\n").unwrap();
    let second_member = mini_stdout.find("second.o:\n").unwrap();
    assert!(first_member < second_member, "{mini_stdout}");
    assert!(mini_stdout.contains("first_export"), "{mini_stdout}");
    assert!(mini_stdout.contains("second_export"), "{mini_stdout}");

    let gnu = Command::new("nm").arg("-A").arg(&archive).output().unwrap();
    assert!(gnu.status.success());
    let gnu_stdout = String::from_utf8_lossy(&gnu.stdout);
    assert!(gnu_stdout.contains("first.o") && gnu_stdout.contains("first_export"));
    assert!(gnu_stdout.contains("second.o") && gnu_stdout.contains("second_export"));

    let _ = fs::remove_dir_all(dir);
}
