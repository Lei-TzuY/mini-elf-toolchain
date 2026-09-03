use mini_elf_toolchain::archive::Archive;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn gnu_ar_available() -> bool {
    let Ok(output) = Command::new("ar").arg("--version").output() else {
        return false;
    };
    output.status.success() && String::from_utf8_lossy(&output.stdout).contains("GNU ar")
}

fn temp_dir() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock must be after Unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "mini-elf-toolchain-archive-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&path).expect("create temporary test directory");
    path
}

#[test]
fn parser_matches_gnu_ar_member_listing_for_long_names() {
    if !gnu_ar_available() {
        return;
    }

    let dir = temp_dir();
    let short_name = "short.o";
    let long_name = "this-is-a-very-long-object-member-name.o";
    fs::write(dir.join(short_name), b"short payload").expect("write short archive input");
    fs::write(dir.join(long_name), b"long payload").expect("write long archive input");
    let archive_path = dir.join("libinputs.a");

    let status = Command::new("ar")
        .current_dir(&dir)
        .args(["rc", "libinputs.a", short_name, long_name])
        .status()
        .expect("run GNU ar");
    assert!(status.success(), "GNU ar failed");

    let listing = Command::new("ar")
        .current_dir(&dir)
        .args(["t", "libinputs.a"])
        .output()
        .expect("run GNU ar t");
    assert!(listing.status.success(), "GNU ar t failed");
    let expected = String::from_utf8(listing.stdout)
        .expect("GNU ar listing must be UTF-8")
        .lines()
        .map(|line| line.as_bytes().to_vec())
        .collect::<Vec<_>>();

    let bytes = fs::read(&archive_path).expect("read GNU archive");
    let parsed = Archive::parse(&bytes).expect("parse GNU archive");
    let actual = parsed
        .ordinary_members()
        .map(|member| member.name.clone())
        .collect::<Vec<_>>();

    assert_eq!(actual, expected);

    fs::remove_dir_all(dir).expect("remove temporary test directory");
}
