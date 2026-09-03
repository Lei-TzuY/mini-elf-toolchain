use mini_elf_toolchain::archive::Archive;
use mini_elf_toolchain::archive_index::parse_archive_symbol_index;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn command_available(program: &str, arg: &str, marker: &str) -> bool {
    let Ok(output) = Command::new(program).arg(arg).output() else {
        return false;
    };
    output.status.success()
        && (String::from_utf8_lossy(&output.stdout).contains(marker)
            || String::from_utf8_lossy(&output.stderr).contains(marker))
}

fn temp_dir() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock must be after Unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "mini-elf-toolchain-archive-index-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&path).expect("create temporary test directory");
    path
}

#[test]
fn symbol_index_matches_gnu_nm_archive_index() {
    if !command_available("ar", "--version", "GNU ar")
        || !command_available("nm", "--version", "GNU nm")
        || !command_available("as", "--version", "GNU assembler")
    {
        return;
    }

    let dir = temp_dir();
    fs::write(
        dir.join("alpha.s"),
        ".globl alpha\n.type alpha,@function\nalpha:\n  ret\n",
    )
    .expect("write alpha assembly");
    fs::write(
        dir.join("beta.s"),
        ".globl beta\n.type beta,@function\nbeta:\n  ret\n",
    )
    .expect("write beta assembly");

    for stem in ["alpha", "beta"] {
        let status = Command::new("as")
            .current_dir(&dir)
            .args(["--64", "-o", &format!("{stem}.o"), &format!("{stem}.s")])
            .status()
            .expect("run GNU as");
        assert!(status.success(), "GNU as failed for {stem}");
    }

    let status = Command::new("ar")
        .current_dir(&dir)
        .args(["rcs", "libsymbols.a", "alpha.o", "beta.o"])
        .status()
        .expect("run GNU ar");
    assert!(status.success(), "GNU ar failed");

    let nm = Command::new("nm")
        .current_dir(&dir)
        .args(["-s", "libsymbols.a"])
        .output()
        .expect("run GNU nm -s");
    assert!(nm.status.success(), "GNU nm -s failed");
    let nm_stdout = String::from_utf8(nm.stdout).expect("GNU nm output must be UTF-8");

    let bytes = fs::read(dir.join("libsymbols.a")).expect("read GNU archive");
    let archive = Archive::parse(&bytes).expect("parse GNU archive");
    let index = parse_archive_symbol_index(&archive)
        .expect("parse GNU archive symbol index")
        .expect("GNU archive should have a symbol index");

    let actual = index
        .entries
        .iter()
        .map(|entry| {
            (
                String::from_utf8(entry.name.to_vec()).expect("symbol name must be UTF-8"),
                String::from_utf8(archive.members[entry.member_index].name.clone())
                    .expect("member name must be UTF-8"),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(
        actual,
        vec![
            ("alpha".to_string(), "alpha.o".to_string()),
            ("beta".to_string(), "beta.o".to_string()),
        ]
    );
    for (symbol, member) in &actual {
        assert!(
            nm_stdout.contains(&format!("{symbol} in {member}")),
            "GNU nm archive index did not contain {symbol} in {member}:\n{nm_stdout}"
        );
    }

    fs::remove_dir_all(dir).expect("remove temporary test directory");
}
