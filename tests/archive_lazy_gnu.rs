use mini_elf_toolchain::archive::Archive;
use mini_elf_toolchain::archive_index::parse_archive_symbol_index;
use mini_elf_toolchain::archive_lazy::{extract_indexed_archive_members, ArchiveExtractionError};
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

fn have_gnu_binutils() -> bool {
    command_available("ar", "--version", "GNU ar")
        && command_available("as", "--version", "GNU assembler")
        && command_available("ld", "--version", "GNU ld")
        && command_available("nm", "--version", "GNU nm")
}

fn temp_dir(tag: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock must be after Unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "mini-elf-toolchain-archive-lazy-{tag}-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&path).expect("create temporary test directory");
    path
}

fn assemble(dir: &PathBuf, stem: &str, source: &str) {
    fs::write(dir.join(format!("{stem}.s")), source).expect("write assembly source");
    let status = Command::new("as")
        .current_dir(dir)
        .args(["--64", "-o", &format!("{stem}.o"), &format!("{stem}.s")])
        .status()
        .expect("run GNU as");
    assert!(status.success(), "GNU as failed for {stem}");
}

fn make_chain_archive(dir: &PathBuf) {
    assemble(
        dir,
        "foo",
        ".globl foo\n.type foo,@function\nfoo:\n  call bar\n  ret\n",
    );
    assemble(dir, "bar", ".globl bar\n.type bar,@function\nbar:\n  ret\n");
    assemble(
        dir,
        "unused",
        ".globl unused\n.type unused,@function\nunused:\n  ret\n",
    );
    let status = Command::new("ar")
        .current_dir(dir)
        .args(["rcs", "libchain.a", "foo.o", "bar.o", "unused.o"])
        .status()
        .expect("run GNU ar");
    assert!(status.success(), "GNU ar failed");
}

#[test]
fn extraction_reaches_fixed_point_without_extracting_unused_members() {
    if !have_gnu_binutils() {
        return;
    }

    let dir = temp_dir("chain");
    make_chain_archive(&dir);

    let bytes = fs::read(dir.join("libchain.a")).expect("read archive");
    let archive = Archive::parse(&bytes).expect("parse archive");
    let index = parse_archive_symbol_index(&archive)
        .expect("parse symbol index")
        .expect("archive should have symbol index");
    let extraction = extract_indexed_archive_members(
        &archive,
        &index,
        [b"foo".as_slice()],
        std::iter::empty::<&[u8]>(),
    )
    .expect("lazy extraction should succeed");

    let actual_names = extraction
        .members
        .iter()
        .map(|member| String::from_utf8(member.name.clone()).expect("member name must be UTF-8"))
        .collect::<Vec<_>>();
    assert_eq!(actual_names, vec!["foo.o", "bar.o"]);
    assert!(extraction.unresolved.is_empty());

    assemble(
        &dir,
        "root",
        ".globl _start\n.type _start,@function\n_start:\n  call foo\n  mov $60,%rax\n  xor %rdi,%rdi\n  syscall\n",
    );
    let status = Command::new("ld")
        .current_dir(&dir)
        .args(["-o", "gnu.out", "root.o", "libchain.a"])
        .status()
        .expect("run GNU ld");
    assert!(status.success(), "GNU ld failed");
    let nm = Command::new("nm")
        .current_dir(&dir)
        .arg("gnu.out")
        .output()
        .expect("run GNU nm");
    assert!(nm.status.success(), "GNU nm failed");
    let nm_stdout = String::from_utf8(nm.stdout).expect("GNU nm output must be UTF-8");
    assert!(nm_stdout.lines().any(|line| line.ends_with(" foo")));
    assert!(nm_stdout.lines().any(|line| line.ends_with(" bar")));
    assert!(!nm_stdout.lines().any(|line| line.ends_with(" unused")));

    fs::remove_dir_all(dir).expect("remove temporary test directory");
}

#[test]
fn preexisting_definition_prevents_redundant_transitive_extraction() {
    if !have_gnu_binutils() {
        return;
    }

    let dir = temp_dir("predefined");
    make_chain_archive(&dir);

    let bytes = fs::read(dir.join("libchain.a")).expect("read archive");
    let archive = Archive::parse(&bytes).expect("parse archive");
    let index = parse_archive_symbol_index(&archive)
        .expect("parse symbol index")
        .expect("archive should have symbol index");
    let extraction =
        extract_indexed_archive_members(&archive, &index, [b"foo".as_slice()], [b"bar".as_slice()])
            .expect("preexisting bar definition should satisfy foo's reference");

    let actual_names = extraction
        .members
        .iter()
        .map(|member| String::from_utf8(member.name.clone()).expect("member name must be UTF-8"))
        .collect::<Vec<_>>();
    assert_eq!(actual_names, vec!["foo.o"]);
    assert!(extraction.unresolved.is_empty());

    fs::remove_dir_all(dir).expect("remove temporary test directory");
}

#[test]
fn unresolved_weak_reference_does_not_trigger_transitive_extraction() {
    if !have_gnu_binutils() {
        return;
    }

    let dir = temp_dir("weak");
    assemble(
        &dir,
        "foo",
        ".weak weakdep\n.globl foo\n.type foo,@function\nfoo:\n  call weakdep\n  ret\n",
    );
    assemble(
        &dir,
        "weakdep",
        ".globl weakdep\n.type weakdep,@function\nweakdep:\n  ret\n",
    );
    let status = Command::new("ar")
        .current_dir(&dir)
        .args(["rcs", "libweak.a", "foo.o", "weakdep.o"])
        .status()
        .expect("run GNU ar");
    assert!(status.success(), "GNU ar failed");

    let bytes = fs::read(dir.join("libweak.a")).expect("read archive");
    let archive = Archive::parse(&bytes).expect("parse archive");
    let index = parse_archive_symbol_index(&archive)
        .expect("parse symbol index")
        .expect("archive should have symbol index");
    let extraction = extract_indexed_archive_members(
        &archive,
        &index,
        [b"foo".as_slice()],
        std::iter::empty::<&[u8]>(),
    )
    .expect("lazy extraction should succeed");

    let actual_names = extraction
        .members
        .iter()
        .map(|member| String::from_utf8(member.name.clone()).expect("member name must be UTF-8"))
        .collect::<Vec<_>>();
    assert_eq!(actual_names, vec!["foo.o"]);
    assert!(extraction.unresolved.is_empty());

    fs::remove_dir_all(dir).expect("remove temporary test directory");
}

#[test]
fn selected_malformed_member_is_rejected_but_unselected_members_are_not_parsed() {
    if !have_gnu_binutils() {
        return;
    }

    let dir = temp_dir("malformed");
    make_chain_archive(&dir);
    let mut bytes = fs::read(dir.join("libchain.a")).expect("read archive");

    let foo_data_offset = {
        let archive = Archive::parse(&bytes).expect("parse archive before mutation");
        let index = parse_archive_symbol_index(&archive)
            .expect("parse symbol index")
            .expect("archive should have symbol index");
        let foo = index
            .entries
            .iter()
            .find(|entry| entry.name == b"foo")
            .expect("foo index entry");
        archive.members[foo.member_index].data_offset
    };
    bytes[foo_data_offset] = 0;

    let archive = Archive::parse(&bytes).expect("archive container remains structurally valid");
    let index = parse_archive_symbol_index(&archive)
        .expect("symbol index remains structurally valid")
        .expect("archive should have symbol index");

    let missing = extract_indexed_archive_members(
        &archive,
        &index,
        [b"missing".as_slice()],
        std::iter::empty::<&[u8]>(),
    )
    .expect("unselected malformed member must remain lazy");
    assert!(missing.members.is_empty());
    assert_eq!(
        missing.unresolved.into_iter().collect::<Vec<_>>(),
        vec![b"missing".to_vec()]
    );

    let error = extract_indexed_archive_members(
        &archive,
        &index,
        [b"foo".as_slice()],
        std::iter::empty::<&[u8]>(),
    )
    .expect_err("selected malformed member must fail");
    assert!(matches!(
        error,
        ArchiveExtractionError::InvalidObject { .. }
    ));

    fs::remove_dir_all(dir).expect("remove temporary test directory");
}
