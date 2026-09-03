use mini_elf_toolchain::ordered_inputs::{
    prepare_ordered_link_inputs, LinkObjectOrigin, OrderedLinkInput,
};
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
        "mini-elf-toolchain-ordered-inputs-{tag}-{}-{nonce}",
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

fn archive(dir: &PathBuf, name: &str, members: &[&str]) {
    let mut command = Command::new("ar");
    command.current_dir(dir).args(["rcs", name]);
    command.args(members);
    let status = command.status().expect("run GNU ar");
    assert!(status.success(), "GNU ar failed for {name}");
}

fn ordinary_origin_names(origins: &[LinkObjectOrigin]) -> Vec<String> {
    origins
        .iter()
        .filter_map(|origin| match origin {
            LinkObjectOrigin::Regular { .. } => None,
            LinkObjectOrigin::ArchiveMember { member_name, .. } => Some(
                String::from_utf8(member_name.clone()).expect("member name must be UTF-8"),
            ),
        })
        .collect()
}

#[test]
fn ordered_archives_resolve_transitive_references_like_gnu_ld() {
    if !have_gnu_binutils() {
        return;
    }

    let dir = temp_dir("transitive");
    assemble(
        &dir,
        "root",
        ".globl _start\n.type _start,@function\n_start:\n  call foo\n  mov $60,%rax\n  xor %rdi,%rdi\n  syscall\n",
    );
    assemble(
        &dir,
        "foo",
        ".globl foo\n.type foo,@function\nfoo:\n  call bar\n  ret\n",
    );
    assemble(dir.as_ref(), "bar", ".globl bar\n.type bar,@function\nbar:\n  ret\n");
    assemble(
        &dir,
        "unused",
        ".globl unused\n.type unused,@function\nunused:\n  ret\n",
    );
    archive(&dir, "libfoo.a", &["foo.o", "unused.o"]);
    archive(&dir, "libbar.a", &["bar.o"]);

    let root = fs::read(dir.join("root.o")).expect("read root object");
    let libfoo = fs::read(dir.join("libfoo.a")).expect("read foo archive");
    let libbar = fs::read(dir.join("libbar.a")).expect("read bar archive");
    let prepared = prepare_ordered_link_inputs(&[
        OrderedLinkInput::Object(&root),
        OrderedLinkInput::Archive(&libfoo),
        OrderedLinkInput::Archive(&libbar),
    ])
    .expect("ordered archive preparation should succeed");

    assert!(prepared.unresolved.is_empty());
    assert_eq!(prepared.objects.len(), 3);
    assert_eq!(
        prepared
            .objects
            .iter()
            .map(|object| object.object_index)
            .collect::<Vec<_>>(),
        vec![0, 1, 2]
    );
    assert_eq!(
        ordinary_origin_names(&prepared.origins),
        vec!["foo.o", "bar.o"]
    );

    let status = Command::new("ld")
        .current_dir(&dir)
        .args(["-o", "gnu.out", "root.o", "libfoo.a", "libbar.a"])
        .status()
        .expect("run GNU ld");
    assert!(status.success(), "GNU ld failed");
    let nm = Command::new("nm")
        .current_dir(&dir)
        .arg("gnu.out")
        .output()
        .expect("run GNU nm");
    assert!(nm.status.success(), "GNU nm failed");
    let stdout = String::from_utf8(nm.stdout).expect("GNU nm output must be UTF-8");
    assert!(stdout.lines().any(|line| line.ends_with(" foo")));
    assert!(stdout.lines().any(|line| line.ends_with(" bar")));
    assert!(!stdout.lines().any(|line| line.ends_with(" unused")));

    fs::remove_dir_all(dir).expect("remove temporary test directory");
}

#[test]
fn archive_is_not_rescanned_for_symbols_introduced_by_later_object() {
    if !have_gnu_binutils() {
        return;
    }

    let dir = temp_dir("order");
    assemble(
        &dir,
        "root",
        ".globl _start\n.type _start,@function\n_start:\n  call foo\n  ret\n",
    );
    assemble(dir.as_ref(), "foo", ".globl foo\n.type foo,@function\nfoo:\n  ret\n");
    archive(&dir, "libfoo.a", &["foo.o"]);

    let root = fs::read(dir.join("root.o")).expect("read root object");
    let libfoo = fs::read(dir.join("libfoo.a")).expect("read foo archive");
    let prepared = prepare_ordered_link_inputs(&[
        OrderedLinkInput::Archive(&libfoo),
        OrderedLinkInput::Object(&root),
    ])
    .expect("ordered input preparation should remain structurally valid");

    assert_eq!(prepared.objects.len(), 1);
    assert!(prepared.origins.iter().all(|origin| matches!(
        origin,
        LinkObjectOrigin::Regular { input_index: 1 }
    )));
    assert_eq!(
        prepared.unresolved.into_iter().collect::<Vec<_>>(),
        vec![b"foo".to_vec()]
    );

    let output = Command::new("ld")
        .current_dir(&dir)
        .args(["-o", "gnu.out", "libfoo.a", "root.o"])
        .output()
        .expect("run GNU ld");
    assert!(!output.status.success(), "GNU ld unexpectedly rescanned archive");
    assert!(String::from_utf8_lossy(&output.stderr).contains("foo"));

    fs::remove_dir_all(dir).expect("remove temporary test directory");
}

#[test]
fn earlier_regular_definition_prevents_redundant_archive_member_extraction() {
    if !have_gnu_binutils() {
        return;
    }

    let dir = temp_dir("predefined");
    assemble(
        &dir,
        "root",
        ".globl _start\n.type _start,@function\n_start:\n  call foo\n  ret\n",
    );
    assemble(
        &dir,
        "foo",
        ".globl foo\n.type foo,@function\nfoo:\n  call bar\n  ret\n",
    );
    assemble(dir.as_ref(), "bar_archive", ".globl bar\n.type bar,@function\nbar:\n  ret\n");
    assemble(dir.as_ref(), "bar_regular", ".globl bar\n.type bar,@function\nbar:\n  ret\n");
    archive(&dir, "libchain.a", &["foo.o", "bar_archive.o"]);

    let root = fs::read(dir.join("root.o")).expect("read root object");
    let regular_bar = fs::read(dir.join("bar_regular.o")).expect("read regular bar object");
    let archive_bytes = fs::read(dir.join("libchain.a")).expect("read chain archive");
    let prepared = prepare_ordered_link_inputs(&[
        OrderedLinkInput::Object(&root),
        OrderedLinkInput::Object(&regular_bar),
        OrderedLinkInput::Archive(&archive_bytes),
    ])
    .expect("preexisting regular definition should satisfy archive member dependency");

    assert!(prepared.unresolved.is_empty());
    assert_eq!(ordinary_origin_names(&prepared.origins), vec!["foo.o"]);
    assert_eq!(prepared.objects.len(), 3);

    fs::remove_dir_all(dir).expect("remove temporary test directory");
}
