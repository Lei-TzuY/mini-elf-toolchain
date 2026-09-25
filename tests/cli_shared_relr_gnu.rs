use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn command_reports(program: &str, marker: &str) -> bool {
    let Ok(output) = Command::new(program).arg("--version").output() else {
        return false;
    };
    output.status.success()
        && (String::from_utf8_lossy(&output.stdout).contains(marker)
            || String::from_utf8_lossy(&output.stderr).contains(marker))
}

fn have_tools() -> bool {
    command_reports("as", "GNU assembler")
        && command_reports("ld", "GNU ld")
        && command_reports("readelf", "GNU readelf")
        && Command::new("cc").arg("--version").output().is_ok_and(|out| out.status.success())
}

fn gnu_ld_supports_pack_relative_relocs() -> bool {
    Command::new("ld")
        .arg("--help")
        .output()
        .is_ok_and(|output| {
            output.status.success()
                && String::from_utf8_lossy(&output.stdout).contains("pack-relative-relocs")
        })
}

fn temp_dir(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after Unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "mini-elf-toolchain-shared-relr-{label}-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&path).unwrap();
    path
}

fn assemble(dir: &Path, stem: &str, source: &str) -> PathBuf {
    let asm = dir.join(format!("{stem}.s"));
    let object = dir.join(format!("{stem}.o"));
    fs::write(&asm, source).unwrap();
    let output = Command::new("as")
        .args(["--64", "-o"])
        .arg(&object)
        .arg(&asm)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    object
}

fn readelf(path: &Path, args: &[&str]) -> String {
    let output = Command::new("readelf")
        .args(args)
        .arg(path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

fn shared_fixture(dir: &Path) -> PathBuf {
    assemble(
        dir,
        "shared-relr",
        r#".data
.align 8
.type local_value,@object
local_value:
    .quad 13
.size local_value,8

.align 8
.type local_ptr0,@object
local_ptr0:
    .quad local_value
.type local_ptr1,@object
local_ptr1:
    .quad local_value
.type local_ptr2,@object
local_ptr2:
    .quad local_value

.globl host_value
.type host_value,@object

.text
.globl mixed_value
.type mixed_value,@function
mixed_value:
    mov local_ptr0(%rip), %rax
    mov (%rax), %rax
    mov local_ptr1(%rip), %rcx
    add (%rcx), %rax
    mov local_ptr2(%rip), %rcx
    add (%rcx), %rax
    mov host_value@GOTPCREL(%rip), %rcx
    add (%rcx), %rax
    ret
.size mixed_value, .-mixed_value

.section .note.GNU-stack,"",@progbits
"#,
    )
}

fn build_host(dir: &Path) -> PathBuf {
    let source = dir.join("host.c");
    let host = dir.join("host");
    fs::write(
        &source,
        r#"#include <dlfcn.h>
#include <stdint.h>

uint64_t host_value = 3;

int main(int argc, char **argv) {
    if (argc != 2) return 70;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) return 71;
    uint64_t (*mixed_value)(void) =
        (uint64_t (*)(void))dlsym(handle, "mixed_value");
    if (!mixed_value) return 72;
    uint64_t value = mixed_value();
    if (dlclose(handle) != 0) return 73;
    return value == 42 ? 0 : 74;
}
"#,
    )
    .unwrap();
    let output = Command::new("cc")
        .args(["-rdynamic", "-o"])
        .arg(&host)
        .arg(&source)
        .arg("-ldl")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    host
}

fn link_mini(output: &Path, object: &Path, packed: bool) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"));
    command.args(["link", "-o"]).arg(output).arg("--shared");
    if packed {
        command.args(["-z", "pack-relative-relocs"]);
    }
    let linked = command.arg(object).output().unwrap();
    assert!(
        linked.status.success(),
        "{}",
        String::from_utf8_lossy(&linked.stderr)
    );
}

#[test]
#[cfg(target_os = "linux")]
fn shared_pack_relative_relocs_splits_relr_from_symbol_rela_and_dlopen_executes() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("packed");
    let object = shared_fixture(&dir);
    let host = build_host(&dir);
    let ours = dir.join("libmini-packed.so");
    link_mini(&ours, &object, true);

    let dynamic = readelf(&ours, &["-dW"]);
    for tag in ["RELR", "RELRSZ", "RELRENT", "RELA", "RELASZ", "RELAENT"] {
        assert!(dynamic.contains(tag), "missing {tag}:\n{dynamic}");
    }
    assert!(
        !dynamic.contains("RELACOUNT"),
        "packed RELATIVE relocations must not remain in the RELA prefix:\n{dynamic}"
    );

    let relr = Command::new(env!("CARGO_BIN_EXE_mini-elf-dynrelr"))
        .arg(&ours)
        .output()
        .unwrap();
    assert!(
        relr.status.success(),
        "{}",
        String::from_utf8_lossy(&relr.stderr)
    );
    let relr = String::from_utf8_lossy(&relr.stdout);
    assert!(
        relr.contains("DT_RELR contains 2 encoded entries, 3 relocations"),
        "three contiguous pointer fixups should use one direct entry plus one bitmap:\n{relr}"
    );

    let rela = Command::new(env!("CARGO_BIN_EXE_mini-elf-dynrela"))
        .arg(&ours)
        .output()
        .unwrap();
    assert!(
        rela.status.success(),
        "{}",
        String::from_utf8_lossy(&rela.stderr)
    );
    let rela = String::from_utf8_lossy(&rela.stdout);
    assert!(rela.contains("R_X86_64_GLOB_DAT"), "{rela}");
    assert!(rela.contains("host_value"), "{rela}");
    assert!(
        !rela.contains("R_X86_64_RELATIVE"),
        "packed relatives must not be duplicated in DT_RELA:\n{rela}"
    );

    let status = Command::new(&host).arg(&ours).status().unwrap();
    assert_eq!(
        status.code(),
        Some(0),
        "mini shared object must execute through both RELR and GLOB_DAT; status={status}"
    );

    assert!(
        gnu_ld_supports_pack_relative_relocs(),
        "GNU ld fixture must support -z pack-relative-relocs"
    );
    let gnu = dir.join("libgnu-packed.so");
    let linked = Command::new("ld")
        .args(["-shared", "-z", "pack-relative-relocs", "-o"])
        .arg(&gnu)
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        linked.status.success(),
        "{}",
        String::from_utf8_lossy(&linked.stderr)
    );
    let gnu_dynamic = readelf(&gnu, &["-dW"]);
    assert!(gnu_dynamic.contains("RELR"), "{gnu_dynamic}");
    let status = Command::new(&host).arg(&gnu).status().unwrap();
    assert_eq!(status.code(), Some(0), "GNU reference status={status}");

    let _ = fs::remove_dir_all(dir);
}

#[test]
#[cfg(target_os = "linux")]
fn shared_default_policy_remains_rela_only() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("default");
    let object = shared_fixture(&dir);
    let host = build_host(&dir);
    let ours = dir.join("libmini-default.so");
    link_mini(&ours, &object, false);

    let dynamic = readelf(&ours, &["-dW"]);
    assert!(!dynamic.contains("(RELR)"), "{dynamic}");
    assert!(!dynamic.contains("(RELRSZ)"), "{dynamic}");
    assert!(!dynamic.contains("(RELRENT)"), "{dynamic}");
    assert!(dynamic.contains("RELACOUNT"), "{dynamic}");

    let rela = Command::new(env!("CARGO_BIN_EXE_mini-elf-dynrela"))
        .arg(&ours)
        .output()
        .unwrap();
    assert!(rela.status.success());
    let rela = String::from_utf8_lossy(&rela.stdout);
    assert!(rela.contains("R_X86_64_RELATIVE"), "{rela}");
    assert!(rela.contains("R_X86_64_GLOB_DAT"), "{rela}");

    let status = Command::new(&host).arg(&ours).status().unwrap();
    assert_eq!(status.code(), Some(0), "default RELA path status={status}");

    let _ = fs::remove_dir_all(dir);
}
