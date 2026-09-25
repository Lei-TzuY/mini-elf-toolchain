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

fn have_gnu_tools() -> bool {
    command_reports("as", "GNU assembler")
        && command_reports("ld", "GNU ld")
        && command_reports("readelf", "GNU readelf")
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
        "mini-elf-toolchain-static-pie-relr-{label}-{}-{nonce}",
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

fn fixture(dir: &Path) -> PathBuf {
    assemble(
        dir,
        "fixture",
        r#".data
.align 8
.type local_value,@object
local_value:
    .quad 0x1122334455667788
.size local_value,8

.align 8
local_ptr0:
    .quad local_value
local_ptr1:
    .quad local_value
local_ptr2:
    .quad local_value

.align 8
func_ptr:
    .quad resolver

.text
.type implementation,@function
implementation:
    mov $17, %eax
    ret
.size implementation, .-implementation

.type resolver,@gnu_indirect_function
resolver:
    lea implementation(%rip), %rax
    ret
.size resolver, .-resolver

.globl _start
.type _start,@function
_start:
    lea local_value(%rip), %rbx
    mov local_ptr0(%rip), %rax
    cmp %rbx, %rax
    jne .Lfail_relative
    mov local_ptr1(%rip), %rax
    cmp %rbx, %rax
    jne .Lfail_relative
    mov local_ptr2(%rip), %rax
    cmp %rbx, %rax
    jne .Lfail_relative

    mov func_ptr(%rip), %rax
    call *%rax
    cmp $17, %eax
    jne .Lfail_ifunc

    mov $60, %eax
    xor %edi, %edi
    syscall

.Lfail_relative:
    mov $60, %eax
    mov $41, %edi
    syscall
.Lfail_ifunc:
    mov $60, %eax
    mov $42, %edi
    syscall
.size _start, .-_start

.section .note.GNU-stack,"",@progbits
"#,
    )
}

fn link_mini(output: &Path, object: &Path, packed: bool) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"));
    command.args(["link", "-o"]).arg(output).arg("--pie");
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

#[test]
#[cfg(target_os = "linux")]
fn static_pie_pack_relative_relocs_decodes_relr_then_runs_irelative() {
    if !have_gnu_tools() || !gnu_ld_supports_pack_relative_relocs() {
        return;
    }

    let dir = temp_dir("packed");
    let object = fixture(&dir);
    let ours = dir.join("mini-packed");
    link_mini(&ours, &object, true);

    let dynamic = readelf(&ours, &["-dW"]);
    for tag in ["RELR", "RELRSZ", "RELRENT", "RELA", "RELASZ", "RELAENT"] {
        assert!(dynamic.contains(tag), "missing {tag}:\n{dynamic}");
    }
    assert!(!dynamic.contains("RELACOUNT"), "{dynamic}");

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
        "{relr}"
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
    assert!(rela.contains("R_X86_64_IRELATIVE"), "{rela}");
    assert!(!rela.contains("R_X86_64_RELATIVE"), "{rela}");

    let status = Command::new(&ours).status().unwrap();
    assert_eq!(
        status.code(),
        Some(0),
        "mini packed static PIE status={status}"
    );

    let gnu = dir.join("gnu-packed");
    let linked = Command::new("ld")
        .args([
            "-pie",
            "--no-dynamic-linker",
            "-z",
            "pack-relative-relocs",
            "-o",
        ])
        .arg(&gnu)
        .arg(&object)
        .output()
        .unwrap();
    assert!(linked.status.success(), "{}", String::from_utf8_lossy(&linked.stderr));
    assert!(readelf(&gnu, &["-dW"]).contains("RELR"));
    let status = Command::new(&gnu).status().unwrap();
    assert_eq!(
        status.code(),
        Some(0),
        "GNU packed static PIE status={status}"
    );

    let _ = fs::remove_dir_all(dir);
}

#[test]
#[cfg(target_os = "linux")]
fn static_pie_default_policy_remains_rela_only() {
    if !have_gnu_tools() {
        return;
    }

    let dir = temp_dir("default");
    let object = fixture(&dir);
    let ours = dir.join("mini-default");
    link_mini(&ours, &object, false);

    let dynamic = readelf(&ours, &["-dW"]);
    assert!(!dynamic.contains("(RELR)"), "{dynamic}");
    assert!(dynamic.contains("RELACOUNT"), "{dynamic}");

    let rela = Command::new(env!("CARGO_BIN_EXE_mini-elf-dynrela"))
        .arg(&ours)
        .output()
        .unwrap();
    assert!(rela.status.success());
    let rela = String::from_utf8_lossy(&rela.stdout);
    assert!(rela.contains("R_X86_64_RELATIVE"), "{rela}");
    assert!(rela.contains("R_X86_64_IRELATIVE"), "{rela}");

    let status = Command::new(&ours).status().unwrap();
    assert_eq!(
        status.code(),
        Some(0),
        "default static PIE status={status}"
    );

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn pack_relative_relocs_plain_static_mode_stays_fail_closed_before_io() {
    let output = PathBuf::from("/tmp/mini-elf-toolchain-static-relr-should-not-exist");
    let result = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&output)
        .args(["-z", "pack-relative-relocs", "definitely-missing-input.o"])
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(2));
    assert!(result.stdout.is_empty());
    assert!(String::from_utf8_lossy(&result.stderr).contains(
        "-z pack-relative-relocs is only supported with --pie, --shared or --dynamic-pie"
    ));
    assert!(!output.exists());
}
