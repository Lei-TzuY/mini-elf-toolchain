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

fn dynamic_linker() -> Option<&'static str> {
    [
        "/lib64/ld-linux-x86-64.so.2",
        "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
    ]
    .into_iter()
    .find(|path| Path::new(path).is_file())
}

fn temp_dir(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after Unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "mini-elf-toolchain-pie-runtime-{label}-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&path).unwrap();
    path
}

fn assemble(dir: &Path, stem: &str, source: &str) -> PathBuf {
    let asm = dir.join(format!("{stem}.s"));
    let object = dir.join(format!("{stem}.o"));
    fs::write(&asm, source).unwrap();
    let status = Command::new("as")
        .args(["--64", "-o"])
        .arg(&object)
        .arg(&asm)
        .status()
        .unwrap();
    assert!(status.success(), "GNU as failed for {stem}");
    object
}

#[test]
fn dynamic_pie_emits_and_executes_relative_runtime_relocation() {
    if !have_gnu_tools() {
        return;
    }
    let Some(interpreter) = dynamic_linker() else {
        return;
    };

    let dir = temp_dir("relative");
    let object = assemble(
        &dir,
        "relative",
        r#".section .data
.align 8
.globl target_value
.type target_value,@object
target_value:
    .quad 0x1122334455667788
.size target_value, .-target_value

.align 8
.globl target_pointer
.type target_pointer,@object
target_pointer:
    .quad target_value
.size target_pointer, .-target_pointer

.section .text
.globl _start
.type _start,@function
_start:
    lea target_value(%rip), %rbx
    mov target_pointer(%rip), %rcx
    cmp %rbx, %rcx
    jne .Lfail
    mov (%rcx), %rdx
    movabs $0x1122334455667788, %rax
    cmp %rax, %rdx
    jne .Lfail
    mov $60, %rax
    xor %rdi, %rdi
    syscall
.Lfail:
    mov $60, %rax
    mov $1, %rdi
    syscall
.size _start, .-_start
"#,
    );

    let input_relocations = Command::new("readelf")
        .args(["-rW"])
        .arg(&object)
        .output()
        .unwrap();
    assert!(input_relocations.status.success());
    let input_relocations = String::from_utf8_lossy(&input_relocations.stdout);
    assert!(
        input_relocations.contains("R_X86_64_64")
            && input_relocations.contains("target_value"),
        "fixture must carry a real absolute relocation: {input_relocations}"
    );

    let ours = dir.join("ours");
    let mini = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&ours)
        .arg("--pie")
        .args(["--dynamic-linker", interpreter])
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        mini.status.success(),
        "{}",
        String::from_utf8_lossy(&mini.stderr)
    );

    let headers = Command::new("readelf")
        .args(["-lW"])
        .arg(&ours)
        .output()
        .unwrap();
    assert!(headers.status.success());
    let headers = String::from_utf8_lossy(&headers.stdout);
    assert!(headers.contains("PHDR"));
    assert!(headers.contains("INTERP"));
    assert!(headers.contains("DYNAMIC"));
    assert!(headers.contains(interpreter));

    let dynamic = Command::new("readelf")
        .args(["-dW"])
        .arg(&ours)
        .output()
        .unwrap();
    assert!(dynamic.status.success());
    let dynamic = String::from_utf8_lossy(&dynamic.stdout);
    assert!(dynamic.contains("(RELA)"));
    assert!(dynamic.contains("(RELASZ)"));
    assert!(dynamic.contains("(RELAENT)"));

    let relocations = Command::new("readelf")
        .args(["-rW"])
        .arg(&ours)
        .output()
        .unwrap();
    assert!(relocations.status.success());
    let relocations = String::from_utf8_lossy(&relocations.stdout);
    assert!(relocations.contains("R_X86_64_RELATIVE"));

    let validate = Command::new(env!("CARGO_BIN_EXE_mini-elf-dynrela-relative"))
        .arg("--load-bias=0x70000000")
        .arg(&ours)
        .output()
        .unwrap();
    assert!(
        validate.status.success(),
        "{}",
        String::from_utf8_lossy(&validate.stderr)
    );

    let gnu = dir.join("gnu");
    let gnu_link = Command::new("ld")
        .args(["-pie", "--dynamic-linker", interpreter, "-o"])
        .arg(&gnu)
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        gnu_link.status.success(),
        "{}",
        String::from_utf8_lossy(&gnu_link.stderr)
    );
    let gnu_relocations = Command::new("readelf")
        .args(["-rW"])
        .arg(&gnu)
        .output()
        .unwrap();
    assert!(gnu_relocations.status.success());
    assert!(String::from_utf8_lossy(&gnu_relocations.stdout).contains("R_X86_64_RELATIVE"));

    #[cfg(target_os = "linux")]
    for executable in [&ours, &gnu] {
        let status = Command::new(executable).status().unwrap();
        assert!(
            status.success(),
            "{} returned {status}",
            executable.display()
        );
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn dynamic_pie_rejects_absolute_definition_for_runtime_relative_relocation() {
    if !command_reports("as", "GNU assembler") {
        return;
    }
    let Some(interpreter) = dynamic_linker() else {
        return;
    };

    let dir = temp_dir("absolute");
    let reference = assemble(
        &dir,
        "absolute-ref",
        r#".extern absolute_target
.section .data
.globl pointer
pointer:
    .quad absolute_target
"#,
    );
    let definition = assemble(
        &dir,
        "absolute-def",
        r#".globl absolute_target
.set absolute_target, 0x1234
"#,
    );

    let output = dir.join("must-not-exist");
    let mini = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&output)
        .arg("--pie")
        .args(["--dynamic-linker", interpreter])
        .arg(&reference)
        .arg(&definition)
        .output()
        .unwrap();

    assert!(!mini.status.success());
    assert!(mini.stdout.is_empty());
    assert!(String::from_utf8_lossy(&mini.stderr).contains("SHN_ABS"));
    assert!(!output.exists());

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn dynamic_pie_rejects_runtime_relocation_target_in_read_only_segment() {
    if !command_reports("as", "GNU assembler") {
        return;
    }
    let Some(interpreter) = dynamic_linker() else {
        return;
    };

    let dir = temp_dir("readonly");
    let object = assemble(
        &dir,
        "readonly",
        r#".section .rodata
.globl readonly_pointer
readonly_pointer:
    .quad writable_target

.section .data
.globl writable_target
writable_target:
    .quad 7

.section .text
.globl _start
_start:
    mov $60, %rax
    xor %rdi, %rdi
    syscall
"#,
    );
    let output = dir.join("must-not-exist");

    let mini = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&output)
        .arg("--pie")
        .args(["--dynamic-linker", interpreter])
        .arg(&object)
        .output()
        .unwrap();

    assert!(!mini.status.success());
    assert!(mini.stdout.is_empty());
    assert!(String::from_utf8_lossy(&mini.stderr).contains("writable"));
    assert!(!output.exists());

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn dynamic_linker_option_requires_pie_before_input_io() {
    let missing = Path::new("definitely-missing-runtime-relative-input.o");
    assert!(!missing.exists());

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args([
            "link",
            "-o",
            "unused-runtime-relative-output",
            "--dynamic-linker",
            "/lib64/ld-linux-x86-64.so.2",
            "definitely-missing-runtime-relative-input.o",
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("--dynamic-linker requires --pie"));
}

#[test]
fn empty_dynamic_linker_is_rejected_before_input_io() {
    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args([
            "link",
            "-o",
            "unused-runtime-relative-output",
            "--pie",
            "--dynamic-linker=",
            "definitely-missing-runtime-relative-input.o",
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("dynamic linker path cannot be empty"));
}
