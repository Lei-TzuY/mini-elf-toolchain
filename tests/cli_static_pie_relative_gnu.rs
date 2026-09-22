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

fn temp_dir(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after Unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "mini-elf-toolchain-static-pie-relative-{label}-{}-{nonce}",
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

#[test]
fn emits_relative_runtime_relocation_and_executes_absolute_pointer_pie() {
    if !have_gnu_tools() {
        return;
    }

    let dir = temp_dir("execute");
    let object = assemble(
        &dir,
        "relative",
        r#".section .rodata
.align 8
.globl target_value
.type target_value,@object
target_value:
    .quad 0x1122334455667788
.size target_value, .-target_value

.section .data
.align 8
.globl absolute_pointer
.type absolute_pointer,@object
absolute_pointer:
    .quad target_value
.size absolute_pointer, .-absolute_pointer

.section .text
.globl _start
.type _start,@function
_start:
    lea absolute_pointer(%rip), %rbx
    mov (%rbx), %rbx
    mov (%rbx), %rcx
    movabs $0x1122334455667788, %rdx
    cmp %rdx, %rcx
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
        input_relocations.contains("R_X86_64_64") && input_relocations.contains("target_value"),
        "fixture must contain an absolute 64-bit relocation: {input_relocations}"
    );

    let ours = dir.join("ours-pie");
    let mini = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&ours)
        .arg("--pie")
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
    assert!(headers.contains("DYNAMIC"));
    assert!(!headers.contains("INTERP"));

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
    assert!(dynamic.contains("(RELACOUNT)"));

    let relocations = Command::new("readelf")
        .args(["-rW", "--use-dynamic"])
        .arg(&ours)
        .output()
        .unwrap();
    assert!(relocations.status.success());
    let relocations = String::from_utf8_lossy(&relocations.stdout);
    assert!(
        relocations.contains("R_X86_64_RELATIVE"),
        "emitted PIE must expose a runtime RELATIVE relocation: {relocations}"
    );

    let gnu = dir.join("gnu-pie");
    let gnu_link = Command::new("ld")
        .args(["-pie", "--no-dynamic-linker", "-o"])
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
        .args(["-rW", "--use-dynamic"])
        .arg(&gnu)
        .output()
        .unwrap();
    assert!(gnu_relocations.status.success());
    assert!(
        String::from_utf8_lossy(&gnu_relocations.stdout).contains("R_X86_64_RELATIVE"),
        "GNU reference must use a relative runtime relocation"
    );

    #[cfg(target_os = "linux")]
    {
        let status = Command::new(&ours).status().unwrap();
        assert!(status.success(), "{} returned {status}", ours.display());
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn relative_runtime_relocation_rejects_absolute_symbol_definition() {
    if !have_gnu_tools() {
        return;
    }

    let dir = temp_dir("absolute-symbol");
    let reference = assemble(
        &dir,
        "absolute-symbol-ref",
        r#".extern absolute_target
.section .data
.globl pointer
pointer:
    .quad absolute_target

.section .text
.globl _start
_start:
    mov $60, %rax
    xor %rdi, %rdi
    syscall
"#,
    );
    let definition = assemble(
        &dir,
        "absolute-symbol-def",
        r#".globl absolute_target
.set absolute_target, 0x4321
"#,
    );

    let relocations = Command::new("readelf")
        .args(["-rW"])
        .arg(&reference)
        .output()
        .unwrap();
    assert!(relocations.status.success());
    assert!(String::from_utf8_lossy(&relocations.stdout).contains("R_X86_64_64"));

    let output = dir.join("must-not-exist");
    let mini = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&output)
        .arg("--pie")
        .arg(&reference)
        .arg(&definition)
        .output()
        .unwrap();

    assert!(!mini.status.success());
    assert!(mini.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&mini.stderr);
    assert!(stderr.contains("SHN_ABS"));
    assert!(stderr.contains("R_X86_64_RELATIVE"));
    assert!(!output.exists());

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn relative_runtime_relocation_rejects_undefined_weak_symbol() {
    if !command_reports("as", "GNU assembler") {
        return;
    }

    let dir = temp_dir("weak");
    let object = assemble(
        &dir,
        "weak",
        r#".weak weak_target
.section .data
.globl pointer
pointer:
    .quad weak_target

.section .text
.globl _start
_start:
    mov $60, %rax
    xor %rdi, %rdi
    syscall
"#,
    );

    let relocations = Command::new("readelf")
        .args(["-rW"])
        .arg(&object)
        .output()
        .unwrap();
    assert!(relocations.status.success());
    assert!(String::from_utf8_lossy(&relocations.stdout).contains("R_X86_64_64"));

    let output = dir.join("must-not-exist");
    let mini = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&output)
        .arg("--pie")
        .arg(&object)
        .output()
        .unwrap();

    assert!(!mini.status.success());
    assert!(mini.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&mini.stderr);
    assert!(stderr.contains("undefined weak"));
    assert!(stderr.contains("R_X86_64_RELATIVE"));
    assert!(!output.exists());

    let _ = fs::remove_dir_all(dir);
}
