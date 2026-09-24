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
        "mini-elf-toolchain-static-pie-weak-zero-{label}-{}-{nonce}",
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

fn link_mini(dir: &Path, stem: &str, objects: &[&Path]) -> PathBuf {
    let output = dir.join(stem);
    let mut command = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"));
    command.args(["link", "-o"]).arg(&output).arg("--pie");
    for object in objects {
        command.arg(object);
    }
    let linked = command.output().unwrap();
    assert!(
        linked.status.success(),
        "{}",
        String::from_utf8_lossy(&linked.stderr)
    );
    output
}

fn link_gnu(dir: &Path, stem: &str, objects: &[&Path]) -> PathBuf {
    let output = dir.join(stem);
    let mut command = Command::new("ld");
    command
        .args(["-pie", "--no-dynamic-linker", "-o"])
        .arg(&output);
    for object in objects {
        command.arg(object);
    }
    let linked = command.output().unwrap();
    assert!(
        linked.status.success(),
        "{}",
        String::from_utf8_lossy(&linked.stderr)
    );
    output
}

fn assert_no_dynamic_relocations(path: &Path) {
    let output = Command::new("readelf")
        .args(["-rW", "--use-dynamic"])
        .arg(path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("R_X86_64_"),
        "unresolved weak zero semantics must not require a runtime relocation: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn unresolved_weak_absolute_pointer_stays_zero_without_runtime_relocation() {
    if !have_gnu_tools() {
        return;
    }

    let dir = temp_dir("absolute");
    let object = assemble(
        &dir,
        "absolute",
        r#".weak weak_target
.section .data
.align 8
weak_ptr:
    .quad weak_target

.section .text
.globl _start
.type _start,@function
_start:
    lea weak_ptr(%rip), %rbx
    cmpq $0, (%rbx)
    jne .Lfail
    mov $60, %rax
    xor %rdi, %rdi
    syscall
.Lfail:
    mov $60, %rax
    mov $1, %rdi
    syscall
.size _start, .-_start

.section .note.GNU-stack,"",@progbits
"#,
    );

    let input = Command::new("readelf")
        .args(["-rW", "-sW"])
        .arg(&object)
        .output()
        .unwrap();
    assert!(input.status.success());
    let input = String::from_utf8_lossy(&input.stdout);
    assert!(input.contains("R_X86_64_64") && input.contains("weak_target"));
    assert!(input.contains("WEAK") && input.contains("UND"));

    let mini = link_mini(&dir, "mini-absolute", &[&object]);
    let gnu = link_gnu(&dir, "gnu-absolute", &[&object]);
    assert_no_dynamic_relocations(&mini);
    assert_no_dynamic_relocations(&gnu);

    #[cfg(target_os = "linux")]
    for executable in [&mini, &gnu] {
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
fn unresolved_weak_gotpcrel_loads_zero_without_runtime_relocation() {
    if !have_gnu_tools() {
        return;
    }

    let dir = temp_dir("got");
    let object = assemble(
        &dir,
        "got",
        r#".weak weak_target
.section .text
.globl _start
.type _start,@function
_start:
    mov weak_target@GOTPCREL(%rip), %rbx
    test %rbx, %rbx
    jne .Lfail
    mov $60, %rax
    xor %rdi, %rdi
    syscall
.Lfail:
    mov $60, %rax
    mov $1, %rdi
    syscall
.size _start, .-_start

.section .note.GNU-stack,"",@progbits
"#,
    );

    let input = Command::new("readelf")
        .args(["-rW"])
        .arg(&object)
        .output()
        .unwrap();
    assert!(input.status.success());
    let input = String::from_utf8_lossy(&input.stdout);
    assert!(
        (input.contains("GOTPCREL") || input.contains("GOTPCRELX"))
            && input.contains("weak_target"),
        "{input}"
    );

    let mini = link_mini(&dir, "mini-got", &[&object]);
    let gnu = link_gnu(&dir, "gnu-got", &[&object]);
    assert_no_dynamic_relocations(&mini);
    assert_no_dynamic_relocations(&gnu);

    #[cfg(target_os = "linux")]
    for executable in [&mini, &gnu] {
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
fn weak_reference_resolved_by_definition_keeps_runtime_binding() {
    if !have_gnu_tools() {
        return;
    }

    let dir = temp_dir("resolved");
    let reference = assemble(
        &dir,
        "reference",
        r#".weak weak_target
.section .data
.align 8
weak_ptr:
    .quad weak_target

.section .text
.globl _start
.type _start,@function
_start:
    mov weak_target@GOTPCREL(%rip), %rbx
    lea weak_target(%rip), %rcx
    cmp %rcx, %rbx
    jne .Lfail
    lea weak_ptr(%rip), %rdx
    cmp %rcx, (%rdx)
    jne .Lfail
    mov (%rbx), %rax
    movabs $0x1122334455667788, %rsi
    cmp %rsi, %rax
    jne .Lfail
    mov $60, %rax
    xor %rdi, %rdi
    syscall
.Lfail:
    mov $60, %rax
    mov $1, %rdi
    syscall
.size _start, .-_start

.section .note.GNU-stack,"",@progbits
"#,
    );
    let definition = assemble(
        &dir,
        "definition",
        r#".section .rodata
.align 8
.globl weak_target
.type weak_target,@object
weak_target:
    .quad 0x1122334455667788
.size weak_target, .-weak_target

.section .note.GNU-stack,"",@progbits
"#,
    );

    let mini = link_mini(&dir, "mini-resolved", &[&reference, &definition]);
    let relocations = Command::new("readelf")
        .args(["-rW", "--use-dynamic"])
        .arg(&mini)
        .output()
        .unwrap();
    assert!(relocations.status.success());
    let relocations = String::from_utf8_lossy(&relocations.stdout);
    assert!(
        relocations.matches("R_X86_64_RELATIVE").count() >= 2,
        "resolved direct pointer and GOT slot should remain load-bias relocations: {relocations}"
    );

    #[cfg(target_os = "linux")]
    {
        let status = Command::new(&mini).status().unwrap();
        assert!(status.success(), "{} returned {status}", mini.display());
    }

    let _ = fs::remove_dir_all(dir);
}
