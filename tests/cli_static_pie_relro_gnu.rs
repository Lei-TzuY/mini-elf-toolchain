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
        "mini-elf-toolchain-static-pie-relro-{label}-{}-{nonce}",
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

fn link_mini_pie(dir: &Path, stem: &str, object: &Path) -> PathBuf {
    let output = dir.join(stem);
    let linked = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&output)
        .arg("--pie")
        .arg(object)
        .output()
        .unwrap();
    assert!(
        linked.status.success(),
        "{}",
        String::from_utf8_lossy(&linked.stderr)
    );
    output
}

fn runtime_relocation_fixture() -> &'static str {
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
    lea absolute_pointer(%rip), %rax
    mov (%rax), %rax
    lea target_value(%rip), %rbx
    cmp %rbx, %rax
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
"#
}

#[test]
fn runtime_relocating_static_pie_emits_checked_gnu_relro() {
    if !have_gnu_tools() {
        return;
    }

    let dir = temp_dir("metadata");
    let object = assemble(&dir, "relative", runtime_relocation_fixture());
    let ours = link_mini_pie(&dir, "ours-pie", &object);

    let relocations = Command::new("readelf")
        .args(["-rW", "--use-dynamic"])
        .arg(&ours)
        .output()
        .unwrap();
    assert!(relocations.status.success());
    assert!(
        String::from_utf8_lossy(&relocations.stdout).contains("R_X86_64_RELATIVE"),
        "fixture must force the self-relocation path"
    );

    let headers = Command::new("readelf")
        .args(["-lW"])
        .arg(&ours)
        .output()
        .unwrap();
    assert!(
        headers.status.success(),
        "{}",
        String::from_utf8_lossy(&headers.stderr)
    );
    let headers = String::from_utf8_lossy(&headers.stdout);
    assert!(headers.contains("DYNAMIC"), "{headers}");
    assert!(headers.contains("GNU_RELRO"), "{headers}");

    let inspected = Command::new(env!("CARGO_BIN_EXE_mini-elf-relro"))
        .arg(&ours)
        .output()
        .unwrap();
    assert!(
        inspected.status.success(),
        "{}",
        String::from_utf8_lossy(&inspected.stderr)
    );
    assert!(
        String::from_utf8_lossy(&inspected.stdout)
            .contains("Found 1 PT_GNU_RELRO segment(s)")
    );

    let gnu = dir.join("gnu-pie");
    let gnu_link = Command::new("ld")
        .args(["-pie", "--no-dynamic-linker", "-z", "relro", "-o"])
        .arg(&gnu)
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        gnu_link.status.success(),
        "{}",
        String::from_utf8_lossy(&gnu_link.stderr)
    );
    let gnu_headers = Command::new("readelf")
        .args(["-lW"])
        .arg(&gnu)
        .output()
        .unwrap();
    assert!(gnu_headers.status.success());
    assert!(
        String::from_utf8_lossy(&gnu_headers.stdout).contains("GNU_RELRO"),
        "GNU reference should expose the same RELRO program-header capability"
    );

    #[cfg(target_os = "linux")]
    {
        let status = Command::new(&ours).status().unwrap();
        assert!(status.success(), "{} returned {status}", ours.display());
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn self_relocator_seals_reported_relro_range_before_user_entry() {
    if !have_gnu_tools() {
        return;
    }

    let dir = temp_dir("enforced");
    let object = assemble(
        &dir,
        "probe",
        r#".section .rodata
.align 8
target_value:
    .quad 0x1122334455667788

.section .data
.align 8
absolute_pointer:
    .quad target_value

.section .text
.globl _start
.type _start,@function
_start:
    # First prove the R_X86_64_RELATIVE relocation completed.
    lea absolute_pointer(%rip), %rax
    mov (%rax), %rax
    lea target_value(%rip), %rbx
    cmp %rbx, %rax
    jne .Lfail

    # Walk argv and envp to the auxiliary vector.
    lea 8(%rsp), %rsi
.Largv:
    mov (%rsi), %rax
    add $8, %rsi
    test %rax, %rax
    jne .Largv
.Lenv:
    mov (%rsi), %rax
    add $8, %rsi
    test %rax, %rax
    jne .Lenv

    # Capture AT_PHDR, AT_PHENT, and AT_PHNUM.
    xor %r12, %r12
    xor %r13, %r13
    xor %r14, %r14
.Laux:
    mov (%rsi), %rax
    mov 8(%rsi), %rdx
    test %rax, %rax
    je .Laux_done
    cmp $3, %rax
    je .Lset_phdr
    cmp $4, %rax
    je .Lset_phent
    cmp $5, %rax
    je .Lset_phnum
.Laux_next:
    add $16, %rsi
    jmp .Laux
.Lset_phdr:
    mov %rdx, %r12
    jmp .Laux_next
.Lset_phent:
    mov %rdx, %r13
    jmp .Laux_next
.Lset_phnum:
    mov %rdx, %r14
    jmp .Laux_next

.Laux_done:
    test %r12, %r12
    je .Lfail
    test %r13, %r13
    je .Lfail
    test %r14, %r14
    je .Lfail

    # Find PT_PHDR and PT_GNU_RELRO in the runtime program-header table.
    xor %r15, %r15
    xor %rbp, %rbp
    mov %r12, %rsi
    mov %r14, %rcx
.Lphdr_loop:
    test %rcx, %rcx
    je .Lphdr_done
    mov (%rsi), %eax
    cmp $6, %eax
    jne .Lcheck_relro
    mov 16(%rsi), %r15
.Lcheck_relro:
    cmp $0x6474e552, %eax
    jne .Lphdr_next
    mov 16(%rsi), %rbp
.Lphdr_next:
    add %r13, %rsi
    dec %rcx
    jmp .Lphdr_loop

.Lphdr_done:
    test %r15, %r15
    je .Lfail
    test %rbp, %rbp
    je .Lfail

    # Convert the RELRO link-time vaddr to its runtime address and try to
    # mutate it. Correct enforcement must terminate us with SIGSEGV.
    mov %r12, %rax
    sub %r15, %rax
    add %rbp, %rax
    movb $0, (%rax)

    # Reaching here means the reported RELRO range stayed writable.
    mov $60, %rax
    mov $99, %rdi
    syscall

.Lfail:
    mov $60, %rax
    mov $1, %rdi
    syscall
.size _start, .-_start

.section .note.GNU-stack,"",@progbits
"#,
    );
    let ours = link_mini_pie(&dir, "sealed-pie", &object);

    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::ExitStatusExt;

        let status = Command::new(&ours).status().unwrap();
        assert_eq!(
            status.signal(),
            Some(11),
            "{} should fault when user code writes the sealed RELRO range; status={status}",
            ours.display()
        );
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn pie_without_runtime_relocations_does_not_invent_relro() {
    if !have_gnu_tools() {
        return;
    }

    let dir = temp_dir("absent");
    let object = assemble(
        &dir,
        "plain",
        r#".section .text
.globl _start
.type _start,@function
_start:
    mov $60, %rax
    xor %rdi, %rdi
    syscall
.size _start, .-_start

.section .note.GNU-stack,"",@progbits
"#,
    );
    let ours = link_mini_pie(&dir, "plain-pie", &object);
    let headers = Command::new("readelf")
        .args(["-lW"])
        .arg(&ours)
        .output()
        .unwrap();
    assert!(headers.status.success());
    assert!(!String::from_utf8_lossy(&headers.stdout).contains("GNU_RELRO"));

    let _ = fs::remove_dir_all(dir);
}
