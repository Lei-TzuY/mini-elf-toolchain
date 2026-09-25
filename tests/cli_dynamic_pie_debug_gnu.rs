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

fn dynamic_linker() -> Option<PathBuf> {
    [
        PathBuf::from("/lib64/ld-linux-x86-64.so.2"),
        PathBuf::from("/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"),
    ]
    .into_iter()
    .find(|path| path.is_file())
}

fn temp_dir(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after Unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "mini-elf-toolchain-dynamic-pie-debug-{label}-{}-{nonce}",
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

fn debug_probe_source() -> &'static str {
    r#".text
.globl _start
.type _start,@function
_start:
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

    # Capture AT_PHDR, AT_PHENT, AT_PHNUM.
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
    je .Lfail_aux
    cmp $56, %r13
    jne .Lfail_aux
    test %r14, %r14
    je .Lfail_aux

    # Find PT_PHDR and PT_DYNAMIC.
    xor %r15, %r15
    xor %rbp, %rbp
    mov %r12, %rsi
    mov %r14, %rcx
.Lphdr_loop:
    test %rcx, %rcx
    je .Lphdr_done
    mov (%rsi), %eax
    cmp $6, %eax
    jne .Lcheck_dynamic
    mov 16(%rsi), %r15
.Lcheck_dynamic:
    cmp $2, %eax
    jne .Lphdr_next
    mov 16(%rsi), %rbp
.Lphdr_next:
    add %r13, %rsi
    dec %rcx
    jmp .Lphdr_loop

.Lphdr_done:
    test %r15, %r15
    je .Lfail_phdr
    test %rbp, %rbp
    je .Lfail_phdr

    # Convert PT_DYNAMIC link-time vaddr to runtime address.
    mov %r12, %rbx
    sub %r15, %rbx
    add %rbp, %rbx

    # Find DT_DEBUG. glibc must replace its zero file value with r_debug*.
.Ldyn_loop:
    mov (%rbx), %rax
    test %rax, %rax
    je .Lfail_debug
    cmp $21, %rax
    je .Lgot_debug
    add $16, %rbx
    jmp .Ldyn_loop

.Lgot_debug:
    mov 8(%rbx), %rbx
    test %rbx, %rbx
    je .Lfail_debug

    # glibc struct r_debug: r_version == 1 and r_map != NULL.
    cmpl $1, (%rbx)
    jne .Lfail_rdebug
    mov 8(%rbx), %rax
    test %rax, %rax
    je .Lfail_rdebug

    xor %edi, %edi
    jmp .Lexit

.Lfail_aux:
    mov $11, %edi
    jmp .Lexit
.Lfail_phdr:
    mov $12, %edi
    jmp .Lexit
.Lfail_debug:
    mov $13, %edi
    jmp .Lexit
.Lfail_rdebug:
    mov $14, %edi
.Lexit:
    mov $60, %eax
    syscall
.size _start, .-_start

.section .note.GNU-stack,"",@progbits
"#
}

#[test]
fn dynamic_pie_matches_gnu_pie_identity_and_debug_tags() {
    if !have_gnu_tools() {
        return;
    }
    let Some(interpreter) = dynamic_linker() else {
        return;
    };

    let dir = temp_dir("metadata");
    let object = assemble(&dir, "probe", debug_probe_source());

    let mini = dir.join("mini-pie");
    let mini_link = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&mini)
        .arg("--dynamic-pie")
        .arg("--dynamic-linker")
        .arg(&interpreter)
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        mini_link.status.success(),
        "{}",
        String::from_utf8_lossy(&mini_link.stderr)
    );

    let gnu = dir.join("gnu-pie");
    let gnu_link = Command::new("ld")
        .arg("-pie")
        .arg("--dynamic-linker")
        .arg(&interpreter)
        .arg("-o")
        .arg(&gnu)
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        gnu_link.status.success(),
        "{}",
        String::from_utf8_lossy(&gnu_link.stderr)
    );

    for (label, path) in [("mini", &mini), ("gnu", &gnu)] {
        let dynamic = readelf(path, &["-dW"]);
        assert!(
            dynamic.lines().any(|line| line.contains("(DEBUG)")),
            "{label} missing DT_DEBUG:\n{dynamic}"
        );
        assert!(
            dynamic
                .lines()
                .any(|line| line.contains("(FLAGS_1)") && line.contains("PIE")),
            "{label} missing DF_1_PIE:\n{dynamic}"
        );
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
#[cfg(target_os = "linux")]
fn glibc_populates_dynamic_pie_debug_rendezvous_before_entry() {
    if !have_gnu_tools() {
        return;
    }
    let Some(interpreter) = dynamic_linker() else {
        return;
    };

    let dir = temp_dir("runtime");
    let object = assemble(&dir, "probe", debug_probe_source());
    let mini = dir.join("mini-pie");
    let linked = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&mini)
        .arg("--dynamic-pie")
        .arg("--dynamic-linker")
        .arg(&interpreter)
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        linked.status.success(),
        "{}",
        String::from_utf8_lossy(&linked.stderr)
    );

    let status = Command::new(&mini).status().unwrap();
    assert_eq!(
        status.code(),
        Some(0),
        "{} must observe glibc-populated DT_DEBUG/r_debug before user entry; status={status}",
        mini.display()
    );

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn shared_object_does_not_claim_pie_identity_or_debug_rendezvous() {
    if !have_gnu_tools() {
        return;
    }

    let dir = temp_dir("shared");
    let object = assemble(
        &dir,
        "shared",
        r#".text
.globl exported
.type exported,@function
exported:
    ret
.size exported, .-exported

.section .note.GNU-stack,"",@progbits
"#,
    );
    let shared = dir.join("libmini.so");
    let linked = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&shared)
        .arg("--shared")
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        linked.status.success(),
        "{}",
        String::from_utf8_lossy(&linked.stderr)
    );

    let dynamic = readelf(&shared, &["-dW"]);
    assert!(
        !dynamic.lines().any(|line| line.contains("(DEBUG)")),
        "shared object must not expose executable DT_DEBUG:\n{dynamic}"
    );
    assert!(
        !dynamic
            .lines()
            .any(|line| line.contains("(FLAGS_1)") && line.contains("PIE")),
        "shared object must not claim DF_1_PIE:\n{dynamic}"
    );

    let _ = fs::remove_dir_all(dir);
}
