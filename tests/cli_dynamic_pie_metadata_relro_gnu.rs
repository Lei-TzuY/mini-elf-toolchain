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
        "mini-elf-toolchain-dynamic-pie-metadata-relro-{label}-{}-{nonce}",
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

fn provider(dir: &Path) -> PathBuf {
    let object = assemble(
        dir,
        "provider",
        r#".text
.globl provider_value
.type provider_value,@function
provider_value:
    mov $42, %eax
    ret
.size provider_value, .-provider_value

.section .note.GNU-stack,"",@progbits
"#,
    );
    let shared = dir.join("libprovider.so");
    let linked = Command::new("ld")
        .args([
            "-shared",
            "--hash-style=sysv",
            "-soname",
            "libprovider.so",
            "-o",
        ])
        .arg(&shared)
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        linked.status.success(),
        "{}",
        String::from_utf8_lossy(&linked.stderr)
    );
    shared
}

fn consumer_source() -> &'static str {
    r#".text
.globl provider_value
.type provider_value,@function

.globl _start
.type _start,@function
_start:
    # Prove lazy GOTPLT remains usable after loader startup and can transition
    # on the first call before being reused on the second call.
    call provider_value@PLT
    cmp $42, %eax
    jne .Lfail
    call provider_value@PLT
    cmp $42, %eax
    jne .Lfail

    # Walk argv/envp to auxv.
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

    # Find PT_PHDR and PT_DYNAMIC link-time virtual addresses.
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
    je .Lfail
    test %rbp, %rbp
    je .Lfail

    # AT_PHDR - PT_PHDR.p_vaddr gives load bias. PT_DYNAMIC must be covered
    # by RELRO, so a post-startup byte write must fault.
    mov %r12, %rax
    sub %r15, %rax
    add %rbp, %rax
    movb $0, (%rax)

    # Reaching this point means loader metadata remained writable.
    mov $60, %eax
    mov $99, %edi
    syscall

.Lfail:
    mov $60, %eax
    mov $1, %edi
    syscall
.size _start, .-_start

.section .note.GNU-stack,"",@progbits
"#
}

#[test]
#[cfg(target_os = "linux")]
fn dynamic_pie_metadata_relro_is_enforced_without_breaking_lazy_plt() {
    use std::os::unix::process::ExitStatusExt;

    if !have_tools() {
        return;
    }
    let Some(interpreter) = dynamic_linker() else {
        return;
    };

    let dir = temp_dir("enforced");
    let provider = provider(&dir);
    let consumer = assemble(&dir, "consumer", consumer_source());

    let ours = dir.join("mini-app");
    let linked = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&ours)
        .arg("--dynamic-pie")
        .arg("--dynamic-linker")
        .arg(&interpreter)
        .arg("--needed-from")
        .arg(&provider)
        .args(["--runpath", "$ORIGIN"])
        .arg(&consumer)
        .output()
        .unwrap();
    assert!(
        linked.status.success(),
        "{}",
        String::from_utf8_lossy(&linked.stderr)
    );

    let headers = readelf(&ours, &["-lW"]);
    assert!(headers.contains("DYNAMIC"), "{headers}");
    assert!(headers.contains("GNU_RELRO"), "{headers}");
    let relro = Command::new(env!("CARGO_BIN_EXE_mini-elf-relro"))
        .arg(&ours)
        .output()
        .unwrap();
    assert!(
        relro.status.success(),
        "{}",
        String::from_utf8_lossy(&relro.stderr)
    );

    let status = Command::new(&ours).status().unwrap();
    assert_eq!(
        status.signal(),
        Some(11),
        "{} must fault on a post-startup PT_DYNAMIC write while lazy PLT calls remain functional; status={status}",
        ours.display()
    );

    let gnu = dir.join("gnu-app");
    let gnu_link = Command::new("ld")
        .arg("-pie")
        .arg("--dynamic-linker")
        .arg(&interpreter)
        .args(["-z", "relro", "-z", "lazy", "-rpath", "$ORIGIN", "-o"])
        .arg(&gnu)
        .arg(&consumer)
        .arg("-L")
        .arg(&dir)
        .arg("-lprovider")
        .output()
        .unwrap();
    assert!(
        gnu_link.status.success(),
        "{}",
        String::from_utf8_lossy(&gnu_link.stderr)
    );
    let gnu_headers = readelf(&gnu, &["-lW"]);
    assert!(gnu_headers.contains("GNU_RELRO"), "{gnu_headers}");
    let gnu_status = Command::new(&gnu).status().unwrap();
    assert_eq!(
        gnu_status.signal(),
        Some(11),
        "GNU -z relro -z lazy should enforce the same metadata protection; status={gnu_status}"
    );

    let _ = fs::remove_dir_all(dir);
}
