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
        "mini-elf-toolchain-static-pie-irelative-{label}-{}-{nonce}",
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

fn link_mini_pie(dir: &Path, stem: &str, object: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(dir.join(stem))
        .arg("--pie")
        .arg(object)
        .output()
        .unwrap()
}

fn mixed_ifunc_fixture() -> &'static str {
    r#".section .rodata
.align 8
target_value:
    .quad 0x1122334455667788

.section .text
.type implementation,@function
implementation:
    mov $42, %eax
    ret
.size implementation, .-implementation

.type resolver,@function
resolver:
    lea implementation(%rip), %rax
    ret
.size resolver, .-resolver

.globl chosen
.type chosen,@gnu_indirect_function
.set chosen,resolver

.section .data
.align 8
.globl ordinary_ptr
ordinary_ptr:
    .quad target_value
.globl ifunc_ptr
ifunc_ptr:
    .quad chosen

.section .text
.globl _start
.type _start,@function
_start:
    mov ifunc_ptr(%rip), %rax
    call *%rax
    cmp $42, %eax
    jne .Lfail

    mov ordinary_ptr(%rip), %rbx
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

.section .note.GNU-stack,"",@progbits
"#
}

#[test]
fn static_pie_executes_local_ifunc_and_keeps_relative_prefix() {
    if !have_gnu_tools() {
        return;
    }

    let dir = temp_dir("mixed");
    let object = assemble(&dir, "mixed", mixed_ifunc_fixture());

    let input = Command::new("readelf")
        .args(["-rW", "-sW"])
        .arg(&object)
        .output()
        .unwrap();
    assert!(input.status.success());
    let input = String::from_utf8_lossy(&input.stdout);
    assert!(input.contains("R_X86_64_64"), "{input}");
    assert!(input.contains("IFUNC") && input.contains("chosen"), "{input}");

    let mini = link_mini_pie(&dir, "ours-pie", &object);
    assert!(
        mini.status.success(),
        "{}",
        String::from_utf8_lossy(&mini.stderr)
    );
    let ours = dir.join("ours-pie");

    let relocations = Command::new("readelf")
        .args(["-rW", "--use-dynamic"])
        .arg(&ours)
        .output()
        .unwrap();
    assert!(relocations.status.success());
    let relocations = String::from_utf8_lossy(&relocations.stdout);
    let relative = relocations
        .find("R_X86_64_RELATIVE")
        .expect("ordinary pointer must stay RELATIVE");
    let irelative = relocations
        .find("R_X86_64_IRELATIVE")
        .expect("IFUNC pointer must become IRELATIVE");
    assert!(
        relative < irelative,
        "RELATIVE entries must remain the DT_RELACOUNT prefix: {relocations}"
    );

    let dynamic = Command::new("readelf")
        .args(["-dW"])
        .arg(&ours)
        .output()
        .unwrap();
    assert!(dynamic.status.success());
    let dynamic = String::from_utf8_lossy(&dynamic.stdout);
    let relacount = dynamic
        .lines()
        .find(|line| line.contains("(RELACOUNT)"))
        .expect("mixed runtime table must publish DT_RELACOUNT");
    assert!(
        relacount.split_whitespace().last() == Some("1"),
        "only the ordinary RELATIVE entry belongs to DT_RELACOUNT: {relacount}"
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
    let gnu_relocations = String::from_utf8_lossy(&gnu_relocations.stdout);
    assert!(gnu_relocations.contains("R_X86_64_RELATIVE"));
    assert!(gnu_relocations.contains("R_X86_64_IRELATIVE"));

    #[cfg(target_os = "linux")]
    {
        let status = Command::new(&ours).status().unwrap();
        assert!(status.success(), "{} returned {status}", ours.display());
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn ifunc_got_slot_resolves_before_static_pie_relro_sealing() {
    if !have_gnu_tools() {
        return;
    }

    let dir = temp_dir("got");
    let object = assemble(
        &dir,
        "got",
        r#".section .text
.type implementation,@function
implementation:
    mov $42, %eax
    ret
.size implementation, .-implementation

.type resolver,@function
resolver:
    lea implementation(%rip), %rax
    ret
.size resolver, .-resolver

.globl chosen
.type chosen,@gnu_indirect_function
.set chosen,resolver

.globl _start
.type _start,@function
_start:
    mov chosen@GOTPCREL(%rip), %rax
    call *%rax
    cmp $42, %eax
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
        input.contains("GOTPCREL") && input.contains("chosen"),
        "fixture must use the ordinary GOT path: {input}"
    );

    let mini = link_mini_pie(&dir, "ours-got-pie", &object);
    assert!(
        mini.status.success(),
        "{}",
        String::from_utf8_lossy(&mini.stderr)
    );
    let ours = dir.join("ours-got-pie");

    let relocations = Command::new("readelf")
        .args(["-rW", "--use-dynamic"])
        .arg(&ours)
        .output()
        .unwrap();
    assert!(relocations.status.success());
    let relocations = String::from_utf8_lossy(&relocations.stdout);
    assert!(
        relocations.contains("R_X86_64_IRELATIVE"),
        "IFUNC GOT slot must be resolver-backed: {relocations}"
    );

    let headers = Command::new("readelf")
        .args(["-lW"])
        .arg(&ours)
        .output()
        .unwrap();
    assert!(headers.status.success());
    let headers = String::from_utf8_lossy(&headers.stdout);
    assert!(
        headers.matches("GNU_RELRO").count() >= 2,
        "runtime metadata and isolated GOT must both remain protected: {headers}"
    );

    #[cfg(target_os = "linux")]
    {
        let status = Command::new(&ours).status().unwrap();
        assert!(
            status.success(),
            "resolver must run before GOT RELRO sealing; {} returned {status}",
            ours.display()
        );
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn static_pie_rejects_ifunc_resolver_outside_executable_storage() {
    if !command_reports("as", "GNU assembler") {
        return;
    }

    let dir = temp_dir("nonexec");
    let object = assemble(
        &dir,
        "nonexec",
        r#".section .data
.align 8
resolver_data:
    .quad 0
.globl chosen
.type chosen,@gnu_indirect_function
.set chosen,resolver_data

.globl ifunc_ptr
ifunc_ptr:
    .quad chosen

.section .text
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
    assert!(stderr.contains("IFUNC"), "{stderr}");
    assert!(stderr.contains("executable"), "{stderr}");
    assert!(!output.exists());

    let _ = fs::remove_dir_all(dir);
}
