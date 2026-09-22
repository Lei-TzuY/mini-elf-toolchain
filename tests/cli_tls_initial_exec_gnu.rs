use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const PT_TLS: u32 = 7;

fn command_reports(program: &str, marker: &str) -> bool {
    let Ok(output) = Command::new(program).arg("--version").output() else {
        return false;
    };
    output.status.success()
        && (String::from_utf8_lossy(&output.stdout).contains(marker)
            || String::from_utf8_lossy(&output.stderr).contains(marker))
}

fn have_gnu_toolchain() -> bool {
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
        "mini-elf-toolchain-tls-initial-exec-{label}-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&path).unwrap();
    path
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn has_tls_program_header(path: &Path) -> bool {
    let bytes = fs::read(path).unwrap();
    let phoff = read_u64(&bytes, 32) as usize;
    let phentsize = read_u16(&bytes, 54) as usize;
    let phnum = read_u16(&bytes, 56) as usize;
    (0..phnum).any(|index| read_u32(&bytes, phoff + index * phentsize) == PT_TLS)
}

#[test]
fn links_and_executes_initial_exec_tls_gottpoff_with_regular_got() {
    if !have_gnu_toolchain() {
        return;
    }

    let dir = temp_dir("execute");
    let source = dir.join("initial-exec.s");
    let object = dir.join("initial-exec.o");
    let ours = dir.join("ours");
    let gnu = dir.join("gnu");

    fs::write(
        &source,
        r#".section .tdata,"awT",@progbits
.align 4
.globl tls_init
.type tls_init,@tls_object
tls_init:
    .long 7
.size tls_init, .-tls_init

.section .tbss,"awT",@nobits
.align 4
.globl tls_zero
.type tls_zero,@tls_object
tls_zero:
    .zero 4
.size tls_zero, .-tls_zero

.section .data
.align 8
.globl regular_data
.type regular_data,@object
regular_data:
    .quad 0x1122334455667788
.size regular_data, .-regular_data

.section .bss
.align 16
tls_storage:
    .zero 32

.section .text
.globl _start
.type _start,@function
_start:
    lea tls_storage+8(%rip), %rsi
    movl $7, -8(%rsi)
    movl $0, -4(%rsi)
    mov %rsi, (%rsi)

    mov $158, %eax
    mov $0x1002, %edi
    syscall
    test %eax, %eax
    jne .Lfail

    mov tls_init@gottpoff(%rip), %rax
    cmpl $7, %fs:(%rax)
    jne .Lfail

    mov tls_zero@gottpoff(%rip), %rax
    cmpl $0, %fs:(%rax)
    jne .Lfail

    mov regular_data@GOTPCREL(%rip), %rdx
    mov (%rdx), %rcx
    movabs $0x1122334455667788, %rax
    cmp %rax, %rcx
    jne .Lfail

    mov $60, %eax
    xor %edi, %edi
    syscall
.Lfail:
    mov $60, %eax
    mov $1, %edi
    syscall
.size _start, .-_start
"#,
    )
    .unwrap();

    assert!(Command::new("as")
        .args(["--64", "-o"])
        .arg(&object)
        .arg(&source)
        .status()
        .unwrap()
        .success());

    let relocations = Command::new("readelf")
        .args(["-rW"])
        .arg(&object)
        .output()
        .unwrap();
    assert!(relocations.status.success());
    let relocation_text = String::from_utf8_lossy(&relocations.stdout);
    assert!(
        relocation_text.matches("R_X86_64_GOTTPOFF").count() >= 2,
        "fixture must carry two GOTTPOFF relocations: {relocation_text}"
    );
    assert!(
        relocation_text.contains("GOTPCREL"),
        "fixture must also carry a regular GOT relocation: {relocation_text}"
    );

    let mini = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&ours)
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        mini.status.success(),
        "{}",
        String::from_utf8_lossy(&mini.stderr)
    );

    let gnu_link = Command::new("ld")
        .args(["-static", "--no-relax", "-o"])
        .arg(&gnu)
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        gnu_link.status.success(),
        "{}",
        String::from_utf8_lossy(&gnu_link.stderr)
    );

    for executable in [&ours, &gnu] {
        assert!(
            has_tls_program_header(executable),
            "{} is missing PT_TLS",
            executable.display()
        );
        let headers = Command::new("readelf")
            .args(["-lW"])
            .arg(executable)
            .output()
            .unwrap();
        assert!(headers.status.success());
        assert!(String::from_utf8_lossy(&headers.stdout).contains("TLS"));
    }

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
fn rejects_gottpoff_against_non_tls_symbol_without_output() {
    if !command_reports("as", "GNU assembler") {
        return;
    }

    let dir = temp_dir("non-tls");
    let source = dir.join("bad.s");
    let object = dir.join("bad.o");
    let output = dir.join("bad.out");

    fs::write(
        &source,
        r#".section .data
.globl not_tls
.type not_tls,@object
not_tls:
    .quad 1
.size not_tls, .-not_tls

.section .text
.globl _start
.type _start,@function
_start:
    mov not_tls@gottpoff(%rip), %rax
    mov $60, %eax
    xor %edi, %edi
    syscall
.size _start, .-_start
"#,
    )
    .unwrap();

    assert!(Command::new("as")
        .args(["--64", "-o"])
        .arg(&object)
        .arg(&source)
        .status()
        .unwrap()
        .success());

    let relocations = Command::new("readelf")
        .args(["-rW"])
        .arg(&object)
        .output()
        .unwrap();
    assert!(relocations.status.success());
    assert!(String::from_utf8_lossy(&relocations.stdout).contains("R_X86_64_GOTTPOFF"));

    let mini = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&output)
        .arg(&object)
        .output()
        .unwrap();

    assert!(!mini.status.success());
    assert!(mini.stdout.is_empty());
    assert!(String::from_utf8_lossy(&mini.stderr).contains("expected STT_TLS"));
    assert!(!output.exists());

    let _ = fs::remove_dir_all(dir);
}
