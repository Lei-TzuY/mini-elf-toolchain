use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
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
        "mini-elf-toolchain-static-pie-tls-{label}-{}-{nonce}",
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

fn program_header_count(path: &Path, kind: u32) -> usize {
    let bytes = fs::read(path).unwrap();
    let phoff = read_u64(&bytes, 32) as usize;
    let phentsize = read_u16(&bytes, 54) as usize;
    let phnum = read_u16(&bytes, 56) as usize;
    (0..phnum)
        .filter(|index| read_u32(&bytes, phoff + index * phentsize) == kind)
        .count()
}

fn dynamic_relative_count(path: &Path) -> usize {
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
    String::from_utf8_lossy(&output.stdout)
        .matches("R_X86_64_RELATIVE")
        .count()
}

#[test]
fn pie_tls_local_initial_exec_and_runtime_got_coexist_and_execute() {
    if !have_gnu_toolchain() {
        return;
    }

    let dir = temp_dir("mixed");
    let source = dir.join("mixed.s");
    let object = dir.join("mixed.o");
    let ours = dir.join("ours-pie");
    let gnu = dir.join("gnu-pie");

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

    mov %fs:0, %rax
    lea tls_init@tpoff(%rax), %rcx
    cmpl $7, (%rcx)
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
    assert!(relocation_text.contains("R_X86_64_TPOFF32"));
    assert!(relocation_text.contains("R_X86_64_GOTTPOFF"));
    assert!(relocation_text.contains("GOTPCREL"));

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

    assert_eq!(program_header_count(&ours, PT_TLS), 1);
    assert_eq!(program_header_count(&ours, PT_DYNAMIC), 1);
    assert_eq!(program_header_count(&ours, PT_INTERP), 0);
    assert_eq!(
        dynamic_relative_count(&ours),
        1,
        "ordinary GOT entry should be the only runtime-relative relocation"
    );

    let gnu_link = Command::new("ld")
        .args(["-pie", "--no-dynamic-linker", "--no-relax", "-o"])
        .arg(&gnu)
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        gnu_link.status.success(),
        "{}",
        String::from_utf8_lossy(&gnu_link.stderr)
    );
    assert_eq!(program_header_count(&gnu, PT_TLS), 1);
    assert_eq!(program_header_count(&gnu, PT_INTERP), 0);

    #[cfg(target_os = "linux")]
    {
        let status = Command::new(&ours).status().unwrap();
        assert!(status.success(), "{} returned {status}", ours.display());
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn pie_tls_without_runtime_relative_relocations_keeps_no_dynamic_plane_and_executes() {
    if !have_gnu_toolchain() {
        return;
    }

    let dir = temp_dir("local-only");
    let source = dir.join("local.s");
    let object = dir.join("local.o");
    let ours = dir.join("ours-pie");
    let gnu = dir.join("gnu-pie");

    fs::write(
        &source,
        r#".section .tdata,"awT",@progbits
.align 4
.globl tls_init
.type tls_init,@tls_object
tls_init:
    .long 7
.size tls_init, .-tls_init

.section .bss
.align 16
tls_storage:
    .zero 32

.section .text
.globl _start
.type _start,@function
_start:
    lea tls_storage+4(%rip), %rsi
    movl $7, -4(%rsi)
    mov %rsi, (%rsi)

    mov $158, %eax
    mov $0x1002, %edi
    syscall
    test %eax, %eax
    jne .Lfail

    mov %fs:0, %rax
    lea tls_init@tpoff(%rax), %rcx
    cmpl $7, (%rcx)
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

    for executable in [&ours, &gnu] {
        assert_eq!(program_header_count(executable, PT_TLS), 1);
        assert_eq!(program_header_count(executable, PT_INTERP), 0);
    }
    assert_eq!(program_header_count(&ours, PT_DYNAMIC), 0);

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
