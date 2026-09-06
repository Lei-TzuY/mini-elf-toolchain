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

fn temp_dir() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock must be after Unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "mini-elf-toolchain-cli-tls-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&path).expect("create temporary test directory");
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TlsHeader {
    file_offset: u64,
    virtual_address: u64,
    file_size: u64,
    memory_size: u64,
    alignment: u64,
}

fn tls_header(path: &Path) -> TlsHeader {
    let bytes = fs::read(path).expect("read executable");
    assert_eq!(&bytes[..4], b"\x7fELF");
    let phoff = read_u64(&bytes, 32) as usize;
    let phentsize = read_u16(&bytes, 54) as usize;
    let phnum = read_u16(&bytes, 56) as usize;
    assert!(phentsize >= 56);

    for index in 0..phnum {
        let base = phoff + index * phentsize;
        if read_u32(&bytes, base) == PT_TLS {
            return TlsHeader {
                file_offset: read_u64(&bytes, base + 8),
                virtual_address: read_u64(&bytes, base + 16),
                file_size: read_u64(&bytes, base + 32),
                memory_size: read_u64(&bytes, base + 40),
                alignment: read_u64(&bytes, base + 48),
            };
        }
    }
    panic!("executable has no PT_TLS program header");
}

#[test]
fn cli_links_gnu_static_local_exec_tls_and_emits_pt_tls() {
    if !have_gnu_toolchain() {
        return;
    }

    let dir = temp_dir();
    let source = dir.join("tls.s");
    let object = dir.join("tls.o");
    let ours = dir.join("ours-tls");
    let gnu = dir.join("gnu-tls");

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

    mov %fs:0, %rax
    lea tls_zero@tpoff(%rax), %rcx
    cmpl $0, (%rcx)
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
    .expect("write TLS assembly fixture");

    let assemble = Command::new("as")
        .args(["--64", "-o"])
        .arg(&object)
        .arg(&source)
        .status()
        .expect("run GNU as");
    assert!(assemble.success(), "GNU as failed");

    let relocations = Command::new("readelf")
        .args(["-rW"])
        .arg(&object)
        .output()
        .expect("run GNU readelf -rW");
    assert!(relocations.status.success());
    let relocation_stdout = String::from_utf8_lossy(&relocations.stdout);
    assert!(
        relocation_stdout.contains("R_X86_64_TPOFF32"),
        "GNU fixture did not contain TPOFF32: {relocation_stdout}"
    );

    let mini_link = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&ours)
        .arg(&object)
        .output()
        .expect("run mini-elf-toolchain link");
    assert!(
        mini_link.status.success(),
        "mini linker failed: {}",
        String::from_utf8_lossy(&mini_link.stderr)
    );

    let gnu_link = Command::new("ld")
        .args(["-static", "-o"])
        .arg(&gnu)
        .arg(&object)
        .output()
        .expect("run GNU ld");
    assert!(
        gnu_link.status.success(),
        "GNU ld failed: {}",
        String::from_utf8_lossy(&gnu_link.stderr)
    );

    for executable in [&ours, &gnu] {
        let program_headers = Command::new("readelf")
            .args(["-lW"])
            .arg(executable)
            .output()
            .expect("run GNU readelf -lW");
        assert!(program_headers.status.success());
        let stdout = String::from_utf8_lossy(&program_headers.stdout);
        assert!(stdout.contains("TLS"), "missing TLS header: {stdout}");

        let tls = tls_header(executable);
        assert_eq!(tls.file_size, 4);
        assert_eq!(tls.memory_size, 8);
        assert_eq!(tls.alignment, 4);
        let bytes = fs::read(executable).expect("read executable bytes");
        assert_eq!(
            &bytes[tls.file_offset as usize..tls.file_offset as usize + 4],
            &7_u32.to_le_bytes()
        );
    }

    #[cfg(target_os = "linux")]
    for executable in [&ours, &gnu] {
        let status = Command::new(executable)
            .status()
            .expect("execute static TLS fixture");
        assert!(status.success(), "{} returned {status}", executable.display());
    }

    fs::remove_dir_all(dir).expect("remove temporary test directory");
}
