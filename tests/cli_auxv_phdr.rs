use std::fs;
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

#[test]
fn cli_maps_program_headers_and_kernel_publishes_at_phdr() {
    if !command_reports("as", "GNU assembler") || !command_reports("readelf", "GNU readelf") {
        return;
    }

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock must be after Unix epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "mini-elf-toolchain-auxv-phdr-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).expect("create temporary test directory");
    let source = dir.join("start.s");
    let object = dir.join("start.o");
    let output = dir.join("auxv-phdr");

    fs::write(
        &source,
        r#".text
.globl _start
.type _start,@function
_start:
    mov %rsp, %r11
    mov (%r11), %rcx
    lea 16(%r11,%rcx,8), %rsi
.Lenv:
    cmpq $0, (%rsi)
    je .Laux
    add $8, %rsi
    jmp .Lenv
.Laux:
    add $8, %rsi
    xor %r8d, %r8d
    xor %r9d, %r9d
    xor %r10d, %r10d
.Lscan:
    mov (%rsi), %rax
    mov 8(%rsi), %rdx
    add $16, %rsi
    test %rax, %rax
    je .Lcheck
    cmp $3, %rax
    je .Lphdr
    cmp $4, %rax
    je .Lphent
    cmp $5, %rax
    je .Lphnum
    jmp .Lscan
.Lphdr:
    mov %rdx, %r8
    jmp .Lscan
.Lphent:
    mov %rdx, %r9
    jmp .Lscan
.Lphnum:
    mov %rdx, %r10
    jmp .Lscan
.Lcheck:
    test %r8, %r8
    je .Lfail
    cmp $56, %r9
    jne .Lfail
    cmp $2, %r10
    jb .Lfail
    cmpl $6, (%r8)
    jne .Lfail
    mov 16(%r8), %rax
    cmp %r8, %rax
    jne .Lfail
    mov 32(%r8), %rax
    imul $56, %r10, %rdx
    cmp %rdx, %rax
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
    .expect("write auxv fixture");

    let assemble = Command::new("as")
        .args(["--64", "-o"])
        .arg(&object)
        .arg(&source)
        .status()
        .expect("run GNU as");
    assert!(assemble.success(), "GNU as failed");

    let link = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&output)
        .arg(&object)
        .output()
        .expect("run mini-elf-toolchain link");
    assert!(
        link.status.success(),
        "link failed: {}",
        String::from_utf8_lossy(&link.stderr)
    );

    let headers = Command::new("readelf")
        .args(["-lW"])
        .arg(&output)
        .output()
        .expect("run GNU readelf -lW");
    assert!(headers.status.success());
    assert!(
        String::from_utf8_lossy(&headers.stdout).contains("PHDR"),
        "linked executable has no PT_PHDR: {}",
        String::from_utf8_lossy(&headers.stdout)
    );

    #[cfg(target_os = "linux")]
    {
        let status = Command::new(&output)
            .status()
            .expect("execute linked auxv fixture");
        assert!(status.success(), "linked executable returned {status}");
    }

    fs::remove_dir_all(dir).expect("remove temporary test directory");
}
