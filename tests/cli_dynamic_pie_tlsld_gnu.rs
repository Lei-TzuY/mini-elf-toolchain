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

fn command_available(program: &str) -> bool {
    Command::new(program)
        .arg("--version")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn have_tools() -> bool {
    command_reports("as", "GNU assembler")
        && command_reports("ld", "GNU ld")
        && command_reports("readelf", "GNU readelf")
        && command_available("cc")
}

fn dynamic_linker() -> Option<PathBuf> {
    [
        PathBuf::from("/lib64/ld-linux-x86-64.so.2"),
        PathBuf::from("/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"),
    ]
    .into_iter()
    .find(|path| path.is_file())
}

fn libc_path() -> Option<PathBuf> {
    let output = Command::new("cc")
        .arg("-print-file-name=libc.so.6")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let path = PathBuf::from(String::from_utf8(output.stdout).ok()?.trim());
    path.is_file().then_some(path)
}

fn temp_dir(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after Unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "mini-elf-toolchain-dynamic-pie-tlsld-{label}-{}-{nonce}",
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

fn link_mini(dir: &Path, stem: &str, object: &Path, interpreter: &Path, libc: &Path) -> PathBuf {
    let output = dir.join(format!("mini-{stem}"));
    let linked = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&output)
        .arg("--dynamic-pie")
        .arg("--dynamic-linker")
        .arg(interpreter)
        .arg("--needed-from")
        .arg(libc)
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

fn link_gnu(dir: &Path, stem: &str, object: &Path, interpreter: &Path, libc: &Path) -> PathBuf {
    let output = dir.join(format!("gnu-{stem}"));
    let linked = Command::new("ld")
        .arg("-pie")
        .arg("--dynamic-linker")
        .arg(interpreter)
        .arg("-o")
        .arg(&output)
        .arg(object)
        .arg(interpreter)
        .arg(libc)
        .output()
        .unwrap();
    assert!(
        linked.status.success(),
        "{}",
        String::from_utf8_lossy(&linked.stderr)
    );
    output
}

#[test]
#[cfg(target_os = "linux")]
fn dynamic_pie_local_dynamic_tls_uses_one_module_descriptor_and_executes() {
    if !have_tools() {
        return;
    }
    let Some(interpreter) = dynamic_linker() else {
        return;
    };
    let Some(libc) = libc_path() else {
        return;
    };

    let dir = temp_dir("access");
    let object = assemble(
        &dir,
        "tlsld",
        r#".section .tdata,"awT",@progbits
.align 8
.local tls_a
.type tls_a,@tls_object
tls_a:
    .quad 11
.size tls_a, .-tls_a

.section .tbss,"awT",@nobits
.align 8
.local tls_b
.type tls_b,@tls_object
tls_b:
    .zero 8
.size tls_b, .-tls_b

.section .text
.extern __tls_get_addr
.type __tls_get_addr,@function
.globl _start
.type _start,@function
_start:
    leaq tls_a@tlsld(%rip), %rdi
    call __tls_get_addr@PLT
    mov tls_a@dtpoff(%rax), %rcx
    add tls_b@dtpoff(%rax), %rcx
    cmp $11, %rcx
    jne .Lfail
    addq $1, tls_a@dtpoff(%rax)
    addq $2, tls_b@dtpoff(%rax)
    mov tls_a@dtpoff(%rax), %rcx
    add tls_b@dtpoff(%rax), %rcx
    cmp $14, %rcx
    jne .Lfail
    mov $60, %eax
    xor %edi, %edi
    syscall
.Lfail:
    mov $60, %eax
    mov $1, %edi
    syscall
.size _start, .-_start

.section .note.GNU-stack,"",@progbits
"#,
    );

    let input_relocations = readelf(&object, &["-rW"]);
    assert!(input_relocations.contains("R_X86_64_TLSLD"));
    assert!(input_relocations.contains("R_X86_64_DTPOFF32"));
    assert!(input_relocations.contains("__tls_get_addr"));

    let ours = link_mini(&dir, "tlsld", &object, &interpreter, &libc);
    let headers = readelf(&ours, &["-lW"]);
    assert!(headers.contains("INTERP"), "{headers}");
    assert!(headers.contains("TLS"), "{headers}");

    let relocations = readelf(&ours, &["-rW", "--use-dynamic"]);
    let dtpmod = relocations
        .lines()
        .filter(|line| line.contains("R_X86_64_DTPMOD64"))
        .count();
    assert_eq!(
        dtpmod, 1,
        "local-dynamic executable TLS must share exactly one module descriptor: {relocations}"
    );
    assert!(
        !relocations.contains("R_X86_64_DTPOFF64"),
        "local symbol offsets must be linked into DTPOFF32 sites: {relocations}"
    );
    assert!(
        relocations.contains("R_X86_64_JUMP_SLOT") && relocations.contains("__tls_get_addr"),
        "{relocations}"
    );

    let symbols = readelf(&ours, &["-sDW"]);
    assert!(!symbols.lines().any(|line| line.ends_with(" tls_a")));
    assert!(!symbols.lines().any(|line| line.ends_with(" tls_b")));

    let status = Command::new(&ours).status().unwrap();
    assert!(status.success(), "mini TLSLD executable returned {status}");

    let gnu = link_gnu(&dir, "tlsld", &object, &interpreter, &libc);
    let gnu_headers = readelf(&gnu, &["-lW"]);
    assert!(gnu_headers.contains("TLS"), "{gnu_headers}");
    let gnu_status = Command::new(&gnu).status().unwrap();
    assert!(
        gnu_status.success(),
        "GNU TLSLD reference returned {gnu_status}"
    );

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn dynamic_pie_local_dynamic_tls_rejects_nonlocal_tls_symbols() {
    if !have_tools() {
        return;
    }
    let Some(interpreter) = dynamic_linker() else {
        return;
    };
    let Some(libc) = libc_path() else {
        return;
    };

    let dir = temp_dir("nonlocal");
    let object = assemble(
        &dir,
        "nonlocal",
        r#".section .tdata,"awT",@progbits
.globl nonlocal_tls
.type nonlocal_tls,@tls_object
nonlocal_tls:
    .quad 3
.size nonlocal_tls, .-nonlocal_tls

.section .text
.globl _start
.type _start,@function
_start:
    leaq nonlocal_tls@tlsld(%rip), %rdi
    call __tls_get_addr@PLT
    mov nonlocal_tls@dtpoff(%rax), %rdi
    mov $60, %eax
    syscall
.size _start, .-_start

.section .note.GNU-stack,"",@progbits
"#,
    );
    let output = dir.join("must-not-exist");

    let mini = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&output)
        .arg("--dynamic-pie")
        .arg("--dynamic-linker")
        .arg(&interpreter)
        .arg("--needed-from")
        .arg(&libc)
        .arg(&object)
        .output()
        .unwrap();

    assert!(!mini.status.success());
    assert!(mini.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&mini.stderr);
    assert!(
        stderr.contains("local-dynamic") || stderr.contains("local TLS"),
        "{stderr}"
    );
    assert!(!output.exists());

    let _ = fs::remove_dir_all(dir);
}
