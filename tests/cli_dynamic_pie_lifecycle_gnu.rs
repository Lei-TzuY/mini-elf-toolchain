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
        "mini-elf-toolchain-dynamic-pie-lifecycle-{label}-{}-{nonce}",
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

fn link_mini(dir: &Path, object: &Path, interpreter: &Path, libc: &Path) -> PathBuf {
    let output = dir.join("mini-lifecycle");
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

fn link_gnu(dir: &Path, object: &Path, interpreter: &Path, libc: &Path) -> PathBuf {
    let output = dir.join("gnu-lifecycle");
    let linked = Command::new("ld")
        .arg("-pie")
        .arg("--dynamic-linker")
        .arg(interpreter)
        .arg("-o")
        .arg(&output)
        .arg(object)
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

fn lifecycle_fixture() -> &'static str {
    r#".data
.align 8
state:
    .quad 0

.text
.type preinit_hook,@function
preinit_hook:
    movq $1, state(%rip)
    ret
.size preinit_hook, .-preinit_hook

.type init_hook,@function
init_hook:
    cmpq $1, state(%rip)
    jne .Linit_bad
    movq $2, state(%rip)
    ret
.Linit_bad:
    movq $99, state(%rip)
    ret
.size init_hook, .-init_hook

.type fini_hook,@function
fini_hook:
    cmpq $2, state(%rip)
    jne .Lfini_bad
    mov $231, %rax
    mov $43, %rdi
    syscall
.Lfini_bad:
    mov $231, %rax
    mov $99, %rdi
    syscall
.size fini_hook, .-fini_hook

.type main,@function
main:
    cmpq $2, state(%rip)
    jne .Lmain_bad
    mov $42, %eax
    ret
.Lmain_bad:
    mov $10, %eax
    ret
.size main, .-main

.globl __libc_start_main
.type __libc_start_main,@function
.globl _start
.type _start,@function
_start:
    xor %ebp, %ebp
    mov %rdx, %r9
    pop %rsi
    mov %rsp, %rdx
    and $-16, %rsp
    push %rax
    push %rsp
    xor %r8d, %r8d
    xor %ecx, %ecx
    lea main(%rip), %rdi
    call __libc_start_main@PLT
    hlt
.size _start, .-_start

.section .preinit_array,"aw",@preinit_array
.quad preinit_hook
.section .init_array,"aw",@init_array
.quad init_hook
.section .fini_array,"aw",@fini_array
.quad fini_hook

.section .note.GNU-stack,"",@progbits
"#
}

#[test]
#[cfg(target_os = "linux")]
fn dynamic_pie_lifecycle_arrays_match_gnu_metadata_and_execution() {
    if !have_tools() {
        return;
    }
    let Some(interpreter) = dynamic_linker() else {
        return;
    };
    let Some(libc) = libc_path() else {
        return;
    };

    let dir = temp_dir("runtime");
    let object = assemble(&dir, "lifecycle", lifecycle_fixture());
    let ours = link_mini(&dir, &object, &interpreter, &libc);
    let gnu = link_gnu(&dir, &object, &interpreter, &libc);

    for image in [&ours, &gnu] {
        let dynamic = readelf(image, &["-dW"]);
        for fact in [
            "PREINIT_ARRAY",
            "PREINIT_ARRAYSZ",
            "INIT_ARRAY",
            "INIT_ARRAYSZ",
            "FINI_ARRAY",
            "FINI_ARRAYSZ",
        ] {
            assert!(
                dynamic.contains(fact),
                "{} missing {fact}:\n{dynamic}",
                image.display()
            );
        }

        let inspected = Command::new(env!("CARGO_BIN_EXE_mini-elf-dyninit"))
            .arg(image)
            .output()
            .unwrap();
        assert!(
            inspected.status.success(),
            "{}",
            String::from_utf8_lossy(&inspected.stderr)
        );
        let inspected = String::from_utf8_lossy(&inspected.stdout);
        assert!(
            inspected.contains("DT_PREINIT_ARRAY: address="),
            "{inspected}"
        );
        assert!(inspected.contains("DT_INIT_ARRAY: address="), "{inspected}");
        assert!(inspected.contains("DT_FINI_ARRAY: address="), "{inspected}");
        assert_eq!(inspected.matches("entries=1").count(), 3, "{inspected}");

        let status = Command::new(image).status().unwrap();
        assert_eq!(
            status.code(),
            Some(43),
            "{} must execute preinit -> init -> main -> fini in order; status={status}",
            image.display()
        );
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
#[cfg(target_os = "linux")]
fn malformed_lifecycle_pointer_array_is_rejected_before_output() {
    if !have_tools() {
        return;
    }
    let Some(interpreter) = dynamic_linker() else {
        return;
    };

    let dir = temp_dir("malformed-size");
    let object = assemble(
        &dir,
        "malformed",
        r#".text
.globl _start
.type _start,@function
_start:
    mov $60, %eax
    xor %edi, %edi
    syscall
.size _start, .-_start

.section .init_array,"aw",@init_array
.byte 0

.section .note.GNU-stack,"",@progbits
"#,
    );
    let output = dir.join("should-not-exist");
    let linked = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&output)
        .arg("--dynamic-pie")
        .arg("--dynamic-linker")
        .arg(&interpreter)
        .arg(&object)
        .output()
        .unwrap();

    assert!(!linked.status.success(), "malformed lifecycle array was accepted");
    assert!(
        String::from_utf8_lossy(&linked.stderr)
            .contains("lifecycle arrays must contain whole 8-byte function pointers"),
        "{}",
        String::from_utf8_lossy(&linked.stderr)
    );
    assert!(
        !output.exists(),
        "failed lifecycle validation must not leave an output image"
    );

    let _ = fs::remove_dir_all(dir);
}
