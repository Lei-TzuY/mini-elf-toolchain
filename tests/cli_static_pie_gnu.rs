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
        "mini-elf-toolchain-static-pie-{label}-{}-{nonce}",
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

#[test]
fn emits_and_executes_bounded_static_pie_like_gnu_et_dyn() {
    if !have_gnu_tools() {
        return;
    }

    let dir = temp_dir("execute");
    let object = assemble(
        &dir,
        "pie",
        r#".section .rodata
.align 8
.globl pie_value
.type pie_value,@object
pie_value:
    .quad 0x1122334455667788
.size pie_value, .-pie_value

.section .text
.globl pie_helper
.type pie_helper,@function
pie_helper:
    ret
.size pie_helper, .-pie_helper

.globl _start
.type _start,@function
_start:
    call pie_helper
    lea pie_value(%rip), %rbx
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
"#,
    );

    let input_relocations = Command::new("readelf")
        .args(["-rW"])
        .arg(&object)
        .output()
        .unwrap();
    assert!(input_relocations.status.success());
    let relocations = String::from_utf8_lossy(&input_relocations.stdout);
    assert!(
        relocations.contains("R_X86_64_PLT32") || relocations.contains("R_X86_64_PC32"),
        "fixture must exercise a load-bias-invariant relocation: {relocations}"
    );
    assert!(
        relocations.contains("pie_value"),
        "fixture must carry the RIP-relative data relocation: {relocations}"
    );

    let ours = dir.join("ours-pie");
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

    let header = Command::new("readelf")
        .args(["-hW"])
        .arg(&ours)
        .output()
        .unwrap();
    assert!(header.status.success());
    let header = String::from_utf8_lossy(&header.stdout);
    assert!(header.contains("Type:                              DYN"));

    let program_headers = Command::new("readelf")
        .args(["-lW"])
        .arg(&ours)
        .output()
        .unwrap();
    assert!(program_headers.status.success());
    let program_headers = String::from_utf8_lossy(&program_headers.stdout);
    assert!(program_headers.contains("PHDR"));
    assert!(program_headers.contains("LOAD"));
    assert!(!program_headers.contains("INTERP"));
    assert!(!program_headers.contains("DYNAMIC"));

    let gnu = dir.join("gnu-pie");
    let gnu_link = Command::new("ld")
        .args(["-pie", "--no-dynamic-linker", "-Ttext=0", "-e", "_start", "-o"])
        .arg(&gnu)
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        gnu_link.status.success(),
        "{}",
        String::from_utf8_lossy(&gnu_link.stderr)
    );
    let gnu_header = Command::new("readelf")
        .args(["-hW"])
        .arg(&gnu)
        .output()
        .unwrap();
    assert!(gnu_header.status.success());
    assert!(String::from_utf8_lossy(&gnu_header.stdout)
        .contains("Type:                              DYN"));

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
fn static_pie_rejects_absolute_relocation_before_output() {
    if !command_reports("as", "GNU assembler") {
        return;
    }

    let dir = temp_dir("absolute");
    let object = assemble(
        &dir,
        "absolute",
        r#".section .data
.globl absolute_pointer
absolute_pointer:
    .quad absolute_target

.section .text
.globl absolute_target
absolute_target:
    ret

.globl _start
_start:
    mov $60, %rax
    xor %rdi, %rdi
    syscall
"#,
    );

    let relocations = Command::new("readelf")
        .args(["-rW"])
        .arg(&object)
        .output()
        .unwrap();
    assert!(relocations.status.success());
    assert!(String::from_utf8_lossy(&relocations.stdout).contains("R_X86_64_64"));

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
    assert!(stderr.contains("R_X86_64_64") || stderr.contains("relocation type 1"));
    assert!(stderr.contains("position-independent"));
    assert!(!output.exists());

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn pie_and_image_base_are_mutually_exclusive_before_input_io() {
    let dir = temp_dir("options");
    let output = dir.join("must-not-exist");

    let mini = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&output)
        .args(["--pie", "--image-base", "0x400000", "missing.o"])
        .output()
        .unwrap();

    assert!(!mini.status.success());
    assert!(mini.stdout.is_empty());
    assert!(String::from_utf8_lossy(&mini.stderr)
        .contains("--pie cannot be combined with --image-base"));
    assert!(!output.exists());

    let _ = fs::remove_dir_all(dir);
}
