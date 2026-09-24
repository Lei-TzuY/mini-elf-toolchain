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
        "mini-elf-toolchain-dynamic-pie-copy-got-{label}-{}-{nonce}",
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
        r#".data
.globl provider_value
.type provider_value,@object
provider_value:
    .quad 42
.size provider_value, .-provider_value

.section .note.GNU-stack,"",@progbits
"#,
    );
    let provider = dir.join("libprovider.so");
    let linked = Command::new("ld")
        .args(["-shared", "-soname", "libprovider.so", "-o"])
        .arg(&provider)
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        linked.status.success(),
        "{}",
        String::from_utf8_lossy(&linked.stderr)
    );
    provider
}

#[test]
#[cfg(target_os = "linux")]
fn dynamic_pie_copy_and_got_share_executable_copy_symbol() {
    if !have_gnu_tools() {
        return;
    }
    let Some(interpreter) = dynamic_linker() else {
        return;
    };

    let dir = temp_dir("runtime");
    let provider = provider(&dir);
    let consumer = assemble(
        &dir,
        "consumer",
        r#".text
.globl provider_value
.type provider_value,@object

.globl _start
.type _start,@function
_start:
    mov provider_value(%rip), %edi

    # LEA forces plain R_X86_64_GOTPCREL rather than a relaxable GOTPCRELX form.
    lea provider_value@GOTPCREL(%rip), %rax
    mov (%rax), %rax
    lea provider_value(%rip), %rbx
    cmp %rbx, %rax
    jne .Lfail
    mov (%rax), %esi
    cmp %edi, %esi
    jne .Lfail

    mov $60, %eax
    syscall
.Lfail:
    mov $60, %eax
    mov $99, %edi
    syscall
.size _start, .-_start

.section .note.GNU-stack,"",@progbits
"#,
    );
    let ours = dir.join("mini-app");

    let linked = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&ours)
        .arg("--dynamic-pie")
        .arg("--dynamic-linker")
        .arg(&interpreter)
        .arg("--needed-from")
        .arg(&provider)
        .arg("--runpath")
        .arg("$ORIGIN")
        .arg(&consumer)
        .output()
        .unwrap();
    assert!(
        linked.status.success(),
        "{}",
        String::from_utf8_lossy(&linked.stderr)
    );

    let relocations = readelf(&ours, &["-rW", "--use-dynamic"]);
    assert!(
        relocations.contains("R_X86_64_COPY") && relocations.contains("R_X86_64_GLOB_DAT"),
        "mixed executable data binding must expose COPY + GLOB_DAT:\n{relocations}"
    );
    assert_eq!(
        relocations.matches("provider_value").count(),
        2,
        "COPY and GLOB_DAT should be the only loader relocations for provider_value:\n{relocations}"
    );

    let symbols = readelf(&ours, &["-sDW"]);
    let provider_symbols = symbols
        .lines()
        .filter(|line| line.contains("provider_value"))
        .collect::<Vec<_>>();
    assert_eq!(
        provider_symbols.len(),
        1,
        "copy-backed GOT binding must reuse one executable-defined dynsym entry:\n{symbols}"
    );
    let copy_symbol = provider_symbols[0];
    assert!(copy_symbol.contains("OBJECT"), "{copy_symbol}");
    assert!(copy_symbol.contains("GLOBAL"), "{copy_symbol}");
    assert!(
        !copy_symbol.contains(" UND "),
        "GLOB_DAT must bind through the executable-defined COPY symbol: {copy_symbol}"
    );

    let status = Command::new(&ours).status().unwrap();
    assert_eq!(
        status.code(),
        Some(42),
        "{} should observe the same initialized object through direct and GOT paths; status={status}",
        ours.display()
    );

    let gnu = dir.join("gnu-app");
    let gnu_link = Command::new("ld")
        .arg("-pie")
        .arg("--dynamic-linker")
        .arg(&interpreter)
        .args(["-rpath", "$ORIGIN", "-o"])
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
    let gnu_relocations = readelf(&gnu, &["-rW", "--use-dynamic"]);
    assert!(
        gnu_relocations.contains("R_X86_64_COPY") && gnu_relocations.contains("R_X86_64_GLOB_DAT"),
        "GNU reference must expose COPY + GLOB_DAT:\n{gnu_relocations}"
    );
    let gnu_status = Command::new(&gnu).status().unwrap();
    assert_eq!(
        gnu_status.code(),
        Some(42),
        "GNU reference status={gnu_status}"
    );

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn copy_relocation_still_rejects_non_got_mixed_loader_binding() {
    if !have_gnu_tools() {
        return;
    }
    let Some(interpreter) = dynamic_linker() else {
        return;
    };

    let dir = temp_dir("reject");
    let provider = provider(&dir);
    let consumer = assemble(
        &dir,
        "mixed",
        r#".text
.globl provider_value
.type provider_value,@object

.globl _start
.type _start,@function
_start:
    mov provider_value(%rip), %edi
    mov $60, %eax
    syscall
.size _start, .-_start

.data
.align 8
provider_pointer:
    .quad provider_value

.section .note.GNU-stack,"",@progbits
"#,
    );
    let output = dir.join("mini-app");

    let linked = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&output)
        .arg("--dynamic-pie")
        .arg("--dynamic-linker")
        .arg(&interpreter)
        .arg("--needed-from")
        .arg(&provider)
        .arg("--runpath")
        .arg("$ORIGIN")
        .arg(&consumer)
        .output()
        .unwrap();

    assert!(!linked.status.success());
    assert!(
        String::from_utf8_lossy(&linked.stderr)
            .contains("unsupported loader-binding reference plane"),
        "{}",
        String::from_utf8_lossy(&linked.stderr)
    );
    assert!(
        !output.exists(),
        "unsupported COPY + absolute-pointer mixing must fail before output"
    );

    let _ = fs::remove_dir_all(dir);
}
