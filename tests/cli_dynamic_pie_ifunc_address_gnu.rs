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
        "mini-elf-toolchain-dynamic-pie-ifunc-address-{label}-{}-{nonce}",
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

#[test]
#[cfg(target_os = "linux")]
fn dynamic_pie_binds_explicit_ifunc_through_got_and_writable_pointer() {
    if !have_gnu_tools() {
        return;
    }
    let Some(interpreter) = dynamic_linker() else {
        return;
    };

    let dir = temp_dir("bind");
    let provider_object = assemble(
        &dir,
        "provider",
        r#".text
.type provider_impl,@function
provider_impl:
    mov $42, %eax
    ret
.size provider_impl, .-provider_impl

.type provider_resolver,@function
provider_resolver:
    lea provider_impl(%rip), %rax
    ret
.size provider_resolver, .-provider_resolver

.globl provider_value
.type provider_value,@gnu_indirect_function
.set provider_value,provider_resolver

.section .note.GNU-stack,"",@progbits
"#,
    );
    let provider = dir.join("libprovider.so");
    let provider_link = Command::new("ld")
        .args(["-shared", "-soname", "libprovider.so", "-o"])
        .arg(&provider)
        .arg(&provider_object)
        .output()
        .unwrap();
    assert!(
        provider_link.status.success(),
        "{}",
        String::from_utf8_lossy(&provider_link.stderr)
    );

    let provider_symbols = readelf(&provider, &["-sW"]);
    assert!(
        provider_symbols
            .lines()
            .any(|line| line.contains("IFUNC") && line.contains("provider_value")),
        "provider must export STT_GNU_IFUNC:\n{provider_symbols}"
    );

    let consumer = assemble(
        &dir,
        "consumer",
        r#".globl provider_value
.type provider_value,@gnu_indirect_function

.section .data
.align 8
provider_pointer:
    .quad provider_value

.section .text
.globl _start
.type _start,@function
_start:
    mov provider_value@GOTPCREL(%rip), %rax
    mov provider_pointer(%rip), %rbx
    cmp %rbx, %rax
    jne .Lfail
    call *%rax
    cmp $42, %eax
    jne .Lfail
    mov $60, %eax
    mov $42, %edi
    syscall
.Lfail:
    mov $60, %eax
    mov $1, %edi
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

    let symbols = readelf(&ours, &["-sW"]);
    assert!(
        symbols.lines().any(|line| {
            line.contains("IFUNC") && line.contains("UND") && line.contains("provider_value")
        }),
        "dynamic PIE must preserve explicit undefined IFUNC identity:\n{symbols}"
    );

    let relocations = readelf(&ours, &["-rW", "--use-dynamic"]);
    assert!(
        relocations
            .lines()
            .any(|line| line.contains("R_X86_64_GLOB_DAT") && line.contains("provider_value")),
        "expected GOT/GLOB_DAT IFUNC binding:\n{relocations}"
    );
    assert!(
        relocations
            .lines()
            .any(|line| { line.contains("R_X86_64_64") && line.contains("provider_value") }),
        "expected writable function-pointer IFUNC binding:\n{relocations}"
    );

    let status = Command::new(&ours).status().unwrap();
    assert_eq!(
        status.code(),
        Some(42),
        "{} should observe one resolver-selected implementation address through both loader planes; status={status}",
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
        gnu_relocations.contains("provider_value"),
        "{gnu_relocations}"
    );
    let gnu_status = Command::new(&gnu).status().unwrap();
    assert_eq!(
        gnu_status.code(),
        Some(42),
        "GNU reference status={gnu_status}"
    );

    let _ = fs::remove_dir_all(dir);
}
