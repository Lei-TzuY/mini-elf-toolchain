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
        "mini-elf-toolchain-dynamic-pie-tlsgd-{label}-{}-{nonce}",
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

const PROVIDER_SOURCE: &str = r#".section .tdata,"awT",@progbits
.align 8
.globl provider_tls
.type provider_tls,@tls_object
provider_tls:
    .quad 42
.size provider_tls, .-provider_tls

.section .note.GNU-stack,"",@progbits
"#;

fn build_provider(dir: &Path) -> PathBuf {
    let object = assemble(dir, "provider", PROVIDER_SOURCE);
    let provider = dir.join("libprovider.so");
    let linked = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&provider)
        .args(["--shared", "--soname", "libprovider.so"])
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

fn build_gnu_provider(dir: &Path) -> PathBuf {
    let object = assemble(dir, "provider-gnu", PROVIDER_SOURCE);
    let provider = dir.join("libprovider-gnu.so");
    let linked = Command::new("ld")
        .args(["-shared", "-soname", "libprovider-gnu.so", "-o"])
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
fn dynamic_pie_tlsgd_import_binds_provider_tls_through_glibc() {
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
    let provider = build_provider(&dir);
    let gnu_provider = build_gnu_provider(&dir);

    let consumer = assemble(
        &dir,
        "consumer",
        r#".text
.globl _start
.type _start,@function
.extern provider_tls
.type provider_tls,@tls_object
.extern __tls_get_addr
.type __tls_get_addr,@function
_start:
    data16 leaq provider_tls@tlsgd(%rip), %rdi
    .value 0x6666
    rex64
    call __tls_get_addr@PLT
    mov (%rax), %edi
    mov $60, %eax
    syscall
.size _start, .-_start

.section .note.GNU-stack,"",@progbits
"#,
    );

    let input_relocations = readelf(&consumer, &["-rW"]);
    assert!(
        input_relocations.contains("R_X86_64_TLSGD")
            && input_relocations.contains("provider_tls")
            && input_relocations.contains("__tls_get_addr"),
        "{input_relocations}"
    );

    let ours = dir.join("mini-tlsgd-app");
    let linked = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&ours)
        .arg("--dynamic-pie")
        .arg("--dynamic-linker")
        .arg(&interpreter)
        .arg("--needed-from")
        .arg(&provider)
        .arg("--needed-from")
        .arg(&libc)
        .args(["--runpath", "$ORIGIN"])
        .arg(&consumer)
        .output()
        .unwrap();
    assert!(
        linked.status.success(),
        "{}",
        String::from_utf8_lossy(&linked.stderr)
    );

    let dynamic = readelf(&ours, &["-dW"]);
    assert!(
        dynamic.contains("NEEDED") && dynamic.contains("libprovider.so"),
        "{dynamic}"
    );
    assert!(
        dynamic.contains("libc.so.6"),
        "TLSGD resolver dependency must remain explicit:\n{dynamic}"
    );
    assert!(
        dynamic.contains("RUNPATH") && dynamic.contains("$ORIGIN"),
        "{dynamic}"
    );

    let symbols = readelf(&ours, &["-sDW"]);
    assert!(
        symbols.lines().any(|line| {
            line.contains(" TLS ") && line.contains(" UND ") && line.ends_with(" provider_tls")
        }),
        "{symbols}"
    );

    let relocations = readelf(&ours, &["-rW", "--use-dynamic"]);
    assert!(
        relocations.contains("R_X86_64_DTPMOD64")
            && relocations.contains("R_X86_64_DTPOFF64")
            && relocations.contains("provider_tls"),
        "{relocations}"
    );
    assert!(
        relocations.contains("R_X86_64_JUMP_SLOT") && relocations.contains("__tls_get_addr"),
        "{relocations}"
    );

    let status = Command::new(&ours).status().unwrap();
    assert_eq!(
        status.code(),
        Some(42),
        "{} should read provider TLS through the glibc TLSGD path; status={status}",
        ours.display()
    );

    let gnu_provider_symbols = readelf(&gnu_provider, &["-sDW"]);
    assert!(
        gnu_provider_symbols
            .lines()
            .any(|line| line.contains(" TLS ") && line.ends_with(" provider_tls")),
        "{gnu_provider_symbols}"
    );

    let gnu = dir.join("gnu-tlsgd-app");
    let gnu_link = Command::new("cc")
        .args(["-nostartfiles", "-fPIE", "-pie"])
        .arg("-Wl,--dynamic-linker")
        .arg(format!("-Wl,{}", interpreter.to_string_lossy()))
        .arg("-Wl,-rpath,$ORIGIN")
        .arg("-o")
        .arg(&gnu)
        .arg(&consumer)
        .arg("-L")
        .arg(&dir)
        .arg("-lprovider-gnu")
        .arg("-Wl,--no-as-needed")
        .arg("-lc")
        .output()
        .unwrap();
    assert!(
        gnu_link.status.success(),
        "{}",
        String::from_utf8_lossy(&gnu_link.stderr)
    );
    let gnu_dynamic = readelf(&gnu, &["-dW"]);
    assert!(
        gnu_dynamic.contains("libprovider-gnu.so") && gnu_dynamic.contains("libc.so.6"),
        "{gnu_dynamic}"
    );
    let gnu_relocations = readelf(&gnu, &["-rW", "--use-dynamic"]);
    assert!(
        gnu_relocations.contains("provider_tls")
            && (gnu_relocations.contains("R_X86_64_DTPMOD64")
                || gnu_relocations.contains("R_X86_64_TPOFF64")),
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

#[test]
#[cfg(target_os = "linux")]
fn dynamic_pie_rejects_unqualified_initial_exec_tls() {
    if !have_tools() {
        return;
    }
    let Some(interpreter) = dynamic_linker() else {
        return;
    };

    let dir = temp_dir("ie-rejected");
    let provider = build_provider(&dir);
    let consumer = assemble(
        &dir,
        "ie-consumer",
        r#".text
.globl _start
.type _start,@function
.extern provider_tls
.type provider_tls,@tls_object
_start:
    mov provider_tls@gottpoff(%rip), %rax
    mov %fs:(%rax), %edi
    mov $60, %eax
    syscall
.size _start, .-_start

.section .note.GNU-stack,"",@progbits
"#,
    );
    let input_relocations = readelf(&consumer, &["-rW"]);
    assert!(input_relocations.contains("R_X86_64_GOTTPOFF"));

    let output = dir.join("must-not-exist");
    let linked = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&output)
        .arg("--dynamic-pie")
        .arg("--dynamic-linker")
        .arg(&interpreter)
        .arg("--needed-from")
        .arg(&provider)
        .arg(&consumer)
        .output()
        .unwrap();
    assert!(!linked.status.success());
    assert!(linked.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&linked.stderr);
    assert!(
        stderr.contains("dynamic PIE") && stderr.contains("TLS"),
        "{stderr}"
    );
    assert!(!output.exists());

    let _ = fs::remove_dir_all(dir);
}


#[test]
#[cfg(target_os = "linux")]
fn dynamic_pie_rejects_weak_tlsgd_until_separately_qualified() {
    if !have_tools() {
        return;
    }
    let Some(interpreter) = dynamic_linker() else {
        return;
    };

    let dir = temp_dir("weak-tlsgd-rejected");
    let provider = build_provider(&dir);
    let consumer = assemble(
        &dir,
        "weak-tlsgd-consumer",
        r#".text
.globl _start
.type _start,@function
.weak provider_tls
.type provider_tls,@tls_object
.extern __tls_get_addr
.type __tls_get_addr,@function
_start:
    data16 leaq provider_tls@tlsgd(%rip), %rdi
    .value 0x6666
    rex64
    call __tls_get_addr@PLT
    mov $60, %eax
    xor %edi, %edi
    syscall
.size _start, .-_start

.section .note.GNU-stack,"",@progbits
"#,
    );
    let input_relocations = readelf(&consumer, &["-rW"]);
    assert!(
        input_relocations.contains("R_X86_64_TLSGD")
            && input_relocations.contains("provider_tls"),
        "{input_relocations}"
    );
    let input_symbols = readelf(&consumer, &["-sW"]);
    assert!(
        input_symbols.lines().any(|line| {
            line.contains("WEAK")
                && line.contains(" TLS ")
                && line.contains(" UND ")
                && line.ends_with(" provider_tls")
        }),
        "{input_symbols}"
    );

    let output = dir.join("must-not-exist-weak-tlsgd");
    let linked = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&output)
        .arg("--dynamic-pie")
        .arg("--dynamic-linker")
        .arg(&interpreter)
        .arg("--needed-from")
        .arg(&provider)
        .arg(&consumer)
        .output()
        .unwrap();
    assert!(!linked.status.success());
    assert!(linked.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&linked.stderr);
    assert!(
        stderr.contains("dynamic PIE") && stderr.contains("TLS"),
        "{stderr}"
    );
    assert!(!output.exists());

    let _ = fs::remove_dir_all(dir);
}

#[test]
#[cfg(target_os = "linux")]
fn dynamic_pie_rejects_tlsdesc_until_separately_qualified() {
    if !have_tools() {
        return;
    }
    let Some(interpreter) = dynamic_linker() else {
        return;
    };

    let dir = temp_dir("tlsdesc-rejected");
    let provider = build_provider(&dir);
    let consumer = assemble(
        &dir,
        "tlsdesc-consumer",
        r#".text
.globl _start
.type _start,@function
.extern provider_tls
.type provider_tls,@tls_object
_start:
    leaq provider_tls@TLSDESC(%rip), %rax
    call *provider_tls@TLSCALL(%rax)
    mov %fs:(%rax), %edi
    mov $60, %eax
    syscall
.size _start, .-_start

.section .note.GNU-stack,"",@progbits
"#,
    );
    let input_relocations = readelf(&consumer, &["-rW"]);
    assert!(
        input_relocations.contains("R_X86_64_GOTPC32_TLSDESC")
            && input_relocations.contains("R_X86_64_TLSDESC_CALL")
            && input_relocations.contains("provider_tls"),
        "{input_relocations}"
    );

    let output = dir.join("must-not-exist-tlsdesc");
    let linked = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&output)
        .arg("--dynamic-pie")
        .arg("--dynamic-linker")
        .arg(&interpreter)
        .arg("--needed-from")
        .arg(&provider)
        .arg(&consumer)
        .output()
        .unwrap();
    assert!(!linked.status.success());
    assert!(linked.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&linked.stderr);
    assert!(
        stderr.contains("dynamic PIE") && stderr.contains("TLS"),
        "{stderr}"
    );
    assert!(!output.exists());

    let _ = fs::remove_dir_all(dir);
}
