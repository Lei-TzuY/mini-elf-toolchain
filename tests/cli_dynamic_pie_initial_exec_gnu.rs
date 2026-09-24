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

fn temp_dir(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after Unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "mini-elf-toolchain-dynamic-pie-ie-{label}-{}-{nonce}",
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

fn build_mini_provider(dir: &Path) -> PathBuf {
    let object = assemble(dir, "provider-mini", PROVIDER_SOURCE);
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

fn initial_exec_consumer_source(binding: &str, define_locally: bool) -> String {
    let declaration = if define_locally {
        r#".section .tdata,"awT",@progbits
.align 8
.globl provider_tls
.type provider_tls,@tls_object
provider_tls:
    .quad 42
.size provider_tls, .-provider_tls
"#
        .to_owned()
    } else {
        format!(".section .text\n{binding} provider_tls\n.type provider_tls,@tls_object\n")
    };
    format!(
        r#"{declaration}
.section .text
.globl _start
.type _start,@function
_start:
    mov provider_tls@gottpoff(%rip), %rax
    mov %fs:(%rax), %edi
    mov $60, %eax
    syscall
.size _start, .-_start

.section .note.GNU-stack,"",@progbits
"#
    )
}

#[test]
#[cfg(target_os = "linux")]
fn dynamic_pie_initial_exec_import_matches_gnu_and_executes() {
    if !have_tools() {
        return;
    }
    let Some(interpreter) = dynamic_linker() else {
        return;
    };

    let dir = temp_dir("runtime");
    let provider = build_mini_provider(&dir);
    build_gnu_provider(&dir);
    let consumer = assemble(
        &dir,
        "consumer",
        &initial_exec_consumer_source(".extern", false),
    );

    let input_relocations = readelf(&consumer, &["-rW"]);
    assert!(
        input_relocations.contains("R_X86_64_GOTTPOFF")
            && input_relocations.contains("provider_tls"),
        "{input_relocations}"
    );

    let ours = dir.join("mini-ie-app");
    let linked = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&ours)
        .arg("--dynamic-pie")
        .arg("--dynamic-linker")
        .arg(&interpreter)
        .arg("--needed-from")
        .arg(&provider)
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
        dynamic.contains("RUNPATH") && dynamic.contains("$ORIGIN"),
        "{dynamic}"
    );
    assert!(
        !dynamic.contains("STATIC_TLS"),
        "dynamic PIE must match GNU executable policy and not inherit DSO-only DF_STATIC_TLS:\n{dynamic}"
    );

    let symbols = readelf(&ours, &["-sDW"]);
    assert!(
        symbols.lines().any(|line| {
            line.contains(" GLOBAL ")
                && line.contains(" TLS ")
                && line.contains(" UND ")
                && line.ends_with(" provider_tls")
        }),
        "{symbols}"
    );

    let relocations = readelf(&ours, &["-rW", "--use-dynamic"]);
    assert!(
        relocations.contains("R_X86_64_TPOFF64") && relocations.contains("provider_tls"),
        "{relocations}"
    );
    assert!(
        !relocations.contains("R_X86_64_DTPMOD64")
            && !relocations.contains("R_X86_64_DTPOFF64")
            && !relocations.contains("R_X86_64_TLSDESC"),
        "initial-exec must stay on the TPOFF64 slot plane:\n{relocations}"
    );

    let status = Command::new(&ours).status().unwrap();
    assert_eq!(
        status.code(),
        Some(42),
        "{} should read provider TLS through glibc initial-exec binding; status={status}",
        ours.display()
    );

    let gnu = dir.join("gnu-ie-app");
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
        .output()
        .unwrap();
    assert!(
        gnu_link.status.success(),
        "{}",
        String::from_utf8_lossy(&gnu_link.stderr)
    );
    let gnu_dynamic = readelf(&gnu, &["-dW"]);
    assert!(
        gnu_dynamic.contains("libprovider-gnu.so") && !gnu_dynamic.contains("STATIC_TLS"),
        "{gnu_dynamic}"
    );
    let gnu_relocations = readelf(&gnu, &["-rW", "--use-dynamic"]);
    assert!(
        gnu_relocations.contains("R_X86_64_TPOFF64") && gnu_relocations.contains("provider_tls"),
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
fn dynamic_pie_initial_exec_keeps_defined_tls_fail_closed() {
    if !have_tools() {
        return;
    }
    let Some(interpreter) = dynamic_linker() else {
        return;
    };

    let dir = temp_dir("defined-boundary");
    let consumer = assemble(
        &dir,
        "defined",
        &initial_exec_consumer_source("", true),
    );
    let input_relocations = readelf(&consumer, &["-rW"]);
    assert!(
        input_relocations.contains("R_X86_64_GOTTPOFF"),
        "{input_relocations}"
    );

    let output = dir.join("must-not-exist-defined");
    let linked = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&output)
        .arg("--dynamic-pie")
        .arg("--dynamic-linker")
        .arg(&interpreter)
        .arg(&consumer)
        .output()
        .unwrap();
    assert!(!linked.status.success(), "defined TLS unexpectedly linked");
    assert!(linked.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&linked.stderr);
    assert!(
        stderr.contains("dynamic PIE") && stderr.contains("TLS"),
        "{stderr}"
    );
    assert!(!output.exists());

    let _ = fs::remove_dir_all(dir);
}
