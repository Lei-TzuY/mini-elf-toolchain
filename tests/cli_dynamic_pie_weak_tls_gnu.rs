use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy)]
enum Model {
    TlsGd,
    InitialExec,
    TlsDesc,
}

impl Model {
    fn label(self) -> &'static str {
        match self {
            Self::TlsGd => "tlsgd",
            Self::InitialExec => "initial-exec",
            Self::TlsDesc => "tlsdesc",
        }
    }

    fn source(self, execute_access: bool) -> String {
        let access = match self {
            Self::TlsGd => {
                r#"data16 leaq provider_tls@tlsgd(%rip), %rdi
    .value 0x6666
    rex64
    call __tls_get_addr@PLT
    mov (%rax), %edi"#
            }
            Self::InitialExec => {
                r#"mov provider_tls@gottpoff(%rip), %rax
    mov %fs:(%rax), %edi"#
            }
            Self::TlsDesc => {
                r#"leaq provider_tls@TLSDESC(%rip), %rax
    call *provider_tls@TLSCALL(%rax)
    mov %fs:(%rax), %edi"#
            }
        };
        let resolver = matches!(self, Self::TlsGd)
            .then_some(".extern __tls_get_addr\n.type __tls_get_addr,@function\n")
            .unwrap_or("");
        if execute_access {
            format!(
                r#".text
.globl _start
.type _start,@function
.weak provider_tls
.type provider_tls,@tls_object
{resolver}_start:
    {access}
    mov $60, %eax
    syscall
.size _start, .-_start

.section .note.GNU-stack,"",@progbits
"#
            )
        } else {
            format!(
                r#".text
.globl _start
.type _start,@function
.weak provider_tls
.type provider_tls,@tls_object
{resolver}_start:
    mov $60, %eax
    xor %edi, %edi
    syscall
.size _start, .-_start

.globl weak_tls_probe
.type weak_tls_probe,@function
weak_tls_probe:
    {access}
    ret
.size weak_tls_probe, .-weak_tls_probe

.section .note.GNU-stack,"",@progbits
"#
            )
        }
    }

    fn assert_relocation(self, text: &str) {
        match self {
            Self::TlsGd => assert!(
                text.contains("R_X86_64_DTPMOD64")
                    && text.contains("R_X86_64_DTPOFF64")
                    && text.contains("provider_tls"),
                "{text}"
            ),
            Self::InitialExec => assert!(
                text.contains("R_X86_64_TPOFF64") && text.contains("provider_tls"),
                "{text}"
            ),
            Self::TlsDesc => assert!(
                text.lines()
                    .any(|line| line.contains("R_X86_64_TLSDESC") && line.contains("provider_tls")),
                "{text}"
            ),
        }
    }
}

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
        "mini-elf-toolchain-dynamic-pie-weak-tls-{label}-{}-{nonce}",
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

fn build_provider(dir: &Path) -> PathBuf {
    let object = assemble(
        dir,
        "provider",
        r#".section .tdata,"awT",@progbits
.align 8
.globl provider_tls
.type provider_tls,@tls_object
provider_tls:
    .quad 42
.size provider_tls, .-provider_tls

.section .note.GNU-stack,"",@progbits
"#,
    );
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

fn link_weak(
    dir: &Path,
    model: Model,
    object: &Path,
    interpreter: &Path,
    provider: Option<&Path>,
    libc: Option<&Path>,
) -> PathBuf {
    let output = dir.join(format!("mini-weak-{}", model.label()));
    let mut command = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"));
    command
        .args(["link", "-o"])
        .arg(&output)
        .arg("--dynamic-pie")
        .arg("--dynamic-linker")
        .arg(interpreter);
    if let Some(provider) = provider {
        command.arg("--needed-from").arg(provider);
    }
    if let Some(libc) = libc {
        command.arg("--needed-from").arg(libc);
    }
    if provider.is_some() {
        command.args(["--runpath", "$ORIGIN"]);
    }
    let linked = command.arg(object).output().unwrap();
    assert!(
        linked.status.success(),
        "{}: {}",
        model.label(),
        String::from_utf8_lossy(&linked.stderr)
    );
    output
}

fn assert_weak_tls_symbol(path: &Path) {
    let symbols = readelf(path, &["-sDW"]);
    assert!(
        symbols.lines().any(|line| {
            line.contains(" WEAK ")
                && line.contains(" TLS ")
                && line.contains(" UND ")
                && line.ends_with(" provider_tls")
        }),
        "{symbols}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn weak_dynamic_pie_tls_binds_when_provider_is_present_across_all_models() {
    if !have_tools() {
        return;
    }
    let Some(interpreter) = dynamic_linker() else {
        return;
    };
    let Some(libc) = libc_path() else {
        return;
    };

    let dir = temp_dir("bound");
    let provider = build_provider(&dir);

    for model in [Model::TlsGd, Model::InitialExec, Model::TlsDesc] {
        let object = assemble(
            &dir,
            &format!("{}-bound", model.label()),
            &model.source(true),
        );
        let ours = link_weak(
            &dir,
            model,
            &object,
            &interpreter,
            Some(&provider),
            matches!(model, Model::TlsGd).then_some(libc.as_path()),
        );

        assert_weak_tls_symbol(&ours);
        model.assert_relocation(&readelf(&ours, &["-rW", "--use-dynamic"]));
        let dynamic = readelf(&ours, &["-dW"]);
        assert!(dynamic.contains("libprovider.so"), "{dynamic}");

        let status = Command::new(&ours).status().unwrap();
        assert_eq!(
            status.code(),
            Some(42),
            "{} weak provider-backed TLS should bind through glibc; status={status}",
            model.label()
        );
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
#[cfg(target_os = "linux")]
fn unresolved_weak_dynamic_pie_tls_remains_loadable_across_all_models() {
    if !have_tools() {
        return;
    }
    let Some(interpreter) = dynamic_linker() else {
        return;
    };
    let Some(libc) = libc_path() else {
        return;
    };

    let dir = temp_dir("absent");

    for model in [Model::TlsGd, Model::InitialExec, Model::TlsDesc] {
        let object = assemble(
            &dir,
            &format!("{}-absent", model.label()),
            &model.source(false),
        );
        let ours = link_weak(
            &dir,
            model,
            &object,
            &interpreter,
            None,
            matches!(model, Model::TlsGd).then_some(libc.as_path()),
        );

        assert_weak_tls_symbol(&ours);
        model.assert_relocation(&readelf(&ours, &["-rW", "--use-dynamic"]));
        let dynamic = readelf(&ours, &["-dW"]);
        assert!(!dynamic.contains("libprovider.so"), "{dynamic}");

        let status = Command::new(&ours).status().unwrap();
        assert_eq!(
            status.code(),
            Some(0),
            "{} unresolved weak TLS relocation must not prevent process startup; status={status}",
            model.label()
        );
    }

    let _ = fs::remove_dir_all(dir);
}


#[test]
#[cfg(target_os = "linux")]
fn versioned_weak_dynamic_pie_tls_remains_fail_closed() {
    if !have_tools() {
        return;
    }
    let Some(interpreter) = dynamic_linker() else {
        return;
    };

    let dir = temp_dir("versioned-boundary");
    let object = assemble(
        &dir,
        "versioned-weak",
        r#".text
.globl _start
.type _start,@function
.weak provider_tls
.type provider_tls,@tls_object
.symver provider_tls,provider_tls@VERS_1
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
    let input_symbols = readelf(&object, &["-sW"]);
    assert!(
        input_symbols.lines().any(|line| {
            line.contains(" WEAK ")
                && line.contains(" TLS ")
                && line.contains(" UND ")
                && line.ends_with(" provider_tls@VERS_1")
        }),
        "{input_symbols}"
    );

    let output = dir.join("must-not-exist-versioned-weak");
    let linked = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&output)
        .arg("--dynamic-pie")
        .arg("--dynamic-linker")
        .arg(&interpreter)
        .arg(&object)
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
