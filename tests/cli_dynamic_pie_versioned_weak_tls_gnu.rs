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

    fn access(self) -> &'static str {
        match self {
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
        }
    }

    fn source(self, execute_access: bool) -> String {
        let resolver = matches!(self, Self::TlsGd)
            .then_some(".extern __tls_get_addr\n.type __tls_get_addr,@function\n")
            .unwrap_or("");
        let access = self.access();
        if execute_access {
            format!(
                r#".text
.globl _start
.type _start,@function
.weak provider_tls
.type provider_tls,@tls_object
.symver provider_tls,provider_tls@VERS_1
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
.symver provider_tls,provider_tls@VERS_1
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
            Self::TlsGd => {
                assert!(
                    text.lines().any(|line| {
                        line.contains("R_X86_64_DTPMOD64")
                            && line.contains("provider_tls@VERS_1")
                    }),
                    "{text}"
                );
                assert!(
                    text.lines().any(|line| {
                        line.contains("R_X86_64_DTPOFF64")
                            && line.contains("provider_tls@VERS_1")
                    }),
                    "{text}"
                );
                assert!(
                    text.lines().any(|line| {
                        line.contains("R_X86_64_JUMP_SLOT")
                            && line.contains("__tls_get_addr")
                    }),
                    "{text}"
                );
            }
            Self::InitialExec => assert!(
                text.lines().any(|line| {
                    line.contains("R_X86_64_TPOFF64")
                        && line.contains("provider_tls@VERS_1")
                }),
                "{text}"
            ),
            Self::TlsDesc => {
                assert!(
                    text.lines().any(|line| {
                        line.contains("R_X86_64_TLSDESC")
                            && line.contains("provider_tls@VERS_1")
                    }),
                    "{text}"
                );
                assert!(
                    !text.contains("R_X86_64_DTPMOD64")
                        && !text.contains("R_X86_64_DTPOFF64")
                        && !text.contains("R_X86_64_TPOFF64"),
                    "TLSDESC must remain descriptor-based without TLSGD/IE substitution:\n{text}"
                );
            }
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
        "mini-elf-toolchain-dynamic-pie-versioned-weak-tls-{label}-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&path).unwrap();
    path
}

fn assemble(dir: &Path, stem: &str, source: &str) -> PathBuf {
    fs::create_dir_all(dir).unwrap();
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

fn versioned_provider(dir: &Path, version: &str, include_tls: bool) -> PathBuf {
    fs::create_dir_all(dir).unwrap();
    let source = if include_tls {
        r#".section .tdata,"awT",@progbits
.align 8
.globl provider_tls
.type provider_tls,@tls_object
provider_tls:
    .quad 42
.size provider_tls, .-provider_tls

.section .note.GNU-stack,"",@progbits
"#
    } else {
        r#".data
.globl provider_other
.type provider_other,@object
provider_other:
    .quad 1
.size provider_other, .-provider_other

.section .note.GNU-stack,"",@progbits
"#
    };
    let object = assemble(dir, "provider", source);
    let map = dir.join("provider.map");
    fs::write(
        &map,
        format!("{version} {{ global: provider_tls; provider_other; local: *; }};\n"),
    )
    .unwrap();
    let shared = dir.join("libprovider.so");
    let linked = Command::new("ld")
        .args(["-shared", "--hash-style=sysv", "--soname=libprovider.so"])
        .arg(format!("--version-script={}", map.display()))
        .args(["-o"])
        .arg(&shared)
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        linked.status.success(),
        "{}",
        String::from_utf8_lossy(&linked.stderr)
    );
    shared
}

fn link_versioned_weak(
    dir: &Path,
    model: Model,
    stem: &str,
    object: &Path,
    interpreter: &Path,
    provider: &Path,
    libc: Option<&Path>,
) -> PathBuf {
    fs::create_dir_all(dir).unwrap();
    let output = dir.join(format!("mini-{stem}-{}", model.label()));
    let mut command = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"));
    command
        .args(["link", "-o"])
        .arg(&output)
        .arg("--dynamic-pie")
        .arg("--dynamic-linker")
        .arg(interpreter)
        .arg("--needed-from")
        .arg(provider)
        .args(["--runpath", "$ORIGIN"]);
    if let Some(libc) = libc {
        command.arg("--needed-from").arg(libc);
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

fn assert_versioned_weak_metadata(path: &Path, model: Model) {
    let symbols = readelf(path, &["-sDW"]);
    assert!(
        symbols.lines().any(|line| {
            line.contains(" WEAK ")
                && line.contains(" TLS ")
                && line.contains(" UND ")
                && line.contains("provider_tls@VERS_1")
        }),
        "{symbols}"
    );

    model.assert_relocation(&readelf(path, &["-rW", "--use-dynamic"]));

    let dynamic = readelf(path, &["-dW"]);
    assert!(dynamic.contains("libprovider.so"), "{dynamic}");
    assert!(
        !dynamic.contains("STATIC_TLS"),
        "dynamic PIE must not inherit DSO-only DF_STATIC_TLS:\n{dynamic}"
    );

    let versions = readelf(path, &["-VW"]);
    let requirement = versions
        .lines()
        .find(|line| line.contains("Name: VERS_1"))
        .unwrap_or_else(|| panic!("missing VERS_1 requirement:\n{versions}"));
    assert!(
        requirement.contains("Flags: none"),
        "weak symbol binding must not weaken the version-node requirement: {requirement}"
    );

    let checked = Command::new(env!("CARGO_BIN_EXE_mini-elf-versym-needed"))
        .arg(path)
        .output()
        .unwrap();
    assert!(
        checked.status.success(),
        "{}",
        String::from_utf8_lossy(&checked.stderr)
    );
    let checked = String::from_utf8_lossy(&checked.stdout);
    assert!(
        checked.contains("requirement=libprovider.so:VERS_1"),
        "{checked}"
    );
}

fn run_with_provider(executable: &Path, provider_dir: &Path) -> std::process::ExitStatus {
    Command::new(executable)
        .env("LD_LIBRARY_PATH", provider_dir)
        .status()
        .unwrap()
}

#[test]
#[cfg(target_os = "linux")]
fn versioned_weak_dynamic_pie_tls_preserves_symbol_and_version_semantics_across_all_models() {
    if !have_tools() {
        return;
    }
    let Some(interpreter) = dynamic_linker() else {
        return;
    };
    let Some(libc) = libc_path() else {
        return;
    };

    let dir = temp_dir("all-models");
    let link_provider_dir = dir.join("link-provider");
    let missing_provider_dir = dir.join("missing-provider");
    let wrong_provider_dir = dir.join("wrong-provider");
    let link_provider = versioned_provider(&link_provider_dir, "VERS_1", true);
    let _missing_provider = versioned_provider(&missing_provider_dir, "VERS_1", false);
    let _wrong_provider = versioned_provider(&wrong_provider_dir, "VERS_2", false);

    for model in [Model::TlsGd, Model::InitialExec, Model::TlsDesc] {
        let bound_dir = dir.join(format!("{}-bound", model.label()));
        let bound_object = assemble(
            &bound_dir,
            "consumer",
            &model.source(true),
        );
        let bound = link_versioned_weak(
            &bound_dir,
            model,
            "bound",
            &bound_object,
            &interpreter,
            &link_provider,
            matches!(model, Model::TlsGd).then_some(libc.as_path()),
        );
        assert_versioned_weak_metadata(&bound, model);

        let bound_status = run_with_provider(&bound, &link_provider_dir);
        assert_eq!(
            bound_status.code(),
            Some(42),
            "{} versioned weak TLS should bind to the requested provider symbol; status={bound_status}",
            model.label()
        );

        let probe_dir = dir.join(format!("{}-probe", model.label()));
        let probe_object = assemble(
            &probe_dir,
            "consumer",
            &model.source(false),
        );
        let probe = link_versioned_weak(
            &probe_dir,
            model,
            "probe",
            &probe_object,
            &interpreter,
            &link_provider,
            matches!(model, Model::TlsGd).then_some(libc.as_path()),
        );
        assert_versioned_weak_metadata(&probe, model);

        let missing_status = run_with_provider(&probe, &missing_provider_dir);
        assert_eq!(
            missing_status.code(),
            Some(0),
            "{} same-version provider may omit the weak TLS symbol; status={missing_status}",
            model.label()
        );

        let wrong_status = run_with_provider(&probe, &wrong_provider_dir);
        assert!(
            !wrong_status.success(),
            "{} missing VERS_1 node must fail loader version checking",
            model.label()
        );
    }

    let _ = fs::remove_dir_all(dir);
}
