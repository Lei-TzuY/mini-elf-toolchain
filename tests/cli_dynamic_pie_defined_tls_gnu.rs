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
        "mini-elf-toolchain-dynamic-pie-defined-tls-{label}-{}-{nonce}",
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

fn source_for(model: &str) -> String {
    let access = match model {
        "tlsgd" => {
            r#"
.extern __tls_get_addr
.type __tls_get_addr,@function
    data16 leaq local_tls@tlsgd(%rip), %rdi
    .value 0x6666
    rex64
    call __tls_get_addr@PLT
    mov (%rax), %edi
"#
        }
        "ie" => {
            r#"
    mov local_tls@gottpoff(%rip), %rax
    mov %fs:(%rax), %edi
"#
        }
        "tlsdesc" => {
            r#"
    leaq local_tls@TLSDESC(%rip), %rax
    call *local_tls@TLSCALL(%rax)
    mov %fs:(%rax), %edi
"#
        }
        other => panic!("unknown TLS model {other}"),
    };
    format!(
        r#".section .tdata,"awT",@progbits
.align 8
.globl local_tls
.type local_tls,@tls_object
local_tls:
    .quad 42
.size local_tls, .-local_tls

.section .text
.globl _start
.type _start,@function
_start:
{access}
    mov $60, %eax
    syscall
.size _start, .-_start

.section .note.GNU-stack,"",@progbits
"#
    )
}

fn link_mini(
    dir: &Path,
    model: &str,
    object: &Path,
    interpreter: &Path,
    libc: Option<&Path>,
) -> PathBuf {
    let output = dir.join(format!("mini-{model}"));
    let mut command = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"));
    command
        .args(["link", "-o"])
        .arg(&output)
        .arg("--dynamic-pie")
        .arg("--dynamic-linker")
        .arg(interpreter);
    if let Some(libc) = libc {
        command.arg("--needed-from").arg(libc);
    }
    let linked = command.arg(object).output().unwrap();
    assert!(
        linked.status.success(),
        "{}",
        String::from_utf8_lossy(&linked.stderr)
    );
    output
}

fn link_gnu(dir: &Path, model: &str, object: &Path, interpreter: &Path, libc: &Path) -> PathBuf {
    let output = dir.join(format!("gnu-{model}"));
    let mut command = Command::new("ld");
    command
        .arg("-pie")
        .arg("--dynamic-linker")
        .arg(interpreter)
        .arg("-o")
        .arg(&output)
        .arg(object)
        .arg(interpreter)
        .arg(libc);
    let linked = command.output().unwrap();
    assert!(
        linked.status.success(),
        "{}",
        String::from_utf8_lossy(&linked.stderr)
    );
    output
}

#[test]
#[cfg(target_os = "linux")]
fn dynamic_pie_defined_tls_executes_across_gd_ie_and_tlsdesc() {
    if !have_tools() {
        return;
    }
    let Some(interpreter) = dynamic_linker() else {
        return;
    };
    let Some(libc) = libc_path() else {
        return;
    };

    let dir = temp_dir("models");
    for model in ["tlsgd", "ie", "tlsdesc"] {
        let object = assemble(&dir, model, &source_for(model));
        let input_relocations = readelf(&object, &["-rW"]);
        match model {
            "tlsgd" => assert!(input_relocations.contains("R_X86_64_TLSGD")),
            "ie" => assert!(input_relocations.contains("R_X86_64_GOTTPOFF")),
            "tlsdesc" => {
                assert!(input_relocations.contains("R_X86_64_GOTPC32_TLSDESC"));
                assert!(input_relocations.contains("R_X86_64_TLSDESC_CALL"));
            }
            _ => unreachable!(),
        }

        let ours = link_mini(
            &dir,
            model,
            &object,
            &interpreter,
            (model == "tlsgd").then_some(libc.as_path()),
        );

        let headers = readelf(&ours, &["-lW"]);
        assert!(
            headers.contains("TLS"),
            "{model}: missing PT_TLS\n{headers}"
        );

        let symbols = readelf(&ours, &["-sDW"]);
        assert!(
            symbols.lines().any(|line| {
                line.contains(" GLOBAL ")
                    && line.contains(" TLS ")
                    && !line.contains(" UND ")
                    && line.ends_with(" local_tls")
            }),
            "{model}: defined TLS symbol missing from dynsym\n{symbols}"
        );

        let relocations = readelf(&ours, &["-rW", "--use-dynamic"]);
        match model {
            "tlsgd" => {
                assert!(
                    relocations.contains("R_X86_64_DTPMOD64")
                        && relocations.contains("R_X86_64_DTPOFF64")
                        && relocations.contains("local_tls"),
                    "{relocations}"
                );
                assert!(
                    relocations.contains("R_X86_64_JUMP_SLOT")
                        && relocations.contains("__tls_get_addr"),
                    "{relocations}"
                );
            }
            "ie" => assert!(
                relocations.contains("R_X86_64_TPOFF64") && relocations.contains("local_tls"),
                "{relocations}"
            ),
            "tlsdesc" => assert!(
                relocations
                    .lines()
                    .any(|line| line.contains("R_X86_64_TLSDESC") && line.contains("local_tls")),
                "{relocations}"
            ),
            _ => unreachable!(),
        }

        let status = Command::new(&ours).status().unwrap();
        assert_eq!(
            status.code(),
            Some(42),
            "mini {model} executable should read its own TLS definition; status={status}"
        );

        let gnu = link_gnu(&dir, model, &object, &interpreter, &libc);
        let gnu_headers = readelf(&gnu, &["-lW"]);
        assert!(
            gnu_headers.contains("TLS"),
            "GNU {model} reference missing PT_TLS\n{gnu_headers}"
        );
        let gnu_status = Command::new(&gnu).status().unwrap();
        assert_eq!(
            gnu_status.code(),
            Some(42),
            "GNU {model} reference status={gnu_status}"
        );
    }

    let _ = fs::remove_dir_all(dir);
}
