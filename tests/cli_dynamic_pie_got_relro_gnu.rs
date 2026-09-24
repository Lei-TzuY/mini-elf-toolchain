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
        "mini-elf-toolchain-dynamic-pie-got-relro-{label}-{}-{nonce}",
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
        r#".text
.globl provider_func
.type provider_func,@function
provider_func:
    mov $7, %eax
    ret
.size provider_func, .-provider_func

.data
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

fn consumer_source(write_got: bool) -> String {
    let probe = if write_got {
        r#"
    # The LEA form computes the address of the ordinary GOT slot itself.
    # After loader relocation and RELRO sealing, this write must fault.
    lea provider_value@GOTPCREL(%rip), %rax
    movq $0, (%rax)

    mov $60, %eax
    mov $99, %edi
    syscall
"#
    } else {
        r#"
    mov $60, %eax
    xor %edi, %edi
    syscall
"#
    };
    format!(
        r#".text
.globl provider_value
.type provider_value,@object
.globl provider_func
.type provider_func,@function

.globl _start
.type _start,@function
_start:
    # Keep the ordinary data import on the pure GOT/GLOB_DAT plane.
    lea provider_value@GOTPCREL(%rip), %r12
    mov (%r12), %rbx
    cmpq $42, (%rbx)
    jne .Lfail

    # Two calls prove lazy GOTPLT remains writable and the first binding sticks.
    call provider_func@PLT
    cmp $7, %eax
    jne .Lfail
    call provider_func@PLT
    cmp $7, %eax
    jne .Lfail

{probe}
.Lfail:
    mov $60, %eax
    mov $77, %edi
    syscall
.size _start, .-_start

.section .note.GNU-stack,"",@progbits
"#
    )
}

fn link_mini(
    dir: &Path,
    name: &str,
    object: &Path,
    provider: &Path,
    interpreter: &Path,
) -> PathBuf {
    let output = dir.join(name);
    let linked = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&output)
        .arg("--dynamic-pie")
        .arg("--dynamic-linker")
        .arg(interpreter)
        .arg("--needed-from")
        .arg(provider)
        .arg("--runpath")
        .arg("$ORIGIN")
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

fn link_gnu(dir: &Path, name: &str, object: &Path, interpreter: &Path) -> PathBuf {
    let output = dir.join(name);
    let linked = Command::new("ld")
        .arg("-pie")
        .arg("--dynamic-linker")
        .arg(interpreter)
        .args(["-z", "relro", "-z", "lazy", "-rpath", "$ORIGIN", "-o"])
        .arg(&output)
        .arg(object)
        .arg("-L")
        .arg(dir)
        .arg("-lprovider")
        .output()
        .unwrap();
    assert!(
        linked.status.success(),
        "{}",
        String::from_utf8_lossy(&linked.stderr)
    );
    output
}

fn assert_partial_relro_metadata(path: &Path) {
    let relocations = readelf(path, &["-rW", "--use-dynamic"]);
    assert!(
        relocations
            .lines()
            .any(|line| line.contains("R_X86_64_GLOB_DAT") && line.contains("provider_value")),
        "ordinary data GOT slot must remain loader-bound:\n{relocations}"
    );
    assert!(
        relocations
            .lines()
            .any(|line| line.contains("R_X86_64_JUMP_SLOT") && line.contains("provider_func")),
        "lazy PLT binding must remain on JUMP_SLOT:\n{relocations}"
    );
    assert!(
        !relocations.contains("R_X86_64_COPY"),
        "pure GOT data binding must not synthesize a COPY relocation:\n{relocations}"
    );

    let headers = readelf(path, &["-lW"]);
    assert!(headers.contains("GNU_RELRO"), "{headers}");

    let dynamic = readelf(path, &["-dW"]);
    assert!(
        !dynamic.contains("BIND_NOW"),
        "bounded partial RELRO must not force eager PLT binding:\n{dynamic}"
    );
    assert!(
        !dynamic
            .lines()
            .any(|line| line.contains("FLAGS_1") && line.contains(" NOW ")),
        "bounded partial RELRO must not set DF_1_NOW:\n{dynamic}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn dynamic_pie_relro_keeps_lazy_plt_live_and_seals_ordinary_got() {
    if !have_gnu_tools() {
        return;
    }
    let Some(interpreter) = dynamic_linker() else {
        return;
    };

    let dir = temp_dir("runtime");
    let provider = provider(&dir);
    let control_object = assemble(&dir, "control", &consumer_source(false));
    let probe_object = assemble(&dir, "probe", &consumer_source(true));

    let mini_control = link_mini(
        &dir,
        "mini-control",
        &control_object,
        &provider,
        &interpreter,
    );
    let mini_probe = link_mini(&dir, "mini-probe", &probe_object, &provider, &interpreter);
    assert_partial_relro_metadata(&mini_control);
    assert_partial_relro_metadata(&mini_probe);

    let control_status = Command::new(&mini_control).status().unwrap();
    assert_eq!(
        control_status.code(),
        Some(0),
        "{} must complete two lazy PLT calls before exit; status={control_status}",
        mini_control.display()
    );

    use std::os::unix::process::ExitStatusExt;
    let probe_status = Command::new(&mini_probe).status().unwrap();
    assert_eq!(
        probe_status.signal(),
        Some(11),
        "{} must fault only when user code writes the loader-sealed ordinary GOT; status={probe_status}",
        mini_probe.display()
    );

    let gnu_control = link_gnu(&dir, "gnu-control", &control_object, &interpreter);
    let gnu_probe = link_gnu(&dir, "gnu-probe", &probe_object, &interpreter);
    assert_partial_relro_metadata(&gnu_control);
    assert_partial_relro_metadata(&gnu_probe);

    let gnu_control_status = Command::new(&gnu_control).status().unwrap();
    assert_eq!(gnu_control_status.code(), Some(0), "{gnu_control_status}");

    let gnu_probe_status = Command::new(&gnu_probe).status().unwrap();
    assert_eq!(
        gnu_probe_status.signal(),
        Some(11),
        "GNU partial RELRO reference must fault on the same ordinary GOT write; status={gnu_probe_status}"
    );

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn dynamic_pie_without_ordinary_got_uses_metadata_relro_slice() {
    if !have_gnu_tools() {
        return;
    }
    let Some(interpreter) = dynamic_linker() else {
        return;
    };

    let dir = temp_dir("absent");
    let provider = provider(&dir);
    let object = assemble(
        &dir,
        "plt-only",
        r#".text
.globl provider_func
.type provider_func,@function
.globl _start
.type _start,@function
_start:
    call provider_func@PLT
    cmp $7, %eax
    jne .Lfail
    mov $60, %eax
    xor %edi, %edi
    syscall
.Lfail:
    mov $60, %eax
    mov $77, %edi
    syscall
.size _start, .-_start

.section .note.GNU-stack,"",@progbits
"#,
    );
    let ours = link_mini(&dir, "mini-plt-only", &object, &provider, &interpreter);
    let headers = readelf(&ours, &["-lW"]);
    assert!(
        headers.contains("GNU_RELRO"),
        "dynamic PIE without loader-bound GOT state should protect its loader metadata:\n{headers}"
    );

    let _ = fs::remove_dir_all(dir);
}
