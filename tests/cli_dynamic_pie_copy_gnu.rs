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
        "mini-elf-toolchain-dynamic-pie-copy-{label}-{}-{nonce}",
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

fn provider(dir: &Path, with_size: bool) -> PathBuf {
    let size = if with_size {
        ".size provider_value, .-provider_value\n"
    } else {
        ""
    };
    let object = assemble(
        dir,
        "provider",
        &format!(
            r#".data
.globl provider_value
.type provider_value,@object
provider_value:
    .quad 42
{size}
.section .note.GNU-stack,"",@progbits
"#
        ),
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

fn consumer(dir: &Path) -> PathBuf {
    assemble(
        dir,
        "consumer",
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

.section .note.GNU-stack,"",@progbits
"#,
    )
}

#[test]
#[cfg(target_os = "linux")]
fn dynamic_pie_executes_direct_provider_copy_relocation() {
    if !have_gnu_tools() {
        return;
    }
    let Some(interpreter) = dynamic_linker() else {
        return;
    };

    let dir = temp_dir("runtime");
    let provider = provider(&dir, true);
    let consumer = consumer(&dir);
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
        relocations.contains("R_X86_64_COPY") && relocations.contains("provider_value"),
        "{relocations}"
    );
    assert!(
        !relocations.contains("R_X86_64_PC32"),
        "the input PC32 reference must be resolved to executable-owned copy storage:\n{relocations}"
    );

    let symbols = readelf(&ours, &["-sDW"]);
    let copy_symbol = symbols
        .lines()
        .find(|line| line.contains("provider_value"))
        .expect("copy destination dynamic symbol");
    assert!(copy_symbol.contains("OBJECT"), "{copy_symbol}");
    assert!(copy_symbol.contains("GLOBAL"), "{copy_symbol}");
    assert!(
        !copy_symbol.contains(" UND "),
        "copy destination must be a defined executable symbol: {copy_symbol}"
    );
    assert!(
        copy_symbol.split_whitespace().any(|field| field == "8"),
        "provider size must become copy destination st_size: {copy_symbol}"
    );

    let checked = Command::new(env!("CARGO_BIN_EXE_mini-elf-dynrela-copy"))
        .arg(&ours)
        .output()
        .unwrap();
    assert!(
        checked.status.success(),
        "{}",
        String::from_utf8_lossy(&checked.stderr)
    );
    assert!(
        String::from_utf8_lossy(&checked.stdout).contains("Validated R_X86_64_COPY"),
        "{}",
        String::from_utf8_lossy(&checked.stdout)
    );

    let status = Command::new(&ours).status().unwrap();
    assert_eq!(
        status.code(),
        Some(42),
        "{} should execute after glibc initializes the copy destination; status={status}",
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
        gnu_relocations.contains("R_X86_64_COPY") && gnu_relocations.contains("provider_value"),
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
fn copy_relocation_requires_checked_provider_size_metadata() {
    if !have_gnu_tools() {
        return;
    }
    let Some(interpreter) = dynamic_linker() else {
        return;
    };

    let dir = temp_dir("zero-size");
    let provider = provider(&dir, false);
    let consumer = consumer(&dir);
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
        String::from_utf8_lossy(&linked.stderr).contains("nonzero provider size"),
        "{}",
        String::from_utf8_lossy(&linked.stderr)
    );
    assert!(
        !output.exists(),
        "invalid copy-relocation provider metadata must fail before output"
    );

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn copy_relocation_rejects_name_only_dependency_without_provider_metadata() {
    if !have_gnu_tools() {
        return;
    }
    let Some(interpreter) = dynamic_linker() else {
        return;
    };

    let dir = temp_dir("name-only");
    let consumer = consumer(&dir);
    let output = dir.join("mini-app");

    let linked = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&output)
        .arg("--dynamic-pie")
        .arg("--dynamic-linker")
        .arg(&interpreter)
        .arg("--needed")
        .arg("libprovider.so")
        .arg(&consumer)
        .output()
        .unwrap();
    assert!(!linked.status.success());
    assert!(
        String::from_utf8_lossy(&linked.stderr).contains("checked direct provider"),
        "{}",
        String::from_utf8_lossy(&linked.stderr)
    );
    assert!(!output.exists());

    let _ = fs::remove_dir_all(dir);
}
