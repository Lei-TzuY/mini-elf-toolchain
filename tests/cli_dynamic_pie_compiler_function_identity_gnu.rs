#![cfg(target_os = "linux")]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn command_available(program: &str) -> bool {
    Command::new(program)
        .arg("--version")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn have_tools() -> bool {
    command_available("cc") && command_available("readelf")
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

fn temp_dir() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after Unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "mini-elf-toolchain-dynamic-pie-compiler-function-identity-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&path).unwrap();
    path
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

fn compile_c(dir: &Path, name: &str, source: &str) -> PathBuf {
    let input = dir.join(format!("{name}.c"));
    let object = dir.join(format!("{name}.o"));
    fs::write(&input, source).unwrap();
    let result = Command::new("cc")
        .args(["-O0", "-fPIE", "-fno-stack-protector", "-c"])
        .arg(&input)
        .arg("-o")
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    object
}

fn compile_assembly(dir: &Path, name: &str, source: &str) -> PathBuf {
    let input = dir.join(format!("{name}.S"));
    let object = dir.join(format!("{name}.o"));
    fs::write(&input, source).unwrap();
    let result = Command::new("cc")
        .arg("-c")
        .arg(&input)
        .arg("-o")
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    object
}

fn mini_link(
    objects: &[PathBuf],
    output: &Path,
    libc: &Path,
    interpreter: &Path,
) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .arg("link")
        .arg("-o")
        .arg(output)
        .args(["--dynamic-pie", "--crt-startup", "--dynamic-linker"])
        .arg(interpreter)
        .arg("--needed-from")
        .arg(libc)
        .args(objects)
        .output()
        .unwrap()
}

fn assert_function_identity(
    objects: &[PathBuf],
    dir: &Path,
    name: &str,
    libc: &Path,
    interpreter: &Path,
) {
    let mini = dir.join(format!("mini-{name}"));
    let linked = mini_link(objects, &mini, libc, interpreter);
    assert!(
        linked.status.success(),
        "{name}: {}",
        String::from_utf8_lossy(&linked.stderr)
    );

    let symbols = readelf(&mini, &["-sW", "--use-dynamic"]);
    let puts_symbols = symbols
        .lines()
        .filter(|line| line.ends_with(" puts"))
        .collect::<Vec<_>>();
    assert_eq!(
        puts_symbols.len(),
        1,
        "one canonical import required:\n{symbols}"
    );
    assert!(
        puts_symbols[0].contains("FUNC")
            && puts_symbols[0].contains("GLOBAL")
            && puts_symbols[0].contains("UND"),
        "{symbols}"
    );
    let relocations = readelf(&mini, &["-rW", "--use-dynamic"]);
    for kind in ["R_X86_64_GLOB_DAT", "R_X86_64_JUMP_SLOT", "R_X86_64_64"] {
        assert_eq!(
            relocations
                .lines()
                .filter(|line| line.contains(kind) && line.contains(" puts"))
                .count(),
            1,
            "{name}: expected one {kind} for puts:\n{relocations}"
        );
    }

    let gnu = dir.join(format!("gnu-{name}"));
    let linked = Command::new("cc")
        .arg("-pie")
        .args(objects)
        .arg("-o")
        .arg(&gnu)
        .output()
        .unwrap();
    assert!(
        linked.status.success(),
        "{}",
        String::from_utf8_lossy(&linked.stderr)
    );
    for executable in [&mini, &gnu] {
        let executed = Command::new(executable).output().unwrap();
        assert_eq!(
            executed.status.code(),
            Some(42),
            "{name}: {}: {:?}",
            executable.display(),
            executed
        );
        assert_eq!(
            String::from_utf8(executed.stdout).unwrap(),
            "direct\nsaved\nlocal\n"
        );
    }
}

const MAIN: &str = r#"#include <stdio.h>
int (*saved_puts)(const char *) = puts;
int main(void) {
    int (*local_puts)(const char *) = puts;
    if (saved_puts != puts || local_puts != puts) return 91;
    if (puts("direct") < 0 || saved_puts("saved") < 0 || local_puts("local") < 0) return 92;
    return 42;
}
"#;

#[test]
fn compiler_function_call_and_address_share_one_import() {
    if !have_tools() {
        eprintln!("SKIP: missing cc/readelf");
        return;
    }
    let Some(interpreter) = dynamic_linker() else {
        eprintln!("SKIP: missing glibc loader");
        return;
    };
    let Some(libc) = libc_path() else {
        eprintln!("SKIP: missing libc provider");
        return;
    };
    let dir = temp_dir();
    let object = compile_c(&dir, "main", MAIN);
    let symbols = readelf(&object, &["-sW"]);
    assert!(
        symbols.lines().any(|line| line.contains("NOTYPE")
            && line.contains("GLOBAL")
            && line.contains("UND")
            && line.ends_with(" puts")),
        "{symbols}"
    );
    let relocations = readelf(&object, &["-rW"]);
    for kind in ["GOTPCRELX", "R_X86_64_PLT32", "R_X86_64_64"] {
        assert!(
            relocations
                .lines()
                .any(|line| line.contains(kind) && line.contains(" puts")),
            "{relocations}"
        );
    }
    assert_function_identity(&[object], &dir, "single", &libc, &interpreter);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn compiler_function_identity_is_independent_of_object_order() {
    if !have_tools() {
        eprintln!("SKIP: missing cc/readelf");
        return;
    }
    let Some(interpreter) = dynamic_linker() else {
        eprintln!("SKIP: missing glibc loader");
        return;
    };
    let Some(libc) = libc_path() else {
        eprintln!("SKIP: missing libc provider");
        return;
    };
    let dir = temp_dir();
    let addresses = compile_c(
        &dir,
        "addresses",
        r#"#include <stdio.h>
int (*saved_puts)(const char *) = puts;
int invoke_saved(void) {
    int (*local_puts)(const char *) = puts;
    if (saved_puts != puts || local_puts != puts) return -1;
    if (saved_puts("saved") < 0 || local_puts("local") < 0) return -1;
    return 0;
}
"#,
    );
    let calls = compile_c(
        &dir,
        "main",
        r#"#include <stdio.h>
int invoke_saved(void);
int main(void) {
    if (puts("direct") < 0 || invoke_saved() < 0) return 92;
    return 42;
}
"#,
    );
    let address_relocations = readelf(&addresses, &["-rW"]);
    assert!(
        !address_relocations
            .lines()
            .any(|line| line.contains("R_X86_64_PLT32") && line.contains(" puts")),
        "address object must not establish a call identity:\n{address_relocations}"
    );
    assert_function_identity(
        &[addresses.clone(), calls.clone()],
        &dir,
        "address-first",
        &libc,
        &interpreter,
    );
    assert_function_identity(&[calls, addresses], &dir, "call-first", &libc, &interpreter);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn untyped_address_without_function_call_still_rejects() {
    if !have_tools() {
        eprintln!("SKIP: missing cc/readelf");
        return;
    }
    let Some(interpreter) = dynamic_linker() else {
        eprintln!("SKIP: missing glibc loader");
        return;
    };
    let Some(libc) = libc_path() else {
        eprintln!("SKIP: missing libc provider");
        return;
    };
    let dir = temp_dir();
    let object = compile_c(
        &dir,
        "main",
        r#"#include <stdio.h>
int (*saved_puts)(const char *) = puts;
int main(void) { return saved_puts == puts ? 42 : 91; }
"#,
    );
    let output = dir.join("must-not-exist");
    let linked = mini_link(&[object], &output, &libc, &interpreter);
    assert!(!linked.status.success());
    assert!(
        String::from_utf8_lossy(&linked.stderr).contains("with ELF symbol type 0"),
        "{}",
        String::from_utf8_lossy(&linked.stderr)
    );
    assert!(!output.exists());
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn explicit_object_type_is_not_overridden_by_function_call() {
    if !have_tools() {
        eprintln!("SKIP: missing cc/readelf");
        return;
    }
    let Some(interpreter) = dynamic_linker() else {
        eprintln!("SKIP: missing glibc loader");
        return;
    };
    let Some(libc) = libc_path() else {
        eprintln!("SKIP: missing libc provider");
        return;
    };
    let dir = temp_dir();
    let main = compile_c(
        &dir,
        "main",
        "#include <stdio.h>\nint main(void) { return puts(\"direct\") < 0 ? 92 : 42; }\n",
    );
    let data = compile_assembly(&dir, "data", ".extern puts\n.type puts,@object\n.data\n.globl object_reference\n.type object_reference,@object\nobject_reference:\n.quad puts\n.section .note.GNU-stack,\"\",@progbits\n");
    for (name, objects) in [
        ("object-first", vec![data.clone(), main.clone()]),
        ("call-first", vec![main, data]),
    ] {
        let output = dir.join(name);
        let linked = mini_link(&objects, &output, &libc, &interpreter);
        assert!(!linked.status.success());
        assert!(
            String::from_utf8_lossy(&linked.stderr).contains("conflicting ELF symbol types"),
            "{}",
            String::from_utf8_lossy(&linked.stderr)
        );
        assert!(!output.exists());
    }
    fs::remove_dir_all(dir).unwrap();
}
