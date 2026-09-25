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
        "mini-elf-toolchain-dynamic-pie-compiler-pc32-{}-{nonce}",
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

#[test]
#[cfg(target_os = "linux")]
fn compiler_generated_pie_binds_internal_pc32_and_external_plt() {
    if !have_tools() {
        return;
    }
    let Some(interpreter) = dynamic_linker() else {
        return;
    };
    let Some(libc) = libc_path() else {
        return;
    };

    let dir = temp_dir();
    let source = dir.join("main.c");
    let object = dir.join("main.o");
    fs::write(
        &source,
        r#"#include <stdio.h>

int counter = 40;

static int bump(void) {
    counter += 2;
    return counter;
}

int main(int argc, char **argv) {
    if (argc != 2) return 90;
    if (argv[1] == 0 || argv[1][0] != 'x') return 91;
    if (puts("mini compiler PIE") < 0) return 92;
    return bump();
}
"#,
    )
    .unwrap();

    let compiled = Command::new("cc")
        .args(["-O0", "-fPIE", "-fno-stack-protector", "-c"])
        .arg(&source)
        .arg("-o")
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );

    let input_symbols = readelf(&object, &["-sW"]);
    assert!(
        input_symbols.lines().any(|line| {
            line.contains("NOTYPE")
                && line.contains("GLOBAL")
                && line.contains("UND")
                && line.ends_with(" puts")
        }),
        "compiler fixture must expose puts as an undefined GLOBAL STT_NOTYPE symbol:\n{input_symbols}"
    );

    let input_relocations = readelf(&object, &["-rW"]);
    assert!(
        input_relocations
            .lines()
            .any(|line| line.contains("R_X86_64_PC32") && line.contains("counter")),
        "compiler fixture must exercise same-executable PC32 data binding:\n{input_relocations}"
    );
    assert!(
        input_relocations
            .lines()
            .any(|line| line.contains("R_X86_64_PLT32") && line.contains("puts")),
        "compiler fixture must exercise external PLT binding:\n{input_relocations}"
    );

    let mini = dir.join("mini-pie");
    let linked = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&mini)
        .arg("--dynamic-pie")
        .arg("--crt-startup")
        .arg("--dynamic-linker")
        .arg(&interpreter)
        .arg("--needed-from")
        .arg(&libc)
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        linked.status.success(),
        "{}",
        String::from_utf8_lossy(&linked.stderr)
    );

    let dynamic_relocations = readelf(&mini, &["-rW", "--use-dynamic"]);
    assert!(
        dynamic_relocations
            .lines()
            .any(|line| line.contains("R_X86_64_JUMP_SLOT") && line.contains("puts")),
        "external compiler call must remain loader-bound through JUMP_SLOT:\n{dynamic_relocations}"
    );
    assert!(
        !dynamic_relocations
            .lines()
            .any(|line| line.contains("counter")),
        "same-executable PC32 data reference must be resolved at link time:\n{dynamic_relocations}"
    );

    let mini_status = Command::new(&mini).arg("x").status().unwrap();
    assert_eq!(
        mini_status.code(),
        Some(42),
        "mini-linked compiler PIE must receive argc/argv and mutate its own global: {mini_status}"
    );

    let gnu = dir.join("gnu-pie");
    let gnu_link = Command::new("cc")
        .arg("-pie")
        .arg(&object)
        .arg("-o")
        .arg(&gnu)
        .output()
        .unwrap();
    assert!(
        gnu_link.status.success(),
        "{}",
        String::from_utf8_lossy(&gnu_link.stderr)
    );
    let gnu_status = Command::new(&gnu).arg("x").status().unwrap();
    assert_eq!(
        gnu_status.code(),
        Some(42),
        "GNU reference must execute the same compiler object: {gnu_status}"
    );

    let _ = fs::remove_dir_all(dir);
}
