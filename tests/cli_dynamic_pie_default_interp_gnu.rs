use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_INTERPRETER: &str = "/lib64/ld-linux-x86-64.so.2";

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

fn temp_dir(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after Unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "mini-elf-toolchain-default-interpreter-{label}-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&path).unwrap();
    path
}

fn assemble(dir: &Path, stem: &str, exit_code: u32) -> PathBuf {
    let asm = dir.join(format!("{stem}.s"));
    let object = dir.join(format!("{stem}.o"));
    fs::write(
        &asm,
        format!(
            ".text\n.globl _start\n.type _start,@function\n_start:\n    mov $60, %eax\n    mov $${exit_code}, %edi\n    syscall\n.size _start, .-_start\n.section .note.GNU-stack,\"\",@progbits\n"
        ),
    )
    .unwrap();
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

fn program_headers(path: &Path) -> String {
    let output = Command::new("readelf")
        .args(["-lW"])
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
fn dynamic_pie_uses_gnu_linux_x86_64_default_interpreter_and_executes() {
    if !have_gnu_tools() || !Path::new(DEFAULT_INTERPRETER).is_file() {
        return;
    }

    let dir = temp_dir("default");
    let object = assemble(&dir, "start", 23);
    let ours = dir.join("mini-default");

    let linked = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&ours)
        .arg("--dynamic-pie")
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        linked.status.success(),
        "{}",
        String::from_utf8_lossy(&linked.stderr)
    );

    let ours_headers = program_headers(&ours);
    assert!(ours_headers.contains("INTERP"), "{ours_headers}");
    assert!(ours_headers.contains(DEFAULT_INTERPRETER), "{ours_headers}");

    let status = Command::new(&ours).status().unwrap();
    assert_eq!(
        status.code(),
        Some(23),
        "{} should execute through the default interpreter; status={status}",
        ours.display()
    );

    let gnu = dir.join("gnu-default");
    let gnu_link = Command::new("ld")
        .args(["-pie", "-o"])
        .arg(&gnu)
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        gnu_link.status.success(),
        "{}",
        String::from_utf8_lossy(&gnu_link.stderr)
    );
    let gnu_headers = program_headers(&gnu);
    assert!(
        gnu_headers.contains(DEFAULT_INTERPRETER),
        "GNU x86-64 Linux default interpreter drifted:\n{gnu_headers}"
    );
    let gnu_status = Command::new(&gnu).status().unwrap();
    assert_eq!(gnu_status.code(), Some(23), "GNU reference status={gnu_status}");

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn explicit_dynamic_linker_overrides_default_policy() {
    if !have_gnu_tools() {
        return;
    }

    let dir = temp_dir("override");
    let object = assemble(&dir, "start", 0);
    let ours = dir.join("mini-override");
    let custom = "/opt/mini-elf-toolchain/custom-ld.so";

    let linked = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&ours)
        .arg("--dynamic-pie")
        .arg("--dynamic-linker")
        .arg(custom)
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        linked.status.success(),
        "{}",
        String::from_utf8_lossy(&linked.stderr)
    );

    let headers = program_headers(&ours);
    assert!(headers.contains(custom), "{headers}");
    assert!(!headers.contains(DEFAULT_INTERPRETER), "{headers}");

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn explicit_dynamic_linker_stays_fail_closed_outside_dynamic_pie_before_io() {
    let output = PathBuf::from("/tmp/mini-elf-toolchain-interpreter-should-not-exist");
    let result = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&output)
        .args([
            "--dynamic-linker",
            "/opt/mini-elf-toolchain/custom-ld.so",
            "definitely-missing-input.o",
        ])
        .output()
        .unwrap();

    assert_eq!(result.status.code(), Some(2));
    assert!(result.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&result.stderr)
            .contains("--dynamic-linker is only supported with --dynamic-pie")
    );
    assert!(!output.exists());
}
