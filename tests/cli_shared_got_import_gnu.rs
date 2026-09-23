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
        && command_reports("readelf", "GNU readelf")
        && command_available("cc")
}

fn temp_dir(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after Unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "mini-elf-toolchain-shared-got-import-{label}-{}-{nonce}",
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

#[test]
fn shared_object_imports_external_data_through_glob_dat_got_slot() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("glob-dat");
    let object = assemble(
        &dir,
        "got-import",
        r#".section .text
.globl read_host
.type read_host,@function
.extern host_value
.type host_value,@object
read_host:
    mov host_value@GOTPCREL(%rip), %rax
    mov (%rax), %rax
    ret
.size read_host, .-read_host
"#,
    );

    let input_relocations = Command::new("readelf")
        .args(["-rW"])
        .arg(&object)
        .output()
        .unwrap();
    assert!(input_relocations.status.success());
    let input_relocations = String::from_utf8_lossy(&input_relocations.stdout);
    assert!(
        input_relocations.contains("GOTPCREL"),
        "fixture must carry a GOTPCREL-family relocation: {input_relocations}"
    );
    assert!(input_relocations.contains("host_value"));

    let shared = dir.join("libgotimport.so");
    let mini = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&shared)
        .arg("--shared")
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        mini.status.success(),
        "{}",
        String::from_utf8_lossy(&mini.stderr)
    );

    let symbols = Command::new("readelf")
        .arg("-sDW")
        .arg(&shared)
        .output()
        .unwrap();
    assert!(symbols.status.success());
    let symbols = String::from_utf8_lossy(&symbols.stdout);
    assert!(
        symbols
            .lines()
            .any(|line| line.contains("UND") && line.ends_with(" host_value")),
        "{symbols}"
    );

    let relocations = Command::new("readelf")
        .args(["-rW", "--use-dynamic"])
        .arg(&shared)
        .output()
        .unwrap();
    assert!(relocations.status.success());
    let relocations = String::from_utf8_lossy(&relocations.stdout);
    assert!(relocations.contains("R_X86_64_GLOB_DAT"), "{relocations}");
    assert!(relocations.contains("host_value"), "{relocations}");

    #[cfg(target_os = "linux")]
    {
        let source = dir.join("consumer.c");
        let consumer = dir.join("consumer");
        fs::write(
            &source,
            r#"#include <dlfcn.h>
#include <stdint.h>

uint64_t host_value = UINT64_C(0x123456789abcdef0);

int main(int argc, char **argv) {
    if (argc != 2) return 50;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) return 51;
    uint64_t (*read_host)(void) =
        (uint64_t (*)(void))dlsym(handle, "read_host");
    if (!read_host) return 52;
    if (read_host() != UINT64_C(0x123456789abcdef0)) return 53;
    host_value = UINT64_C(0x0fedcba987654321);
    if (read_host() != UINT64_C(0x0fedcba987654321)) return 54;
    return dlclose(handle) == 0 ? 0 : 55;
}
"#,
        )
        .unwrap();
        let compile = Command::new("cc")
            .args(["-rdynamic", "-o"])
            .arg(&consumer)
            .arg(&source)
            .arg("-ldl")
            .output()
            .unwrap();
        assert!(
            compile.status.success(),
            "{}",
            String::from_utf8_lossy(&compile.stderr)
        );

        let status = Command::new(&consumer).arg(&shared).status().unwrap();
        assert!(status.success(), "GLOB_DAT dlopen consumer returned {status}");
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn shared_got_import_rejects_undefined_function_target() {
    if !command_reports("as", "GNU assembler") {
        return;
    }

    let dir = temp_dir("function");
    let object = assemble(
        &dir,
        "function-import",
        r#".section .text
.globl address_of_host_function
.type address_of_host_function,@function
.extern host_function
.type host_function,@function
address_of_host_function:
    mov host_function@GOTPCREL(%rip), %rax
    ret
.size address_of_host_function, .-address_of_host_function
"#,
    );
    let output = dir.join("must-not-exist.so");

    let mini = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&output)
        .arg("--shared")
        .arg(&object)
        .output()
        .unwrap();

    assert!(!mini.status.success());
    assert!(mini.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&mini.stderr);
    assert!(
        stderr.contains("STT_OBJECT") || stderr.contains("symbol type"),
        "{stderr}"
    );
    assert!(!output.exists());

    let _ = fs::remove_dir_all(dir);
}
