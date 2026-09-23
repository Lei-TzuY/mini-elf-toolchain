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
        "mini-elf-toolchain-shared-function-import-{label}-{}-{nonce}",
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
fn shared_object_binds_external_function_for_got_call_and_direct_pointer() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("strong");
    let object = assemble(
        &dir,
        "function-import",
        r#".section .text
.globl call_host
.type call_host,@function
.extern host_function
.type host_function,@function
call_host:
    mov host_function@GOTPCREL(%rip), %rax
    mov $41, %edi
    sub $8, %rsp
    call *%rax
    add $8, %rsp
    ret
.size call_host, .-call_host

.section .data
.align 8
.globl imported_function_pointer
.type imported_function_pointer,@object
imported_function_pointer:
    .quad host_function
.size imported_function_pointer, .-imported_function_pointer
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
        "{input_relocations}"
    );
    assert!(
        input_relocations.contains("R_X86_64_64"),
        "{input_relocations}"
    );
    assert!(input_relocations.matches("host_function").count() >= 2);

    let shared = dir.join("libfunctionimport.so");
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
        symbols.lines().any(|line| {
            line.contains("FUNC") && line.contains("UND") && line.ends_with(" host_function")
        }),
        "{symbols}"
    );

    let relocations = Command::new("readelf")
        .args(["-rW", "--use-dynamic"])
        .arg(&shared)
        .output()
        .unwrap();
    assert!(relocations.status.success());
    let relocations = String::from_utf8_lossy(&relocations.stdout);
    assert!(
        relocations
            .lines()
            .any(|line| line.contains("R_X86_64_GLOB_DAT") && line.contains("host_function")),
        "{relocations}"
    );
    assert!(
        relocations
            .lines()
            .any(|line| line.contains("R_X86_64_64") && line.contains("host_function")),
        "{relocations}"
    );

    #[cfg(target_os = "linux")]
    {
        let source = dir.join("consumer.c");
        let consumer = dir.join("consumer");
        fs::write(
            &source,
            r#"#include <dlfcn.h>
#include <stdint.h>

uint64_t host_function(uint64_t value) {
    return value + 1;
}

int main(int argc, char **argv) {
    if (argc != 2) return 60;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) return 61;

    uint64_t (*call_host)(void) =
        (uint64_t (*)(void))dlsym(handle, "call_host");
    uint64_t (**imported_pointer)(uint64_t) =
        (uint64_t (**)(uint64_t))dlsym(handle, "imported_function_pointer");
    if (!call_host || !imported_pointer) return 62;
    if (call_host() != UINT64_C(42)) return 63;
    if (*imported_pointer != host_function) return 64;
    if ((*imported_pointer)(99) != UINT64_C(100)) return 65;

    return dlclose(handle) == 0 ? 0 : 66;
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
        assert!(
            status.success(),
            "external function import consumer returned {status}"
        );
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn shared_external_weak_nonfunction_plt_call_remains_fail_closed() {
    if !command_reports("as", "GNU assembler") {
        return;
    }

    let dir = temp_dir("weak-nonfunction-plt");
    let object = assemble(
        &dir,
        "weak-object-call",
        r#".section .text
.globl call_host_object
.type call_host_object,@function
.weak host_object
.type host_object,@object
call_host_object:
    call host_object@PLT
    ret
.size call_host_object, .-call_host_object
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
    assert!(stderr.contains("PLT") || stderr.contains("function"), "{stderr}");
    assert!(!output.exists());

    let _ = fs::remove_dir_all(dir);
}
