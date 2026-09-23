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
        "mini-elf-toolchain-shared-import-{label}-{}-{nonce}",
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
fn shared_object_imports_external_data_symbol_through_loader() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("strong");
    let object = assemble(
        &dir,
        "import",
        r#".section .data
.align 8
.globl imported_pointer
.type imported_pointer,@object
.extern host_value
.type host_value,@object
imported_pointer:
    .quad host_value
.size imported_pointer, .-imported_pointer
"#,
    );

    let input_relocations = Command::new("readelf")
        .args(["-rW"])
        .arg(&object)
        .output()
        .unwrap();
    assert!(input_relocations.status.success());
    let input_relocations = String::from_utf8_lossy(&input_relocations.stdout);
    assert!(input_relocations.contains("R_X86_64_64"));
    assert!(input_relocations.contains("host_value"));

    let shared = dir.join("libimport.so");
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
    assert!(symbols.contains("host_value"));
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
    assert!(relocations.contains("R_X86_64_64"), "{relocations}");
    assert!(relocations.contains("host_value"), "{relocations}");

    #[cfg(target_os = "linux")]
    {
        let source = dir.join("consumer.c");
        let consumer = dir.join("consumer");
        fs::write(
            &source,
            r#"#include <dlfcn.h>
#include <stdint.h>

uint64_t host_value = UINT64_C(0x8877665544332211);

int main(int argc, char **argv) {
    if (argc != 2) return 30;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) return 31;
    uint64_t **pointer = (uint64_t **)dlsym(handle, "imported_pointer");
    if (!pointer) return 32;
    if (*pointer != &host_value) return 33;
    if (**pointer != UINT64_C(0x8877665544332211)) return 34;
    return dlclose(handle) == 0 ? 0 : 35;
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
            "dlopen external-import consumer returned {status}"
        );
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn shared_external_import_rejects_conflicting_symbol_types() {
    if !command_reports("as", "GNU assembler") {
        return;
    }

    let dir = temp_dir("conflicting-import-types");
    let object_ref = assemble(
        &dir,
        "object-ref",
        r#".section .data
.globl object_pointer
.type object_pointer,@object
.extern conflict_symbol
.type conflict_symbol,@object
object_pointer:
    .quad conflict_symbol
.size object_pointer, .-object_pointer
"#,
    );
    let function_ref = assemble(
        &dir,
        "function-ref",
        r#".section .data
.globl function_pointer
.type function_pointer,@object
.extern conflict_symbol
.type conflict_symbol,@function
function_pointer:
    .quad conflict_symbol
.size function_pointer, .-function_pointer
"#,
    );
    let output = dir.join("must-not-exist.so");

    let mini = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&output)
        .arg("--shared")
        .arg(&object_ref)
        .arg(&function_ref)
        .output()
        .unwrap();

    assert!(!mini.status.success());
    assert!(mini.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&mini.stderr);
    assert!(
        stderr.contains("conflicting ELF symbol types"),
        "{stderr}"
    );
    assert!(!output.exists());

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn shared_external_import_rejects_read_only_relocation_target() {
    if !command_reports("as", "GNU assembler") {
        return;
    }

    let dir = temp_dir("readonly");
    let object = assemble(
        &dir,
        "readonly",
        r#".section .rodata
.globl imported_pointer
.type imported_pointer,@object
.extern host_value
.type host_value,@object
imported_pointer:
    .quad host_value
.size imported_pointer, .-imported_pointer
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
        stderr.contains("writable") || stderr.contains("read-only"),
        "{stderr}"
    );
    assert!(!output.exists());

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn shared_relative_prefix_and_external_import_compose_under_loader() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("mixed");
    let object = assemble(
        &dir,
        "mixed",
        r#".section .data
.align 8
.local local_value
.type local_value,@object
local_value:
    .quad 0x1122334455667788
.size local_value, .-local_value

.globl internal_pointer
.type internal_pointer,@object
internal_pointer:
    .quad local_value
.size internal_pointer, .-internal_pointer

.globl imported_pointer
.type imported_pointer,@object
.extern host_value
.type host_value,@object
imported_pointer:
    .quad host_value
.size imported_pointer, .-imported_pointer
"#,
    );

    let shared = dir.join("libmixed.so");
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

    let dynamic = Command::new("readelf")
        .args(["-dW"])
        .arg(&shared)
        .output()
        .unwrap();
    assert!(dynamic.status.success());
    let dynamic = String::from_utf8_lossy(&dynamic.stdout);
    assert!(
        dynamic.contains("RELACOUNT") && dynamic.contains("1"),
        "{dynamic}"
    );

    let relocations = Command::new("readelf")
        .args(["-rW", "--use-dynamic"])
        .arg(&shared)
        .output()
        .unwrap();
    assert!(relocations.status.success());
    let relocations = String::from_utf8_lossy(&relocations.stdout);
    let relative = relocations
        .find("R_X86_64_RELATIVE")
        .expect("mixed DSO must contain a relative relocation");
    let import = relocations
        .find("R_X86_64_64")
        .expect("mixed DSO must contain an external symbol relocation");
    assert!(
        relative < import,
        "DT_RELACOUNT requires RELATIVE entries to form the relocation prefix: {relocations}"
    );
    assert!(relocations.contains("host_value"), "{relocations}");

    #[cfg(target_os = "linux")]
    {
        let source = dir.join("consumer.c");
        let consumer = dir.join("consumer");
        fs::write(
            &source,
            r#"#include <dlfcn.h>
#include <stdint.h>

uint64_t host_value = UINT64_C(0x8877665544332211);

int main(int argc, char **argv) {
    if (argc != 2) return 40;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) return 41;
    uint64_t **internal = (uint64_t **)dlsym(handle, "internal_pointer");
    uint64_t **external = (uint64_t **)dlsym(handle, "imported_pointer");
    if (!internal || !external) return 42;
    if (**internal != UINT64_C(0x1122334455667788)) return 43;
    if (*external != &host_value) return 44;
    if (**external != UINT64_C(0x8877665544332211)) return 45;
    return dlclose(handle) == 0 ? 0 : 46;
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
        assert!(status.success(), "mixed dlopen consumer returned {status}");
    }

    let _ = fs::remove_dir_all(dir);
}
