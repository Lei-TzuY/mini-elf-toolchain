use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const WEAK_NAME: &str = "mini_elf_optional_weak_data_7f19";

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
        "mini-elf-toolchain-shared-weak-{label}-{}-{nonce}",
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

fn weak_fixture(dir: &Path) -> PathBuf {
    assemble(
        dir,
        "weak-import",
        &format!(
            r#".section .data
.align 8
.globl weak_direct
.type weak_direct,@object
.weak {WEAK_NAME}
.type {WEAK_NAME},@object
weak_direct:
    .quad {WEAK_NAME}
.size weak_direct, .-weak_direct

.section .text
.globl weak_address
.type weak_address,@function
weak_address:
    mov {WEAK_NAME}@GOTPCREL(%rip), %rax
    ret
.size weak_address, .-weak_address
"#
        ),
    )
}

fn build_shared(dir: &Path, name: &str, objects: &[&Path]) -> PathBuf {
    let shared = dir.join(name);
    let mut command = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"));
    command.args(["link", "-o"]).arg(&shared).arg("--shared");
    for object in objects {
        command.arg(object);
    }
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    shared
}

#[test]
fn unresolved_weak_data_imports_resolve_to_zero_without_provider() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("zero");
    let object = weak_fixture(&dir);
    let shared = build_shared(&dir, "libweak.so", &[&object]);

    let symbols = Command::new("readelf")
        .arg("-sDW")
        .arg(&shared)
        .output()
        .unwrap();
    assert!(symbols.status.success());
    let symbols = String::from_utf8_lossy(&symbols.stdout);
    assert!(
        symbols.lines().any(|line| {
            line.contains("WEAK")
                && line.contains("OBJECT")
                && line.contains("UND")
                && line.ends_with(WEAK_NAME)
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
            .any(|line| line.contains("R_X86_64_64") && line.contains(WEAK_NAME)),
        "{relocations}"
    );
    assert!(
        relocations
            .lines()
            .any(|line| line.contains("R_X86_64_GLOB_DAT") && line.contains(WEAK_NAME)),
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

int main(int argc, char **argv) {
    if (argc != 2) return 80;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) return 81;

    uintptr_t *direct = (uintptr_t *)dlsym(handle, "weak_direct");
    uintptr_t (*weak_address)(void) =
        (uintptr_t (*)(void))dlsym(handle, "weak_address");
    if (!direct || !weak_address) return 82;
    if (*direct != 0) return 83;
    if (weak_address() != 0) return 84;

    return dlclose(handle) == 0 ? 0 : 85;
}
"#,
        )
        .unwrap();
        let compile = Command::new("cc")
            .args(["-o"])
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
            "unresolved weak-import consumer returned {status}"
        );
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn weak_data_imports_bind_when_host_definition_is_visible() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("bound");
    let object = weak_fixture(&dir);
    let shared = build_shared(&dir, "libweak-bound.so", &[&object]);

    #[cfg(target_os = "linux")]
    {
        let source = dir.join("consumer.c");
        let consumer = dir.join("consumer");
        fs::write(
            &source,
            format!(
                r#"#include <dlfcn.h>
#include <stdint.h>

uint64_t {WEAK_NAME} = UINT64_C(0x5566778899aabbcc);

int main(int argc, char **argv) {{
    if (argc != 2) return 90;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) return 91;

    uintptr_t *direct = (uintptr_t *)dlsym(handle, "weak_direct");
    uintptr_t (*weak_address)(void) =
        (uintptr_t (*)(void))dlsym(handle, "weak_address");
    if (!direct || !weak_address) return 92;
    if (*direct != (uintptr_t)&{WEAK_NAME}) return 93;
    if (weak_address() != (uintptr_t)&{WEAK_NAME}) return 94;

    {WEAK_NAME} = UINT64_C(0x0102030405060708);
    if (*(uint64_t *)weak_address() != UINT64_C(0x0102030405060708)) return 95;
    return dlclose(handle) == 0 ? 0 : 96;
}}
"#
            ),
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
            "bound weak-import consumer returned {status}"
        );
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn strong_reference_canonicalizes_same_named_weak_import_to_global() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("strong-overrides");
    let weak = assemble(
        &dir,
        "weak-reference",
        &format!(
            r#".section .data
.globl weak_pointer
.type weak_pointer,@object
.weak {WEAK_NAME}
.type {WEAK_NAME},@object
weak_pointer:
    .quad {WEAK_NAME}
.size weak_pointer, .-weak_pointer
"#
        ),
    );
    let strong = assemble(
        &dir,
        "strong-reference",
        &format!(
            r#".section .data
.globl strong_pointer
.type strong_pointer,@object
.extern {WEAK_NAME}
.type {WEAK_NAME},@object
strong_pointer:
    .quad {WEAK_NAME}
.size strong_pointer, .-strong_pointer
"#
        ),
    );
    let shared = build_shared(&dir, "libmixed-binding.so", &[&weak, &strong]);

    let symbols = Command::new("readelf")
        .arg("-sDW")
        .arg(&shared)
        .output()
        .unwrap();
    assert!(symbols.status.success());
    let symbols = String::from_utf8_lossy(&symbols.stdout);
    assert!(
        symbols.lines().any(|line| {
            line.contains("GLOBAL")
                && line.contains("OBJECT")
                && line.contains("UND")
                && line.ends_with(WEAK_NAME)
        }),
        "strong reference must canonicalize dynsym binding to GLOBAL: {symbols}"
    );
    assert!(
        !symbols.lines().any(|line| {
            line.contains("WEAK") && line.contains("UND") && line.ends_with(WEAK_NAME)
        }),
        "same import must not remain WEAK after a strong reference: {symbols}"
    );

    #[cfg(target_os = "linux")]
    {
        let source = dir.join("consumer.c");
        let consumer = dir.join("consumer");
        fs::write(
            &source,
            r#"#include <dlfcn.h>

int main(int argc, char **argv) {
    if (argc != 2) return 100;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (handle) {
        dlclose(handle);
        return 101;
    }
    return 0;
}
"#,
        )
        .unwrap();
        let compile = Command::new("cc")
            .args(["-o"])
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
            "strong-overrides-weak consumer returned {status}"
        );
    }

    let _ = fs::remove_dir_all(dir);
}
