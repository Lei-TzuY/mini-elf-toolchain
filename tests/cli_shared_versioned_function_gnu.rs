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
        "mini-elf-toolchain-versioned-function-{label}-{}-{nonce}",
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

fn mini_provider(dir: &Path, version: &str) -> PathBuf {
    let object = assemble(
        dir,
        &format!("provider-{version}"),
        &format!(
            r#".section .text
.globl provider_impl
.type provider_impl,@function
provider_impl:
    lea 1(%rdi), %rax
    ret
.size provider_impl, .-provider_impl
.symver provider_impl,provider_function@@{version}
"#
        ),
    );
    let shared = dir.join("libprovider.so");
    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&shared)
        .args(["--shared", "--soname", "libprovider.so"])
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    shared
}

fn consumer_object(dir: &Path) -> PathBuf {
    assemble(
        dir,
        "consumer",
        r#".section .text
.extern provider_function
.type provider_function,@function
.symver provider_function,provider_function@VERS_1

.globl call_provider
.type call_provider,@function
call_provider:
    mov $41, %edi
    sub $8, %rsp
    call provider_function
    add $8, %rsp
    ret
.size call_provider, .-call_provider

.globl call_provider_got
.type call_provider_got,@function
call_provider_got:
    mov provider_function@GOTPCREL(%rip), %rax
    mov $99, %edi
    sub $8, %rsp
    call *%rax
    add $8, %rsp
    ret
.size call_provider_got, .-call_provider_got

.section .data
.align 8
.globl imported_function_pointer
.type imported_function_pointer,@object
imported_function_pointer:
    .quad provider_function
.size imported_function_pointer, .-imported_function_pointer
"#,
    )
}

#[test]
fn named_version_function_import_composes_with_plt_got_and_direct_pointer() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("runtime");
    let provider = mini_provider(&dir, "VERS_1");
    let object = consumer_object(&dir);

    let input_relocations = Command::new("readelf")
        .args(["-rW"])
        .arg(&object)
        .output()
        .unwrap();
    assert!(input_relocations.status.success());
    let input_relocations = String::from_utf8_lossy(&input_relocations.stdout);
    assert!(
        input_relocations.contains("R_X86_64_PLT32"),
        "{input_relocations}"
    );
    assert!(
        input_relocations.contains("GOTPCREL"),
        "{input_relocations}"
    );
    assert!(
        input_relocations.contains("R_X86_64_64"),
        "{input_relocations}"
    );
    assert!(
        input_relocations
            .matches("provider_function@VERS_1")
            .count()
            >= 3,
        "{input_relocations}"
    );

    let provider_symbols = Command::new("readelf")
        .arg("-sDW")
        .arg(&provider)
        .output()
        .unwrap();
    assert!(provider_symbols.status.success());
    let provider_symbols = String::from_utf8_lossy(&provider_symbols.stdout);
    assert!(
        provider_symbols.contains("provider_function@@VERS_1"),
        "{provider_symbols}"
    );

    let consumer = dir.join("libconsumer.so");
    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&consumer)
        .args(["--shared", "--soname", "libconsumer.so"])
        .arg("--needed-from")
        .arg(&provider)
        .args(["--runpath", "$ORIGIN"])
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let symbols = Command::new("readelf")
        .arg("-sDW")
        .arg(&consumer)
        .output()
        .unwrap();
    assert!(symbols.status.success());
    let symbols = String::from_utf8_lossy(&symbols.stdout);
    assert!(
        symbols.lines().any(|line| {
            line.contains("FUNC")
                && line.contains("UND")
                && line.ends_with(" provider_function@VERS_1")
        }),
        "{symbols}"
    );

    let relocations = Command::new("readelf")
        .args(["-rW", "--use-dynamic"])
        .arg(&consumer)
        .output()
        .unwrap();
    assert!(relocations.status.success());
    let relocations = String::from_utf8_lossy(&relocations.stdout);
    assert!(
        relocations.contains("R_X86_64_JUMP_SLOT")
            && relocations.contains("provider_function@VERS_1"),
        "{relocations}"
    );
    assert!(
        relocations.contains("R_X86_64_GLOB_DAT")
            && relocations.contains("provider_function@VERS_1"),
        "{relocations}"
    );
    assert!(
        relocations.contains("R_X86_64_64") && relocations.contains("provider_function@VERS_1"),
        "{relocations}"
    );

    let versions = Command::new(env!("CARGO_BIN_EXE_mini-elf-vercheck"))
        .arg(&consumer)
        .output()
        .unwrap();
    assert!(
        versions.status.success(),
        "{}",
        String::from_utf8_lossy(&versions.stderr)
    );
    let versions = String::from_utf8_lossy(&versions.stdout);
    assert!(versions.contains("provider_function"), "{versions}");
    assert!(versions.contains("source=requirement"), "{versions}");
    assert!(versions.contains("version=VERS_1"), "{versions}");

    #[cfg(target_os = "linux")]
    {
        let source = dir.join("runner.c");
        let runner = dir.join("runner");
        fs::write(
            &source,
            r#"#include <dlfcn.h>
#include <stdint.h>

int main(int argc, char **argv) {
    if (argc != 2) return 90;
    void *handle = dlopen(argv[1], RTLD_LAZY | RTLD_LOCAL);
    if (!handle) return 91;
    uint64_t (*call_provider)(void) =
        (uint64_t (*)(void))dlsym(handle, "call_provider");
    uint64_t (*call_provider_got)(void) =
        (uint64_t (*)(void))dlsym(handle, "call_provider_got");
    uint64_t (**pointer)(uint64_t) =
        (uint64_t (**)(uint64_t))dlsym(handle, "imported_function_pointer");
    if (!call_provider || !call_provider_got || !pointer || !*pointer) return 92;
    if (call_provider() != UINT64_C(42)) return 93;
    if (call_provider_got() != UINT64_C(100)) return 94;
    if ((*pointer)(9) != UINT64_C(10)) return 95;
    return dlclose(handle) == 0 ? 0 : 96;
}
"#,
        )
        .unwrap();
        let compile = Command::new("cc")
            .args(["-o"])
            .arg(&runner)
            .arg(&source)
            .arg("-ldl")
            .output()
            .unwrap();
        assert!(
            compile.status.success(),
            "{}",
            String::from_utf8_lossy(&compile.stderr)
        );

        let status = Command::new(&runner).arg(&consumer).status().unwrap();
        assert!(
            status.success(),
            "versioned function consumer returned {status}"
        );
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn named_version_function_import_rejects_different_provider_version() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("mismatch");
    let provider = mini_provider(&dir, "VERS_2");
    let object = consumer_object(&dir);
    let output = dir.join("must-not-exist.so");

    let mini = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&output)
        .arg("--shared")
        .arg("--needed-from")
        .arg(&provider)
        .arg(&object)
        .output()
        .unwrap();

    assert!(!mini.status.success());
    assert!(mini.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&mini.stderr);
    assert!(
        stderr.contains("VERS_1") || stderr.contains("version"),
        "{stderr}"
    );
    assert!(!output.exists());

    let _ = fs::remove_dir_all(dir);
}
