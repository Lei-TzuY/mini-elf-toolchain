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
        && command_reports("ld", "GNU ld")
        && command_reports("readelf", "GNU readelf")
        && command_available("cc")
}

fn temp_dir(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after Unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "mini-elf-toolchain-shared-needed-{label}-{}-{nonce}",
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

fn build_provider(dir: &Path) -> PathBuf {
    let object = assemble(
        dir,
        "provider",
        r#".section .text
.globl provider_function
.type provider_function,@function
provider_function:
    mov $42, %eax
    ret
.size provider_function, .-provider_function
"#,
    );
    let shared = dir.join("libprovider.so");
    let output = Command::new("ld")
        .args(["-shared", "--hash-style=sysv", "-soname", "libprovider.so", "-o"])
        .arg(&shared)
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

fn build_consumer_object(dir: &Path) -> PathBuf {
    assemble(
        dir,
        "consumer-object",
        r#".section .text
.globl call_provider
.type call_provider,@function
.extern provider_function
.type provider_function,@function
call_provider:
    sub $8, %rsp
    call provider_function
    add $8, %rsp
    ret
.size call_provider, .-call_provider
"#,
    )
}

#[test]
fn dt_needed_changes_loader_scope_and_resolves_plt_dependency() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("runtime");
    let provider = build_provider(&dir);
    let consumer_object = build_consumer_object(&dir);
    assert!(provider.exists());

    let without_needed = dir.join("libconsumer-without-needed.so");
    let plain = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&without_needed)
        .arg("--shared")
        .arg(&consumer_object)
        .output()
        .unwrap();
    assert!(
        plain.status.success(),
        "{}",
        String::from_utf8_lossy(&plain.stderr)
    );

    let with_needed = dir.join("libconsumer-needed.so");
    let linked = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&with_needed)
        .args(["--shared", "--needed", "libprovider.so"])
        .arg(&consumer_object)
        .output()
        .unwrap();
    assert!(
        linked.status.success(),
        "{}",
        String::from_utf8_lossy(&linked.stderr)
    );

    let dynamic = Command::new("readelf")
        .arg("-dW")
        .arg(&with_needed)
        .output()
        .unwrap();
    assert!(dynamic.status.success());
    let dynamic = String::from_utf8_lossy(&dynamic.stdout);
    assert!(
        dynamic.contains("Shared library: [libprovider.so]"),
        "{dynamic}"
    );

    let plain_dynamic = Command::new("readelf")
        .arg("-dW")
        .arg(&without_needed)
        .output()
        .unwrap();
    assert!(plain_dynamic.status.success());
    assert!(
        !String::from_utf8_lossy(&plain_dynamic.stdout).contains("(NEEDED)"),
        "{}",
        String::from_utf8_lossy(&plain_dynamic.stdout)
    );

    let relocations = Command::new("readelf")
        .args(["-rW", "--use-dynamic"])
        .arg(&with_needed)
        .output()
        .unwrap();
    assert!(relocations.status.success());
    let relocations = String::from_utf8_lossy(&relocations.stdout);
    assert!(
        relocations
            .lines()
            .any(|line| line.contains("R_X86_64_JUMP_SLOT") && line.contains("provider_function")),
        "{relocations}"
    );

    #[cfg(target_os = "linux")]
    {
        let source = dir.join("loader.c");
        let loader = dir.join("loader");
        fs::write(
            &source,
            r#"#include <dlfcn.h>
#include <stdint.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc != 3) return 80;
    int expect_success = strcmp(argv[2], "success") == 0;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!expect_success) return handle == 0 ? 0 : 81;
    if (!handle) return 82;
    uint64_t (*call_provider)(void) =
        (uint64_t (*)(void))dlsym(handle, "call_provider");
    if (!call_provider) return 83;
    if (call_provider() != UINT64_C(42)) return 84;
    return dlclose(handle) == 0 ? 0 : 85;
}
"#,
        )
        .unwrap();
        let compile = Command::new("cc")
            .args(["-o"])
            .arg(&loader)
            .arg(&source)
            .arg("-ldl")
            .output()
            .unwrap();
        assert!(
            compile.status.success(),
            "{}",
            String::from_utf8_lossy(&compile.stderr)
        );

        let plain_status = Command::new(&loader)
            .arg(&without_needed)
            .arg("failure")
            .env("LD_LIBRARY_PATH", &dir)
            .status()
            .unwrap();
        assert!(
            plain_status.success(),
            "consumer without DT_NEEDED unexpectedly loaded: {plain_status}"
        );

        let needed_status = Command::new(&loader)
            .arg(&with_needed)
            .arg("success")
            .env("LD_LIBRARY_PATH", &dir)
            .status()
            .unwrap();
        assert!(
            needed_status.success(),
            "DT_NEEDED consumer failed: {needed_status}"
        );
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn needed_option_is_shared_only_and_rejects_empty_names_before_output() {
    let dir = temp_dir("cli");
    let output = dir.join("must-not-exist.so");

    let non_shared = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&output)
        .args(["--needed", "libprovider.so"])
        .arg("missing.o")
        .output()
        .unwrap();
    assert!(!non_shared.status.success());
    assert!(non_shared.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&non_shared.stderr).contains("--needed requires --shared"),
        "{}",
        String::from_utf8_lossy(&non_shared.stderr)
    );
    assert!(!output.exists());

    let empty = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&output)
        .args(["--shared", "--needed="])
        .arg("missing.o")
        .output()
        .unwrap();
    assert!(!empty.status.success());
    assert!(empty.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&empty.stderr).contains("dependency name cannot be empty"),
        "{}",
        String::from_utf8_lossy(&empty.stderr)
    );
    assert!(!output.exists());

    let _ = fs::remove_dir_all(dir);
}
