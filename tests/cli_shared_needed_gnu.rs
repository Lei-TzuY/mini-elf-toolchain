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
    lea 2(%rdi), %rax
    ret
.size provider_function, .-provider_function
"#,
    );
    let shared = dir.join("libprovider.so");
    let output = Command::new("ld")
        .args(["-shared", "-soname", "libprovider.so", "-o"])
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

fn build_named_provider(dir: &Path, stem: &str, soname: &str, increment: u64) -> PathBuf {
    let source = format!(
        ".section .text\n.globl provider_function\n.type provider_function,@function\nprovider_function:\n    lea {increment}(%rdi), %rax\n    ret\n.size provider_function, .-provider_function\n"
    );
    let object = assemble(dir, stem, &source);
    let shared = dir.join(soname);
    let output = Command::new("ld")
        .args(["-shared", "-soname", soname, "-o"])
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
    mov $40, %edi
    sub $8, %rsp
    call provider_function
    add $8, %rsp
    ret
.size call_provider, .-call_provider
"#,
    )
}

#[test]
fn shared_needed_dependency_loads_provider_and_resolves_jump_slot() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("runtime");
    let provider = build_provider(&dir);
    let object = build_consumer_object(&dir);
    let shared = dir.join("libconsumer.so");

    let mini = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&shared)
        .arg("--shared")
        .args(["--needed", "libprovider.so", "--needed=libprovider.so"])
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
    assert_eq!(
        dynamic.matches("Shared library: [libprovider.so]").count(),
        1,
        "{dynamic}"
    );

    let relocations = Command::new("readelf")
        .args(["-rW", "--use-dynamic"])
        .arg(&shared)
        .output()
        .unwrap();
    assert!(relocations.status.success());
    let relocations = String::from_utf8_lossy(&relocations.stdout);
    assert!(relocations.contains("R_X86_64_JUMP_SLOT"), "{relocations}");
    assert!(relocations.contains("provider_function"), "{relocations}");

    #[cfg(target_os = "linux")]
    {
        let source = dir.join("runner.c");
        let runner = dir.join("runner");
        fs::write(
            &source,
            r#"#include <dlfcn.h>
#include <stdint.h>

int main(int argc, char **argv) {
    if (argc != 2) return 80;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) return 81;
    uint64_t (*call_provider)(void) =
        (uint64_t (*)(void))dlsym(handle, "call_provider");
    if (!call_provider) return 82;
    if (call_provider() != UINT64_C(42)) return 83;
    return dlclose(handle) == 0 ? 0 : 84;
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

        let status = Command::new(&runner)
            .arg(&shared)
            .env("LD_LIBRARY_PATH", &dir)
            .status()
            .unwrap();
        assert!(status.success(), "DT_NEEDED consumer returned {status}");

        let provider_name = provider.file_name().unwrap();
        assert_eq!(provider_name, "libprovider.so");
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn shared_needed_order_controls_dependency_symbol_scope() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("order");
    let _first = build_named_provider(&dir, "first-provider", "libfirst.so", 2);
    let _second = build_named_provider(&dir, "second-provider", "libsecond.so", 9);
    let object = build_consumer_object(&dir);
    let shared = dir.join("libordered-consumer.so");

    let mini = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&shared)
        .arg("--shared")
        .args(["--needed", "libfirst.so", "--needed", "libsecond.so"])
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
    let first = dynamic
        .find("Shared library: [libfirst.so]")
        .expect("first DT_NEEDED entry");
    let second = dynamic
        .find("Shared library: [libsecond.so]")
        .expect("second DT_NEEDED entry");
    assert!(
        first < second,
        "DT_NEEDED declaration order changed: {dynamic}"
    );

    #[cfg(target_os = "linux")]
    {
        let source = dir.join("runner.c");
        let runner = dir.join("runner");
        fs::write(
            &source,
            r#"#include <dlfcn.h>
#include <stdint.h>

int main(int argc, char **argv) {
    if (argc != 2) return 100;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) return 101;
    uint64_t (*call_provider)(void) =
        (uint64_t (*)(void))dlsym(handle, "call_provider");
    if (!call_provider) return 102;
    if (call_provider() != UINT64_C(42)) return 103;
    return dlclose(handle) == 0 ? 0 : 104;
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

        let status = Command::new(&runner)
            .arg(&shared)
            .env("LD_LIBRARY_PATH", &dir)
            .status()
            .unwrap();
        assert!(
            status.success(),
            "DT_NEEDED dependency order did not control symbol scope: {status}"
        );
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn shared_without_needed_does_not_gain_provider_scope() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("missing");
    let _provider = build_provider(&dir);
    let object = build_consumer_object(&dir);
    let shared = dir.join("libconsumer-no-needed.so");

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

    #[cfg(target_os = "linux")]
    {
        let source = dir.join("runner.c");
        let runner = dir.join("runner");
        fs::write(
            &source,
            r#"#include <dlfcn.h>

int main(int argc, char **argv) {
    if (argc != 2) return 90;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (handle) {
        dlclose(handle);
        return 91;
    }
    return 0;
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

        let status = Command::new(&runner)
            .arg(&shared)
            .env("LD_LIBRARY_PATH", &dir)
            .status()
            .unwrap();
        assert!(
            status.success(),
            "consumer without DT_NEEDED unexpectedly loaded provider: {status}"
        );
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn needed_option_is_shared_only_and_requires_a_name() {
    let dir = temp_dir("cli");
    let output = dir.join("out");

    let non_shared = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&output)
        .args(["--needed", "libprovider.so"])
        .arg("missing.o")
        .output()
        .unwrap();
    assert_eq!(non_shared.status.code(), Some(2));
    assert!(non_shared.stdout.is_empty());
    assert!(String::from_utf8_lossy(&non_shared.stderr)
        .contains("--needed is only supported with --shared"));
    assert!(!output.exists());

    let missing_name = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&output)
        .args(["--shared", "--needed"])
        .output()
        .unwrap();
    assert_eq!(missing_name.status.code(), Some(2));
    assert!(missing_name.stdout.is_empty());
    assert!(String::from_utf8_lossy(&missing_name.stderr)
        .contains("missing dependency name after --needed"));
    assert!(!output.exists());

    let _ = fs::remove_dir_all(dir);
}
