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
        "mini-elf-toolchain-shared-soname-{label}-{}-{nonce}",
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
fn mini_produced_soname_provider_round_trips_through_provider_inference_and_loader() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("round-trip");
    let provider_object = assemble(
        &dir,
        "provider",
        r#".section .data
.globl provider_value
.type provider_value,@object
provider_value:
    .quad 0x1122334455667788
.size provider_value, .-provider_value

.section .text
.globl provider_function
.type provider_function,@function
provider_function:
    movabs $0x1122334455667789, %rax
    ret
.size provider_function, .-provider_function
"#,
    );
    let provider = dir.join("libprovider.so");
    let provider_link = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&provider)
        .args(["--shared", "--soname", "libprovider.so"])
        .arg(&provider_object)
        .output()
        .unwrap();
    assert!(
        provider_link.status.success(),
        "{}",
        String::from_utf8_lossy(&provider_link.stderr)
    );

    let dynamic = Command::new("readelf")
        .args(["-dW"])
        .arg(&provider)
        .output()
        .unwrap();
    assert!(dynamic.status.success());
    let dynamic = String::from_utf8_lossy(&dynamic.stdout);
    assert!(dynamic.contains("(SONAME)"), "{dynamic}");
    assert!(dynamic.contains("[libprovider.so]"), "{dynamic}");

    let consumer_object = assemble(
        &dir,
        "consumer",
        r#".section .text
.globl call_provider
.type call_provider,@function
.extern provider_function
.type provider_function,@function
call_provider:
    call provider_function@PLT
    ret
.size call_provider, .-call_provider

.globl read_provider_value
.type read_provider_value,@function
.extern provider_value
.type provider_value,@object
read_provider_value:
    mov provider_value@GOTPCREL(%rip), %rax
    mov (%rax), %rax
    ret
.size read_provider_value, .-read_provider_value
"#,
    );
    let consumer = dir.join("libconsumer.so");
    let consumer_link = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&consumer)
        .args(["--shared", "--needed-from"])
        .arg(&provider)
        .arg(&consumer_object)
        .output()
        .unwrap();
    assert!(
        consumer_link.status.success(),
        "{}",
        String::from_utf8_lossy(&consumer_link.stderr)
    );

    let consumer_dynamic = Command::new("readelf")
        .args(["-dW"])
        .arg(&consumer)
        .output()
        .unwrap();
    assert!(consumer_dynamic.status.success());
    let consumer_dynamic = String::from_utf8_lossy(&consumer_dynamic.stdout);
    assert!(consumer_dynamic.contains("(NEEDED)"), "{consumer_dynamic}");
    assert!(
        consumer_dynamic.contains("[libprovider.so]"),
        "{consumer_dynamic}"
    );

    #[cfg(target_os = "linux")]
    {
        let source = dir.join("host.c");
        let host = dir.join("host");
        fs::write(
            &source,
            r#"#include <dlfcn.h>
#include <stdint.h>

int main(int argc, char **argv) {
    if (argc != 2) return 60;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) return 61;
    uint64_t (*call_provider)(void) =
        (uint64_t (*)(void))dlsym(handle, "call_provider");
    uint64_t (*read_provider_value)(void) =
        (uint64_t (*)(void))dlsym(handle, "read_provider_value");
    if (!call_provider || !read_provider_value) return 62;
    if (read_provider_value() != UINT64_C(0x1122334455667788)) return 63;
    if (call_provider() != UINT64_C(0x1122334455667789)) return 64;
    return dlclose(handle) == 0 ? 0 : 65;
}
"#,
        )
        .unwrap();
        let compile = Command::new("cc")
            .args(["-o"])
            .arg(&host)
            .arg(&source)
            .arg("-ldl")
            .output()
            .unwrap();
        assert!(
            compile.status.success(),
            "{}",
            String::from_utf8_lossy(&compile.stderr)
        );

        let status = Command::new(&host)
            .arg(&consumer)
            .env("LD_LIBRARY_PATH", &dir)
            .status()
            .unwrap();
        assert!(
            status.success(),
            "self-hosted provider consumer returned {status}"
        );
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn shared_soname_equals_form_is_emitted_exactly() {
    if !command_reports("as", "GNU assembler") || !command_reports("readelf", "GNU readelf") {
        return;
    }

    let dir = temp_dir("equals");
    let object = assemble(
        &dir,
        "export",
        ".text\n.globl exported\n.type exported,@function\nexported:\n  ret\n.size exported, .-exported\n",
    );
    let output = dir.join("libphysical-name.so");

    let mini = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&output)
        .args(["--shared", "--soname=liblogical-name.so.7"])
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
        .arg(&output)
        .output()
        .unwrap();
    assert!(dynamic.status.success());
    let dynamic = String::from_utf8_lossy(&dynamic.stdout);
    assert!(dynamic.contains("[liblogical-name.so.7]"), "{dynamic}");

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn soname_is_rejected_outside_shared_mode_before_input_io() {
    let dir = temp_dir("non-shared");
    let missing = dir.join("missing.o");
    let output = dir.join("out");

    let result = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&output)
        .args(["--soname", "libbad.so"])
        .arg(&missing)
        .output()
        .unwrap();

    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(
        stderr.contains("--soname is only supported with --shared"),
        "{stderr}"
    );
    assert!(!stderr.contains("missing.o"), "{stderr}");
    assert!(!output.exists());

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn duplicate_or_empty_soname_is_rejected_without_output() {
    if !command_reports("as", "GNU assembler") {
        return;
    }

    let dir = temp_dir("invalid");
    let object = assemble(
        &dir,
        "export",
        ".text\n.globl exported\nexported:\n  ret\n",
    );

    for (label, args) in [
        ("duplicate", vec!["--soname", "liba.so", "--soname=libb.so"]),
        ("empty", vec!["--soname="]),
    ] {
        let output = dir.join(format!("{label}.so"));
        let mut command = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"));
        command.args(["link", "-o"]).arg(&output).arg("--shared");
        command.args(args).arg(&object);
        let result = command.output().unwrap();
        assert!(!result.status.success(), "{label}");
        assert!(result.stdout.is_empty(), "{label}");
        assert!(!output.exists(), "{label}");
    }

    let _ = fs::remove_dir_all(dir);
}
