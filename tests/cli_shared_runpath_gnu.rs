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
        "mini-elf-toolchain-shared-runpath-{label}-{}-{nonce}",
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
fn shared_runpath_loads_needed_provider_without_ld_library_path() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("runtime");
    let deps = dir.join("deps");
    fs::create_dir_all(&deps).unwrap();

    let provider_object = assemble(
        &dir,
        "provider",
        r#".section .data
.globl provider_value
.type provider_value,@object
provider_value:
    .quad 0x1020304050607080
.size provider_value, .-provider_value

.section .text
.globl provider_function
.type provider_function,@function
provider_function:
    movabs $0x8877665544332211, %rax
    ret
.size provider_function, .-provider_function
"#,
    );
    let provider = deps.join("libprovider.so");
    let provider_link = Command::new("ld")
        .args([
            "-shared",
            "--hash-style=gnu",
            "-soname",
            "libprovider.so",
            "-o",
        ])
        .arg(&provider)
        .arg(&provider_object)
        .output()
        .unwrap();
    assert!(
        provider_link.status.success(),
        "{}",
        String::from_utf8_lossy(&provider_link.stderr)
    );

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

.globl read_provider
.type read_provider,@function
.extern provider_value
.type provider_value,@object
read_provider:
    mov provider_value@GOTPCREL(%rip), %rax
    mov (%rax), %rax
    ret
.size read_provider, .-read_provider
"#,
    );

    let consumer = dir.join("libconsumer.so");
    let mini = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&consumer)
        .arg("--shared")
        .arg("--needed-from")
        .arg(&provider)
        .arg("--runpath")
        .arg("$ORIGIN/deps")
        .arg(&consumer_object)
        .output()
        .unwrap();
    assert!(
        mini.status.success(),
        "{}",
        String::from_utf8_lossy(&mini.stderr)
    );

    let dynamic = Command::new("readelf")
        .args(["-dW"])
        .arg(&consumer)
        .output()
        .unwrap();
    assert!(dynamic.status.success());
    let dynamic = String::from_utf8_lossy(&dynamic.stdout);
    assert!(
        dynamic.contains("Shared library: [libprovider.so]"),
        "{dynamic}"
    );
    assert!(
        dynamic.contains("Library runpath: [$ORIGIN/deps]"),
        "{dynamic}"
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
    if (argc != 2) return 150;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) return 151;
    uint64_t (*call_provider)(void) =
        (uint64_t (*)(void))dlsym(handle, "call_provider");
    uint64_t (*read_provider)(void) =
        (uint64_t (*)(void))dlsym(handle, "read_provider");
    if (!call_provider || !read_provider) return 152;
    if (call_provider() != UINT64_C(0x8877665544332211)) return 153;
    if (read_provider() != UINT64_C(0x1020304050607080)) return 154;
    return dlclose(handle) == 0 ? 0 : 155;
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
            "RUNPATH-backed provider consumer returned {status}"
        );
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn runpath_long_equals_form_is_emitted_exactly() {
    if !command_reports("as", "GNU assembler") || !command_reports("readelf", "GNU readelf") {
        return;
    }

    let dir = temp_dir("equals");
    let object = assemble(
        &dir,
        "export",
        ".text\n.globl answer\n.type answer,@function\nanswer:\n  ret\n.size answer, .-answer\n",
    );
    let output = dir.join("libanswer.so");

    let mini = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&output)
        .arg("--shared")
        .arg("--runpath=$ORIGIN/lib:$ORIGIN/alt")
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
    assert!(
        String::from_utf8_lossy(&dynamic.stdout)
            .contains("Library runpath: [$ORIGIN/lib:$ORIGIN/alt]"),
        "{}",
        String::from_utf8_lossy(&dynamic.stdout)
    );

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn runpath_is_shared_only_and_rejects_empty_or_duplicate_values() {
    let dir = temp_dir("cli");

    for args in [
        vec!["link", "-o", "out", "--runpath", "$ORIGIN/lib", "missing.o"],
        vec!["link", "-o", "out", "--shared", "--runpath=", "missing.o"],
        vec![
            "link",
            "-o",
            "out",
            "--shared",
            "--runpath",
            "$ORIGIN/a",
            "--runpath=$ORIGIN/b",
            "missing.o",
        ],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
            .current_dir(&dir)
            .args(args)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("runpath")
                || String::from_utf8_lossy(&output.stderr).contains("RUNPATH"),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!dir.join("out").exists());
    }

    let _ = fs::remove_dir_all(dir);
}
