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
        "mini-elf-toolchain-shared-needed-provider-{label}-{}-{nonce}",
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

fn build_provider(
    dir: &Path,
    stem: &str,
    file_name: &str,
    soname: Option<&str>,
    symbol: &str,
) -> PathBuf {
    let object = assemble(
        dir,
        stem,
        &format!(
            ".section .text\n.globl {symbol}\n.type {symbol},@function\n{symbol}:\n    lea 2(%rdi), %rax\n    ret\n.size {symbol}, .-{symbol}\n"
        ),
    );
    let shared = dir.join(file_name);
    let mut command = Command::new("ld");
    command.args(["-shared", "--hash-style=sysv"]);
    if let Some(soname) = soname {
        command.args(["-soname", soname]);
    }
    let output = command
        .arg("-o")
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
        "consumer",
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
fn needed_from_infers_checked_soname_and_loads_provider() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("runtime");
    let provider = build_provider(
        &dir,
        "provider",
        "provider-build-name.so",
        Some("libprovider-public.so"),
        "provider_function",
    );
    let object = build_consumer_object(&dir);
    let shared = dir.join("libconsumer.so");

    let mini = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&shared)
        .arg("--shared")
        .arg("--needed-from")
        .arg(&provider)
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
        dynamic.contains("Shared library: [libprovider-public.so]"),
        "{dynamic}"
    );
    assert!(
        !dynamic.contains("provider-build-name.so"),
        "dependency must use checked SONAME rather than provider pathname: {dynamic}"
    );

    fs::rename(&provider, dir.join("libprovider-public.so")).unwrap();

    #[cfg(target_os = "linux")]
    {
        let source = dir.join("runner.c");
        let runner = dir.join("runner");
        fs::write(
            &source,
            r#"#include <dlfcn.h>
#include <stdint.h>

int main(int argc, char **argv) {
    if (argc != 2) return 110;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) return 111;
    uint64_t (*call_provider)(void) =
        (uint64_t (*)(void))dlsym(handle, "call_provider");
    if (!call_provider) return 112;
    if (call_provider() != UINT64_C(42)) return 113;
    return dlclose(handle) == 0 ? 0 : 114;
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
            "provider-aware DT_NEEDED consumer returned {status}"
        );
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn needed_from_rejects_provider_without_soname() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("no-soname");
    let provider = build_provider(
        &dir,
        "provider",
        "libprovider-no-soname.so",
        None,
        "provider_function",
    );
    let object = build_consumer_object(&dir);
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
    assert!(
        String::from_utf8_lossy(&mini.stderr).contains("DT_SONAME"),
        "{}",
        String::from_utf8_lossy(&mini.stderr)
    );
    assert!(!output.exists());

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn needed_from_rejects_provider_that_satisfies_no_consumer_import() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("unrelated");
    let provider = build_provider(
        &dir,
        "provider",
        "libunrelated.so",
        Some("libunrelated.so"),
        "different_function",
    );
    let object = build_consumer_object(&dir);
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
        stderr.contains("exports none") && stderr.contains("libunrelated.so"),
        "{stderr}"
    );
    assert!(!output.exists());

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn needed_from_rejects_malformed_provider_before_output() {
    if !command_available(env!("CARGO_BIN_EXE_mini-elf-toolchain")) {
        return;
    }

    let dir = temp_dir("malformed");
    let provider = dir.join("bad-provider.so");
    fs::write(&provider, b"not an ELF shared object").unwrap();
    let object = if command_reports("as", "GNU assembler") {
        build_consumer_object(&dir)
    } else {
        let object = dir.join("consumer.o");
        fs::write(&object, b"also not an object").unwrap();
        object
    };
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
    assert!(
        String::from_utf8_lossy(&mini.stderr).contains("cannot inspect shared dependency provider"),
        "{}",
        String::from_utf8_lossy(&mini.stderr)
    );
    assert!(!output.exists());

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn needed_from_is_shared_only() {
    let dir = temp_dir("cli");
    let output = dir.join("out");
    let provider = dir.join("provider.so");

    let result = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&output)
        .arg("--needed-from")
        .arg(&provider)
        .arg("missing.o")
        .output()
        .unwrap();

    assert_eq!(result.status.code(), Some(2));
    assert!(result.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&result.stderr)
            .contains("--needed-from is only supported with --shared")
    );
    assert!(!output.exists());

    let _ = fs::remove_dir_all(dir);
}
