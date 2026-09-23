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
        && command_reports("ar", "GNU ar")
        && command_reports("readelf", "GNU readelf")
        && command_available("cc")
}

fn temp_dir(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after Unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "mini-elf-toolchain-shared-provider-search-{label}-{}-{nonce}",
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
    basename: &str,
    soname: Option<&str>,
    exported_function: &str,
    exported_object: &str,
) -> PathBuf {
    let source = format!(
        r#".section .data
.globl {exported_object}
.type {exported_object},@object
{exported_object}:
    .quad 0x1122334455667788
.size {exported_object}, .-{exported_object}

.section .text
.globl {exported_function}
.type {exported_function},@function
{exported_function}:
    mov $77, %eax
    ret
.size {exported_function}, .-{exported_function}
"#
    );
    let object = assemble(dir, "provider", &source);
    let provider = dir.join(basename);
    let mut command = Command::new("ld");
    command.args(["-shared", "--hash-style=sysv"]);
    if let Some(soname) = soname {
        command.args(["-soname", soname]);
    }
    let output = command.arg("-o").arg(&provider).arg(&object).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    provider
}

fn build_consumer(dir: &Path, function: &str, object: &str) -> PathBuf {
    let source = format!(
        r#".section .text
.globl call_provider
.type call_provider,@function
.extern {function}
.type {function},@function
call_provider:
    call {function}@PLT
    ret
.size call_provider, .-call_provider

.globl read_provider
.type read_provider,@function
.extern {object}
.type {object},@object
read_provider:
    mov {object}@GOTPCREL(%rip), %rax
    mov (%rax), %rax
    ret
.size read_provider, .-read_provider
"#
    );
    assemble(dir, "consumer", &source)
}

#[test]
fn shared_library_search_infers_checked_provider_soname() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("runtime");
    let libdir = dir.join("lib");
    fs::create_dir_all(&libdir).unwrap();

    let provider = build_provider(
        &libdir,
        "libprovider.so",
        Some("libprovider-abi.so"),
        "provider_func",
        "provider_value",
    );
    fs::copy(&provider, libdir.join("libprovider-abi.so")).unwrap();
    let object = build_consumer(&dir, "provider_func", "provider_value");
    let shared = dir.join("libconsumer.so");

    let mini = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&shared)
        .arg("--shared")
        .arg("-L")
        .arg(&libdir)
        .arg("-lprovider")
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
        dynamic
            .lines()
            .any(|line| line.contains("NEEDED") && line.contains("[libprovider-abi.so]")),
        "{dynamic}"
    );
    assert!(
        !dynamic
            .lines()
            .any(|line| line.contains("NEEDED") && line.contains("[libprovider.so]")),
        "lookup filename must not replace checked SONAME: {dynamic}"
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
    if (argc != 2) return 70;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) return 71;
    int (*call_provider)(void) = (int (*)(void))dlsym(handle, "call_provider");
    uint64_t (*read_provider)(void) =
        (uint64_t (*)(void))dlsym(handle, "read_provider");
    if (!call_provider || !read_provider) return 72;
    if (call_provider() != 77) return 73;
    if (read_provider() != UINT64_C(0x1122334455667788)) return 74;
    return dlclose(handle) == 0 ? 0 : 75;
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
            .env("LD_LIBRARY_PATH", &libdir)
            .status()
            .unwrap();
        assert!(
            status.success(),
            "provider-search dlopen consumer returned {status}"
        );
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn shared_library_search_falls_back_to_static_archive() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("archive-fallback");
    let libdir = dir.join("lib");
    fs::create_dir_all(&libdir).unwrap();

    let member = assemble(
        &dir,
        "archive-member",
        r#".section .text
.globl archived_export
.type archived_export,@function
archived_export:
    mov $9, %eax
    ret
.size archived_export, .-archived_export
"#,
    );
    let archive = libdir.join("libstaticonly.a");
    let ar = Command::new("ar")
        .arg("rcs")
        .arg(&archive)
        .arg(&member)
        .output()
        .unwrap();
    assert!(ar.status.success());

    let output = dir.join("libfallback.so");
    let mini = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&output)
        .arg("--shared")
        .arg("--whole-archive")
        .arg("-L")
        .arg(&libdir)
        .arg("-lstaticonly")
        .arg("--no-whole-archive")
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
        !String::from_utf8_lossy(&dynamic.stdout).contains("NEEDED"),
        "static fallback must not create DT_NEEDED"
    );

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn searched_provider_without_soname_remains_fail_closed() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("no-soname");
    let libdir = dir.join("lib");
    fs::create_dir_all(&libdir).unwrap();
    build_provider(
        &libdir,
        "libprovider.so",
        None,
        "provider_func",
        "provider_value",
    );
    let object = build_consumer(&dir, "provider_func", "provider_value");
    let output = dir.join("must-not-exist.so");

    let mini = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&output)
        .arg("--shared")
        .arg("-L")
        .arg(&libdir)
        .arg("-lprovider")
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
fn malformed_selected_shared_provider_fails_before_output() {
    if !command_reports("as", "GNU assembler") {
        return;
    }

    let dir = temp_dir("malformed");
    let libdir = dir.join("lib");
    fs::create_dir_all(&libdir).unwrap();
    fs::write(libdir.join("libbroken.so"), b"not an ELF provider").unwrap();

    let object = build_consumer(&dir, "provider_func", "provider_value");
    let output = dir.join("must-not-exist.so");
    let mini = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&output)
        .arg("--shared")
        .arg("-L")
        .arg(&libdir)
        .arg("-lbroken")
        .arg(&object)
        .output()
        .unwrap();

    assert!(!mini.status.success());
    assert!(mini.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&mini.stderr);
    assert!(
        stderr.contains("cannot inspect shared dependency provider"),
        "{stderr}"
    );
    assert!(!output.exists());

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn selected_provider_that_satisfies_no_import_fails_before_output() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("unmatched");
    let libdir = dir.join("lib");
    fs::create_dir_all(&libdir).unwrap();
    build_provider(
        &libdir,
        "libprovider.so",
        Some("libprovider.so"),
        "different_func",
        "different_value",
    );
    let object = build_consumer(&dir, "provider_func", "provider_value");
    let output = dir.join("must-not-exist.so");

    let mini = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&output)
        .arg("--shared")
        .arg("-L")
        .arg(&libdir)
        .arg("-lprovider")
        .arg(&object)
        .output()
        .unwrap();

    assert!(!mini.status.success());
    assert!(mini.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&mini.stderr);
    assert!(stderr.contains("exports none"), "{stderr}");
    assert!(!output.exists());

    let _ = fs::remove_dir_all(dir);
}
