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
        "mini-elf-toolchain-transitive-provider-{label}-{}-{nonce}",
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

struct Fixture {
    middle: PathBuf,
    deep: PathBuf,
    consumer: PathBuf,
}

fn build_fixture(dir: &Path) -> Fixture {
    let deep_object = assemble(
        dir,
        "deep",
        r#".section .data
.globl deep_value
.type deep_value,@object
deep_value:
    .quad 0x1020304050607080
.size deep_value, .-deep_value

.section .text
.globl deep_function
.type deep_function,@function
deep_function:
    movabs $0x8877665544332211, %rax
    ret
.size deep_function, .-deep_function
"#,
    );
    let deep = dir.join("libdeep.so");
    let deep_link = Command::new("ld")
        .args(["-shared", "--hash-style=gnu", "-soname", "libdeep.so", "-o"])
        .arg(&deep)
        .arg(&deep_object)
        .output()
        .unwrap();
    assert!(
        deep_link.status.success(),
        "{}",
        String::from_utf8_lossy(&deep_link.stderr)
    );

    let middle_object = assemble(
        dir,
        "middle",
        r#".section .text
.globl middle_anchor
.type middle_anchor,@function
.extern deep_function
.type deep_function,@function
middle_anchor:
    jmp deep_function@PLT
.size middle_anchor, .-middle_anchor
"#,
    );
    let middle = dir.join("libmiddle.so");
    let middle_link = Command::new("ld")
        .args([
            "-shared",
            "--hash-style=gnu",
            "-soname",
            "libmiddle.so",
            "-o",
        ])
        .arg(&middle)
        .arg(&middle_object)
        .arg("-L")
        .arg(dir)
        .arg("-ldeep")
        .output()
        .unwrap();
    assert!(
        middle_link.status.success(),
        "{}",
        String::from_utf8_lossy(&middle_link.stderr)
    );

    let middle_dynamic = Command::new("readelf")
        .args(["-dW"])
        .arg(&middle)
        .output()
        .unwrap();
    assert!(middle_dynamic.status.success());
    assert!(
        String::from_utf8_lossy(&middle_dynamic.stdout).contains("Shared library: [libdeep.so]"),
        "{}",
        String::from_utf8_lossy(&middle_dynamic.stdout)
    );

    let consumer = assemble(
        dir,
        "consumer",
        r#".section .text
.globl call_deep
.type call_deep,@function
.extern deep_function
.type deep_function,@function
call_deep:
    call deep_function@PLT
    ret
.size call_deep, .-call_deep

.globl read_deep
.type read_deep,@function
.extern deep_value
.type deep_value,@object
read_deep:
    mov deep_value@GOTPCREL(%rip), %rax
    mov (%rax), %rax
    ret
.size read_deep, .-read_deep
"#,
    );

    Fixture {
        middle,
        deep,
        consumer,
    }
}

#[test]
fn needed_from_matches_imports_through_transitive_provider_dependency() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("runtime");
    let fixture = build_fixture(&dir);
    let output = dir.join("libconsumer.so");

    let mini = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&output)
        .arg("--shared")
        .arg("--needed-from")
        .arg(&fixture.middle)
        .arg(&fixture.consumer)
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
    assert!(
        dynamic.contains("Shared library: [libmiddle.so]"),
        "{dynamic}"
    );
    assert!(
        !dynamic.contains("Shared library: [libdeep.so]"),
        "consumer must record only the direct provider dependency: {dynamic}"
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
    if (argc != 2) return 130;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) return 131;
    uint64_t (*call_deep)(void) =
        (uint64_t (*)(void))dlsym(handle, "call_deep");
    uint64_t (*read_deep)(void) =
        (uint64_t (*)(void))dlsym(handle, "read_deep");
    if (!call_deep || !read_deep) return 132;
    if (call_deep() != UINT64_C(0x8877665544332211)) return 133;
    if (read_deep() != UINT64_C(0x1020304050607080)) return 134;
    return dlclose(handle) == 0 ? 0 : 135;
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
            .arg(&output)
            .env("LD_LIBRARY_PATH", &dir)
            .status()
            .unwrap();
        assert!(
            status.success(),
            "transitive-provider consumer returned {status}"
        );
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn missing_transitive_provider_dependency_fails_before_output() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("missing");
    let fixture = build_fixture(&dir);
    fs::remove_file(&fixture.deep).unwrap();
    let output = dir.join("must-not-exist.so");

    let mini = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&output)
        .arg("--shared")
        .arg("--needed-from")
        .arg(&fixture.middle)
        .arg(&fixture.consumer)
        .output()
        .unwrap();

    assert!(!mini.status.success());
    assert!(mini.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&mini.stderr);
    assert!(
        stderr.contains("libdeep.so") && stderr.contains("transitive"),
        "{stderr}"
    );
    assert!(!output.exists());

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn transitive_provider_search_uses_shared_library_paths() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("search-path");
    let dependency_dir = dir.join("deps");
    fs::create_dir_all(&dependency_dir).unwrap();
    let fixture = build_fixture(&dir);
    let moved_deep = dependency_dir.join("libdeep.so");
    fs::rename(&fixture.deep, &moved_deep).unwrap();
    let output = dir.join("libconsumer.so");

    let mini = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&output)
        .arg("--shared")
        .arg("--needed-from")
        .arg(&fixture.middle)
        .arg("-L")
        .arg(&dependency_dir)
        .arg(&fixture.consumer)
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
    assert!(
        dynamic.contains("Shared library: [libmiddle.so]"),
        "{dynamic}"
    );
    assert!(
        !dynamic.contains("Shared library: [libdeep.so]"),
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
    if (argc != 2) return 140;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) return 141;
    uint64_t (*call_deep)(void) =
        (uint64_t (*)(void))dlsym(handle, "call_deep");
    if (!call_deep) return 142;
    if (call_deep() != UINT64_C(0x8877665544332211)) return 143;
    return dlclose(handle) == 0 ? 0 : 144;
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

        let library_path = std::env::join_paths([dir.as_path(), dependency_dir.as_path()]).unwrap();
        let status = Command::new(&runner)
            .arg(&output)
            .env("LD_LIBRARY_PATH", library_path)
            .status()
            .unwrap();
        assert!(
            status.success(),
            "search-path transitive-provider consumer returned {status}"
        );
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn transitive_provider_cycles_terminate_without_output() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("cycle");
    let a_stub = assemble(
        &dir,
        "a-stub",
        r#".section .text
.globl a_anchor
.type a_anchor,@function
a_anchor:
    ret
.size a_anchor, .-a_anchor
"#,
    );
    let a_path = dir.join("libcyclea.so");
    let a_stub_link = Command::new("ld")
        .args([
            "-shared",
            "--hash-style=gnu",
            "-soname",
            "libcyclea.so",
            "-o",
        ])
        .arg(&a_path)
        .arg(&a_stub)
        .output()
        .unwrap();
    assert!(
        a_stub_link.status.success(),
        "{}",
        String::from_utf8_lossy(&a_stub_link.stderr)
    );

    let b_object = assemble(
        &dir,
        "cycle-b",
        r#".section .text
.globl b_anchor
.type b_anchor,@function
.extern a_anchor
.type a_anchor,@function
b_anchor:
    jmp a_anchor@PLT
.size b_anchor, .-b_anchor
"#,
    );
    let b_path = dir.join("libcycleb.so");
    let b_link = Command::new("ld")
        .args([
            "-shared",
            "--hash-style=gnu",
            "-soname",
            "libcycleb.so",
            "-o",
        ])
        .arg(&b_path)
        .arg(&b_object)
        .arg("-L")
        .arg(&dir)
        .arg("-lcyclea")
        .output()
        .unwrap();
    assert!(
        b_link.status.success(),
        "{}",
        String::from_utf8_lossy(&b_link.stderr)
    );

    let a_object = assemble(
        &dir,
        "cycle-a",
        r#".section .text
.globl a_anchor
.type a_anchor,@function
.extern b_anchor
.type b_anchor,@function
a_anchor:
    jmp b_anchor@PLT
.size a_anchor, .-a_anchor
"#,
    );
    let a_link = Command::new("ld")
        .args([
            "-shared",
            "--hash-style=gnu",
            "-soname",
            "libcyclea.so",
            "-o",
        ])
        .arg(&a_path)
        .arg(&a_object)
        .arg("-L")
        .arg(&dir)
        .arg("-lcycleb")
        .output()
        .unwrap();
    assert!(
        a_link.status.success(),
        "{}",
        String::from_utf8_lossy(&a_link.stderr)
    );

    let consumer = assemble(
        &dir,
        "cycle-consumer",
        r#".section .text
.globl call_missing
.type call_missing,@function
.extern missing_function
.type missing_function,@function
call_missing:
    call missing_function@PLT
    ret
.size call_missing, .-call_missing
"#,
    );
    let output = dir.join("must-not-exist.so");

    let mini = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&output)
        .arg("--shared")
        .arg("--needed-from")
        .arg(&a_path)
        .arg(&consumer)
        .output()
        .unwrap();

    assert!(!mini.status.success());
    assert!(mini.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&mini.stderr);
    assert!(
        stderr.contains("transitive dependency closure") && stderr.contains("libcyclea.so"),
        "{stderr}"
    );
    assert!(!output.exists());

    let _ = fs::remove_dir_all(dir);
}
