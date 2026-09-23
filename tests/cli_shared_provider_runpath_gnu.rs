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
        "mini-elf-toolchain-provider-runpath-{label}-{}-{nonce}",
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
    consumer: PathBuf,
}

fn build_fixture(dir: &Path, middle_runpath: &str) -> Fixture {
    let deps = dir.join("deps");
    fs::create_dir_all(&deps).unwrap();

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
    let deep = deps.join("libdeep.so");
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
            "-rpath",
            middle_runpath,
            "-o",
        ])
        .arg(&middle)
        .arg(&middle_object)
        .arg("-L")
        .arg(&deps)
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
    let middle_dynamic = String::from_utf8_lossy(&middle_dynamic.stdout);
    assert!(
        middle_dynamic.contains("Shared library: [libdeep.so]"),
        "{middle_dynamic}"
    );
    assert!(
        middle_dynamic.contains("Library runpath:"),
        "{middle_dynamic}"
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

    Fixture { middle, consumer }
}

#[test]
fn transitive_provider_closure_uses_parent_origin_runpath_and_runtime_matches() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("origin");
    let fixture = build_fixture(&dir, "$ORIGIN/deps");
    let output = dir.join("libconsumer.so");

    let mini = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&output)
        .arg("--shared")
        .arg("--needed-from")
        .arg(&fixture.middle)
        .arg("--runpath")
        .arg("$ORIGIN")
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
        "consumer must retain only the selected root provider dependency: {dynamic}"
    );
    assert!(dynamic.contains("Library runpath: [$ORIGIN]"), "{dynamic}");

    #[cfg(target_os = "linux")]
    {
        let source = dir.join("runner.c");
        let runner = dir.join("runner");
        fs::write(
            &source,
            r#"#include <dlfcn.h>
#include <stdint.h>

int main(int argc, char **argv) {
    if (argc != 2) return 160;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) return 161;
    uint64_t (*call_deep)(void) =
        (uint64_t (*)(void))dlsym(handle, "call_deep");
    uint64_t (*read_deep)(void) =
        (uint64_t (*)(void))dlsym(handle, "read_deep");
    if (!call_deep || !read_deep) return 162;
    if (call_deep() != UINT64_C(0x8877665544332211)) return 163;
    if (read_deep() != UINT64_C(0x1020304050607080)) return 164;
    return dlclose(handle) == 0 ? 0 : 165;
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

        let status = Command::new(&runner).arg(&output).status().unwrap();
        assert!(
            status.success(),
            "provider-RUNPATH consumer returned {status}"
        );
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn unsupported_provider_runpath_token_fails_before_output() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("unsupported-token");
    let fixture = build_fixture(&dir, "$LIB");
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
        stderr.contains("DT_RUNPATH")
            && stderr.contains("unsupported loader token")
            && stderr.contains("$ORIGIN"),
        "{stderr}"
    );
    assert!(!output.exists());

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn relative_provider_runpath_fails_before_output() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("relative");
    let fixture = build_fixture(&dir, "deps");
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
        stderr.contains("DT_RUNPATH") && stderr.contains("relative") && stderr.contains("$ORIGIN"),
        "{stderr}"
    );
    assert!(!output.exists());

    let _ = fs::remove_dir_all(dir);
}
