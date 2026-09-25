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
        "mini-elf-toolchain-shared-hooks-{label}-{}-{nonce}",
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

fn link_mini(dir: &Path, object: &Path) -> PathBuf {
    let shared = dir.join("libmini-hooks.so");
    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&shared)
        .arg("--shared")
        .args(["-init", "legacy_init", "-fini", "legacy_fini"])
        .arg(object)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    shared
}

fn link_gnu(dir: &Path, object: &Path) -> PathBuf {
    let shared = dir.join("libgnu-hooks.so");
    let output = Command::new("ld")
        .args([
            "-shared",
            "--hash-style=sysv",
            "-init",
            "legacy_init",
            "-fini",
            "legacy_fini",
            "-o",
        ])
        .arg(&shared)
        .arg(object)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    shared
}

#[test]
fn shared_init_fini_hooks_match_gnu_metadata_and_glibc_ordering() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("runtime");
    let object = assemble(
        &dir,
        "hooks",
        r#".section .note.GNU-stack,"",@progbits

.text
.extern record_event
.type record_event,@function

.globl legacy_init
.type legacy_init,@function
legacy_init:
    sub $8, %rsp
    mov $50, %edi
    call record_event@PLT
    add $8, %rsp
    ret
.size legacy_init, .-legacy_init

.globl legacy_fini
.type legacy_fini,@function
legacy_fini:
    sub $8, %rsp
    mov $250, %edi
    call record_event@PLT
    add $8, %rsp
    ret
.size legacy_fini, .-legacy_fini

.local init_200
.type init_200,@function
init_200:
    sub $8, %rsp
    mov $200, %edi
    call record_event@PLT
    add $8, %rsp
    ret
.size init_200, .-init_200

.local init_100
.type init_100,@function
init_100:
    sub $8, %rsp
    mov $100, %edi
    call record_event@PLT
    add $8, %rsp
    ret
.size init_100, .-init_100

.local fini_100
.type fini_100,@function
fini_100:
    sub $8, %rsp
    mov $101, %edi
    call record_event@PLT
    add $8, %rsp
    ret
.size fini_100, .-fini_100

.local fini_200
.type fini_200,@function
fini_200:
    sub $8, %rsp
    mov $201, %edi
    call record_event@PLT
    add $8, %rsp
    ret
.size fini_200, .-fini_200

.section .init_array.200,"aw",@init_array
.quad init_200
.section .init_array.100,"aw",@init_array
.quad init_100
.section .fini_array.100,"aw",@fini_array
.quad fini_100
.section .fini_array.200,"aw",@fini_array
.quad fini_200
"#,
    );

    let mini = link_mini(&dir, &object);
    let gnu = link_gnu(&dir, &object);

    for shared in [&mini, &gnu] {
        let dynamic = Command::new("readelf")
            .arg("-dW")
            .arg(shared)
            .output()
            .unwrap();
        assert!(dynamic.status.success());
        let dynamic = String::from_utf8_lossy(&dynamic.stdout);
        for fact in ["(INIT)", "(FINI)", "(INIT_ARRAY)", "(FINI_ARRAY)"] {
            assert!(
                dynamic.contains(fact),
                "{} missing {fact}:\n{dynamic}",
                shared.display()
            );
        }

        let inspected = Command::new(env!("CARGO_BIN_EXE_mini-elf-dyninit"))
            .arg(shared)
            .output()
            .unwrap();
        assert!(
            inspected.status.success(),
            "{}",
            String::from_utf8_lossy(&inspected.stderr)
        );
        let inspected = String::from_utf8_lossy(&inspected.stdout);
        assert!(inspected.contains("DT_INIT: address="), "{inspected}");
        assert!(inspected.contains("DT_FINI: address="), "{inspected}");
        assert!(inspected.contains("DT_INIT_ARRAY: address="), "{inspected}");
        assert!(inspected.contains("DT_FINI_ARRAY: address="), "{inspected}");
    }

    #[cfg(target_os = "linux")]
    {
        let host_source = dir.join("host.c");
        let host = dir.join("host");
        fs::write(
            &host_source,
            r#"#include <dlfcn.h>
#include <stddef.h>
#include <stdio.h>

static int events[8];
static size_t event_count;

void record_event(int value) {
    if (event_count < sizeof(events) / sizeof(events[0])) {
        events[event_count++] = value;
    }
}

int main(int argc, char **argv) {
    if (argc != 2) return 190;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        fprintf(stderr, "%s\n", dlerror());
        return 191;
    }
    if (event_count != 3) return 192;
    if (events[0] != 50 || events[1] != 100 || events[2] != 200) return 193;
    if (dlclose(handle) != 0) return 194;
    if (event_count != 6) return 195;
    if (events[3] != 201 || events[4] != 101 || events[5] != 250) return 196;
    return 0;
}
"#,
        )
        .unwrap();

        let compiled = Command::new("cc")
            .args(["-rdynamic", "-o"])
            .arg(&host)
            .arg(&host_source)
            .arg("-ldl")
            .output()
            .unwrap();
        assert!(
            compiled.status.success(),
            "{}",
            String::from_utf8_lossy(&compiled.stderr)
        );

        for shared in [&mini, &gnu] {
            let status = Command::new(&host).arg(shared).status().unwrap();
            assert!(
                status.success(),
                "{} lifecycle hook host returned {status}",
                shared.display()
            );
        }
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn shared_missing_init_hook_fails_before_output() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("missing");
    let object = assemble(
        &dir,
        "missing",
        r#".section .note.GNU-stack,"",@progbits
.text
.globl hook_anchor
.type hook_anchor,@function
hook_anchor:
    ret
.size hook_anchor, .-hook_anchor
"#,
    );
    let shared = dir.join("should-not-exist.so");
    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&shared)
        .arg("--shared")
        .args(["-init", "missing_init"])
        .arg(&object)
        .output()
        .unwrap();

    assert!(!output.status.success(), "missing shared DT_INIT hook was accepted");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("DT_INIT") && stderr.contains("missing_init"),
        "{stderr}"
    );
    assert!(!shared.exists(), "failed hook validation left an output image");

    let _ = fs::remove_dir_all(dir);
}
