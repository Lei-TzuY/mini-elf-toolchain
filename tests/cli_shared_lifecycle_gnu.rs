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
        "mini-elf-toolchain-shared-lifecycle-{label}-{}-{nonce}",
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

fn link_mini_shared(dir: &Path, stem: &str, object: &Path) -> PathBuf {
    let shared = dir.join(stem);
    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&shared)
        .arg("--shared")
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

fn link_gnu_shared(dir: &Path, stem: &str, object: &Path) -> PathBuf {
    let shared = dir.join(stem);
    let output = Command::new("ld")
        .args(["-shared", "--hash-style=sysv", "-o"])
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

fn assert_lifecycle_metadata(shared: &Path) {
    let dynamic = Command::new("readelf")
        .arg("-dW")
        .arg(shared)
        .output()
        .unwrap();
    assert!(
        dynamic.status.success(),
        "{}",
        String::from_utf8_lossy(&dynamic.stderr)
    );
    let dynamic = String::from_utf8_lossy(&dynamic.stdout);
    assert!(dynamic.contains("(INIT_ARRAY)"), "{dynamic}");
    assert!(dynamic.contains("(INIT_ARRAYSZ)"), "{dynamic}");
    assert!(dynamic.contains("(FINI_ARRAY)"), "{dynamic}");
    assert!(dynamic.contains("(FINI_ARRAYSZ)"), "{dynamic}");
    assert!(!dynamic.contains("(PREINIT_ARRAY)"), "{dynamic}");

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
    assert!(inspected.contains("DT_INIT_ARRAY: address="), "{inspected}");
    assert!(inspected.contains("DT_FINI_ARRAY: address="), "{inspected}");
    assert_eq!(inspected.matches("entries=2").count(), 2, "{inspected}");
}

#[test]
fn shared_init_fini_arrays_match_gnu_priority_and_glibc_lifecycle() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("runtime");
    let object = assemble(
        &dir,
        "lifecycle",
        r#".section .note.GNU-stack,"",@progbits

.text
.extern record_event
.type record_event,@function

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

    let mini = link_mini_shared(&dir, "libmini-lifecycle.so", &object);
    let gnu = link_gnu_shared(&dir, "libgnu-lifecycle.so", &object);

    for shared in [&mini, &gnu] {
        assert_lifecycle_metadata(shared);
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
    if (argc != 2) return 180;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        fprintf(stderr, "%s\n", dlerror());
        return 181;
    }
    if (event_count != 2 || events[0] != 100 || events[1] != 200) return 182;
    if (dlclose(handle) != 0) return 183;
    if (event_count != 4 || events[2] != 201 || events[3] != 101) return 184;
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
                "{} lifecycle host returned {status}",
                shared.display()
            );
        }
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn shared_preinit_array_is_rejected_like_gnu() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("preinit");
    let object = assemble(
        &dir,
        "preinit",
        r#".section .note.GNU-stack,"",@progbits
.text
.local preinit_hook
.type preinit_hook,@function
preinit_hook:
    ret
.size preinit_hook, .-preinit_hook

.section .preinit_array,"aw",@preinit_array
.quad preinit_hook
"#,
    );

    let mini = dir.join("libmini-preinit.so");
    let mini_output = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&mini)
        .arg("--shared")
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        !mini_output.status.success(),
        "shared PREINIT_ARRAY must fail closed"
    );
    assert!(
        String::from_utf8_lossy(&mini_output.stderr)
            .to_ascii_lowercase()
            .contains("preinit"),
        "{}",
        String::from_utf8_lossy(&mini_output.stderr)
    );

    let gnu = dir.join("libgnu-preinit.so");
    let gnu_output = Command::new("ld")
        .args(["-shared", "--hash-style=sysv", "-o"])
        .arg(&gnu)
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        !gnu_output.status.success(),
        "GNU ld unexpectedly accepted PREINIT_ARRAY in a DSO"
    );

    let _ = fs::remove_dir_all(dir);
}
