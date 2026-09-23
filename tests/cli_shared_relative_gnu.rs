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

fn have_tools() -> bool {
    command_reports("as", "GNU assembler")
        && command_reports("readelf", "GNU readelf")
        && command_reports("cc", "gcc")
}

fn temp_dir(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after Unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "mini-elf-toolchain-shared-relative-{label}-{}-{nonce}",
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
fn shared_object_emits_loader_applied_relative_relocation_for_local_target() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("local");
    let object = assemble(
        &dir,
        "relative",
        r#".section .rodata
.align 8
.local target_value
.type target_value,@object
target_value:
    .quad 0x1122334455667788
.size target_value, .-target_value

.section .data
.align 8
.globl exported_pointer
.type exported_pointer,@object
exported_pointer:
    .quad target_value
.size exported_pointer, .-exported_pointer
"#,
    );

    let input_relocations = Command::new("readelf")
        .args(["-rW"])
        .arg(&object)
        .output()
        .unwrap();
    assert!(input_relocations.status.success());
    let input_relocations = String::from_utf8_lossy(&input_relocations.stdout);
    assert!(
        input_relocations.contains("R_X86_64_64"),
        "fixture must carry a real absolute relocation: {input_relocations}"
    );

    let shared = dir.join("librelative.so");
    let mini = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "--shared", "-o"])
        .arg(&shared)
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
    assert!(dynamic.contains("(RELA)"), "{dynamic}");
    assert!(dynamic.contains("(RELASZ)"), "{dynamic}");
    assert!(dynamic.contains("(RELAENT)"), "{dynamic}");
    assert!(dynamic.contains("(RELACOUNT)"), "{dynamic}");

    let relocations = Command::new("readelf")
        .args(["-rW", "--use-dynamic"])
        .arg(&shared)
        .output()
        .unwrap();
    assert!(relocations.status.success());
    let relocations = String::from_utf8_lossy(&relocations.stdout);
    assert!(
        relocations.contains("R_X86_64_RELATIVE"),
        "generated DSO must expose a loader-applied relative relocation: {relocations}"
    );
    assert!(
        !relocations.contains("target_value"),
        "relative relocation must not carry a dynamic symbol dependency: {relocations}"
    );

    #[cfg(target_os = "linux")]
    {
        let source = dir.join("consumer.c");
        let consumer = dir.join("consumer");
        fs::write(
            &source,
            r#"#include <dlfcn.h>
#include <stdint.h>

int main(int argc, char **argv) {
    if (argc != 2) return 20;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) return 21;
    uint64_t **pointer = (uint64_t **)dlsym(handle, "exported_pointer");
    if (!pointer) return 22;
    if (!*pointer) return 23;
    if (**pointer != UINT64_C(0x1122334455667788)) return 24;
    if (dlsym(handle, "target_value") != 0) return 25;
    return dlclose(handle) == 0 ? 0 : 26;
}
"#,
        )
        .unwrap();
        let compile = Command::new("cc")
            .arg("-o")
            .arg(&consumer)
            .arg(&source)
            .arg("-ldl")
            .output()
            .unwrap();
        assert!(
            compile.status.success(),
            "{}",
            String::from_utf8_lossy(&compile.stderr)
        );

        let status = Command::new(&consumer).arg(&shared).status().unwrap();
        assert!(
            status.success(),
            "dlopen relative-relocation consumer returned {status}"
        );
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn shared_relative_relocation_rejects_default_visible_global_target() {
    if !command_reports("as", "GNU assembler") {
        return;
    }

    let dir = temp_dir("preemptible");
    let object = assemble(
        &dir,
        "preemptible",
        r#".section .rodata
.globl target_value
.type target_value,@object
target_value:
    .quad 7
.size target_value, .-target_value

.section .data
.globl exported_pointer
.type exported_pointer,@object
exported_pointer:
    .quad target_value
.size exported_pointer, .-exported_pointer
"#,
    );
    let output = dir.join("must-not-exist.so");

    let mini = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "--shared", "-o"])
        .arg(&output)
        .arg(&object)
        .output()
        .unwrap();

    assert!(!mini.status.success());
    assert!(mini.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&mini.stderr);
    assert!(
        stderr.contains("preempt") || stderr.contains("interposition"),
        "{stderr}"
    );
    assert!(!output.exists());

    let _ = fs::remove_dir_all(dir);
}
