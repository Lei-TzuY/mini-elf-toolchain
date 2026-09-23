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
        "mini-elf-toolchain-transitive-version-{label}-{}-{nonce}",
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

fn build_leaf(dir: &Path, version: &str, value: u64) -> PathBuf {
    let object = assemble(
        dir,
        &format!("leaf-{version}"),
        &format!(
            r#".section .data
.globl deep_impl
.type deep_impl,@object
deep_impl:
    .quad {value}
.size deep_impl, .-deep_impl
.symver deep_impl,deep_value@@{version}
"#
        ),
    );
    let leaf = dir.join("libdeep.so");
    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&leaf)
        .args(["--shared", "--soname", "libdeep.so"])
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    leaf
}

fn build_middle(dir: &Path) -> PathBuf {
    let object = assemble(
        dir,
        "middle",
        r#".section .text
.globl middle_anchor
.type middle_anchor,@function
middle_anchor:
    ret
.size middle_anchor, .-middle_anchor
"#,
    );
    let middle = dir.join("libmiddle.so");
    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&middle)
        .args(["--shared", "--soname", "libmiddle.so"])
        .args(["--needed", "libdeep.so"])
        .args(["--runpath", "$ORIGIN"])
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    middle
}

fn consumer_object(dir: &Path) -> PathBuf {
    assemble(
        dir,
        "consumer",
        r#".section .data
.align 8
.globl imported_pointer
.type imported_pointer,@object
.extern deep_value
.type deep_value,@object
.symver deep_value,deep_value@VERS_1
imported_pointer:
    .quad deep_value
.size imported_pointer, .-imported_pointer
"#,
    )
}

#[test]
fn transitive_named_version_provider_keeps_root_needed_and_leaf_verneed() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("runtime");
    let leaf = build_leaf(&dir, "VERS_1", 0x1122334455667788);
    let middle = build_middle(&dir);
    let object = consumer_object(&dir);

    let middle_dynamic = Command::new("readelf")
        .arg("-dW")
        .arg(&middle)
        .output()
        .unwrap();
    assert!(middle_dynamic.status.success());
    let middle_dynamic = String::from_utf8_lossy(&middle_dynamic.stdout);
    assert!(
        middle_dynamic.contains("Shared library: [libdeep.so]"),
        "{middle_dynamic}"
    );

    let leaf_symbols = Command::new("readelf")
        .arg("-sDW")
        .arg(&leaf)
        .output()
        .unwrap();
    assert!(leaf_symbols.status.success());
    assert!(
        String::from_utf8_lossy(&leaf_symbols.stdout).contains("deep_value@@VERS_1"),
        "{}",
        String::from_utf8_lossy(&leaf_symbols.stdout)
    );

    let consumer = dir.join("libconsumer.so");
    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&consumer)
        .args(["--shared", "--soname", "libconsumer.so"])
        .arg("--needed-from")
        .arg(&middle)
        .args(["--runpath", "$ORIGIN"])
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let dynamic = Command::new("readelf")
        .arg("-dW")
        .arg(&consumer)
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
        "consumer must preserve root-only DT_NEEDED metadata: {dynamic}"
    );
    assert!(dynamic.contains("VERNEED"), "{dynamic}");

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
    uint64_t **pointer = (uint64_t **)dlsym(handle, "imported_pointer");
    if (!pointer || !*pointer) return 162;
    if (**pointer != UINT64_C(0x1122334455667788)) return 163;
    return dlclose(handle) == 0 ? 0 : 164;
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
            .arg(&consumer)
            .env("LD_LIBRARY_PATH", &dir)
            .status()
            .unwrap();
        assert!(
            status.success(),
            "transitive named-version consumer returned {status}"
        );
    }

    let versions = Command::new(env!("CARGO_BIN_EXE_mini-elf-versym-needed"))
        .arg(&consumer)
        .output()
        .unwrap();
    assert!(
        versions.status.success(),
        "{}",
        String::from_utf8_lossy(&versions.stderr)
    );
    let versions = String::from_utf8_lossy(&versions.stdout);
    assert!(
        versions.contains("requirement=libdeep.so:VERS_1"),
        "{versions}"
    );

    let hidden_leaf = dir.join("libdeep.hidden");
    fs::rename(&leaf, &hidden_leaf).unwrap();
    let missing_leaf = Command::new(env!("CARGO_BIN_EXE_mini-elf-versym-needed"))
        .arg(&consumer)
        .output()
        .unwrap();
    assert!(!missing_leaf.status.success());
    assert!(missing_leaf.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&missing_leaf.stderr);
    assert!(
        stderr.contains("cannot resolve transitive shared provider dependency")
            || stderr.contains("checked dependency closure"),
        "{stderr}"
    );
    fs::rename(&hidden_leaf, &leaf).unwrap();

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn transitive_named_version_provider_rejects_wrong_leaf_version() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("mismatch");
    let _leaf = build_leaf(&dir, "VERS_2", 7);
    let middle = build_middle(&dir);
    let object = consumer_object(&dir);
    let output = dir.join("must-not-exist.so");

    let mini = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&output)
        .arg("--shared")
        .arg("--needed-from")
        .arg(&middle)
        .arg(&object)
        .output()
        .unwrap();

    assert!(!mini.status.success());
    assert!(mini.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&mini.stderr);
    assert!(
        stderr.contains("VERS_1") || stderr.contains("version"),
        "{stderr}"
    );
    assert!(!output.exists());

    let _ = fs::remove_dir_all(dir);
}
