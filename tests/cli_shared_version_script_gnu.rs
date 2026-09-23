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
        "mini-elf-toolchain-version-script-{label}-{}-{nonce}",
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
fn bounded_version_script_versions_exact_export_and_localizes_rest() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("runtime");
    let object = assemble(
        &dir,
        "provider",
        r#".section .data
.globl public_value
.type public_value,@object
public_value:
    .quad 0x1122334455667788
.size public_value, .-public_value

.globl private_value
.type private_value,@object
private_value:
    .quad 0x8877665544332211
.size private_value, .-private_value
"#,
    );
    let script = dir.join("provider.map");
    fs::write(
        &script,
        "/* bounded producer ABI */
VERS_1 {
  global: public_value;
  local: *;
};
",
    )
    .unwrap();
    let shared = dir.join("libprovider.so");

    let link = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&shared)
        .args(["--shared", "--soname", "libprovider.so", "--version-script"])
        .arg(&script)
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        link.status.success(),
        "{}",
        String::from_utf8_lossy(&link.stderr)
    );

    let symbols = Command::new("readelf")
        .arg("-sDW")
        .arg(&shared)
        .output()
        .unwrap();
    assert!(symbols.status.success());
    let symbols = String::from_utf8_lossy(&symbols.stdout);
    assert!(symbols.contains("public_value@@VERS_1"), "{symbols}");
    assert!(!symbols.contains("private_value"), "{symbols}");

    let versions = Command::new(env!("CARGO_BIN_EXE_mini-elf-vercheck"))
        .arg(&shared)
        .output()
        .unwrap();
    assert!(
        versions.status.success(),
        "{}",
        String::from_utf8_lossy(&versions.stderr)
    );
    let versions = String::from_utf8_lossy(&versions.stdout);
    assert!(versions.contains("source=definition"), "{versions}");
    assert!(versions.contains("version=VERS_1"), "{versions}");

    #[cfg(target_os = "linux")]
    {
        let source = dir.join("runner.c");
        let runner = dir.join("runner");
        fs::write(
            &source,
            r#"#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>

int main(int argc, char **argv) {
    if (argc != 2) return 110;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) return 111;

    uint64_t *plain = (uint64_t *)dlsym(handle, "public_value");
    uint64_t *versioned = (uint64_t *)dlvsym(handle, "public_value", "VERS_1");
    void *hidden = dlsym(handle, "private_value");
    if (!plain || !versioned) return 112;
    if (plain != versioned) return 113;
    if (*plain != UINT64_C(0x1122334455667788)) return 114;
    if (hidden != 0) return 115;

    return dlclose(handle) == 0 ? 0 : 116;
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
        let status = Command::new(&runner).arg(&shared).status().unwrap();
        assert!(status.success(), "version-script runtime returned {status}");
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn bounded_version_script_supports_multiple_independent_versions() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("multiple");
    let object = assemble(
        &dir,
        "provider",
        r#".section .data
.globl old_value
.type old_value,@object
old_value:
    .quad 1
.size old_value, .-old_value

.globl new_value
.type new_value,@object
new_value:
    .quad 2
.size new_value, .-new_value
"#,
    );
    let script = dir.join("provider.map");
    fs::write(
        &script,
        "VERS_1 { global: old_value; };
VERS_2 { global: new_value; local: *; };
",
    )
    .unwrap();
    let shared = dir.join("libprovider.so");

    let link = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&shared)
        .args(["--shared", "--version-script"])
        .arg(&script)
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        link.status.success(),
        "{}",
        String::from_utf8_lossy(&link.stderr)
    );

    let symbols = Command::new("readelf")
        .arg("-sDW")
        .arg(&shared)
        .output()
        .unwrap();
    assert!(symbols.status.success());
    let symbols = String::from_utf8_lossy(&symbols.stdout);
    assert!(symbols.contains("old_value@@VERS_1"), "{symbols}");
    assert!(symbols.contains("new_value@@VERS_2"), "{symbols}");

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn version_script_unknown_symbol_fails_without_output() {
    if !command_reports("as", "GNU assembler") {
        return;
    }

    let dir = temp_dir("unknown");
    let object = assemble(
        &dir,
        "provider",
        ".data
.globl actual_value
actual_value:
  .quad 1
",
    );
    let script = dir.join("provider.map");
    fs::write(&script, "VERS_1 { global: missing_value; local: *; };\n").unwrap();
    let output = dir.join("must-not-exist.so");

    let link = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&output)
        .args(["--shared", "--version-script"])
        .arg(&script)
        .arg(&object)
        .output()
        .unwrap();

    assert!(!link.status.success());
    assert!(link.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&link.stderr);
    assert!(
        stderr.contains("missing_value") && stderr.contains("version"),
        "{stderr}"
    );
    assert!(!output.exists());

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn version_script_inheritance_emits_parent_verdef_and_loads() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("inheritance");
    let object = assemble(
        &dir,
        "provider",
        r#".section .data
.globl old_value
.type old_value,@object
old_value:
    .quad 0x1111222233334444
.size old_value, .-old_value

.globl new_value
.type new_value,@object
new_value:
    .quad 0xaaaabbbbccccdddd
.size new_value, .-new_value
"#,
    );
    let script = dir.join("provider.map");
    fs::write(
        &script,
        "VERS_1 { global: old_value; };\nVERS_2 { global: new_value; local: *; } VERS_1;\n",
    )
    .unwrap();
    let shared = dir.join("libinherit.so");

    let link = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&shared)
        .args(["--shared", "--soname", "libinherit.so", "--version-script"])
        .arg(&script)
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        link.status.success(),
        "{}",
        String::from_utf8_lossy(&link.stderr)
    );

    let dynamic = Command::new("readelf")
        .arg("-dW")
        .arg(&shared)
        .output()
        .unwrap();
    assert!(dynamic.status.success());
    let dynamic = String::from_utf8_lossy(&dynamic.stdout);
    assert!(dynamic.contains("VERDEF"), "{dynamic}");
    assert!(
        dynamic.contains("VERDEFNUM") && dynamic.contains("2"),
        "{dynamic}"
    );
    assert!(dynamic.contains("VERSYM"), "{dynamic}");

    let ours = Command::new(env!("CARGO_BIN_EXE_mini-elf-verdef"))
        .arg(&shared)
        .output()
        .unwrap();
    assert!(
        ours.status.success(),
        "{}",
        String::from_utf8_lossy(&ours.stderr)
    );
    let ours = String::from_utf8_lossy(&ours.stdout);
    assert!(ours.contains("name=VERS_2"), "{ours}");
    assert!(ours.contains("parent=VERS_1"), "{ours}");

    let symbols = Command::new("readelf")
        .arg("-sDW")
        .arg(&shared)
        .output()
        .unwrap();
    assert!(symbols.status.success());
    let symbols = String::from_utf8_lossy(&symbols.stdout);
    assert!(symbols.contains("old_value@@VERS_1"), "{symbols}");
    assert!(symbols.contains("new_value@@VERS_2"), "{symbols}");

    #[cfg(target_os = "linux")]
    {
        let source = dir.join("runner.c");
        let runner = dir.join("runner");
        fs::write(
            &source,
            r#"#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>

int main(int argc, char **argv) {
    if (argc != 2) return 120;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) return 121;
    uint64_t *old_value = (uint64_t *)dlvsym(handle, "old_value", "VERS_1");
    uint64_t *new_value = (uint64_t *)dlvsym(handle, "new_value", "VERS_2");
    if (!old_value || !new_value) return 122;
    if (*old_value != UINT64_C(0x1111222233334444)) return 123;
    if (*new_value != UINT64_C(0xaaaabbbbccccdddd)) return 124;
    return dlclose(handle) == 0 ? 0 : 125;
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
        let status = Command::new(&runner).arg(&shared).status().unwrap();
        assert!(
            status.success(),
            "version-script inheritance runtime returned {status}"
        );
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn invalid_version_script_inheritance_fails_before_input_io() {
    let dir = temp_dir("invalid-inheritance");
    let missing_object = dir.join("missing.o");

    for (label, source, expected) in [
        (
            "unknown",
            "VERS_2 { global: api; } MISSING;\n",
            "undefined parent version",
        ),
        (
            "cycle",
            "VERS_1 { global: old_api; } VERS_2;\nVERS_2 { global: new_api; } VERS_1;\n",
            "cycle",
        ),
    ] {
        let script = dir.join(format!("{label}.map"));
        fs::write(&script, source).unwrap();
        let output = dir.join(format!("{label}.so"));

        let link = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
            .args(["link", "-o"])
            .arg(&output)
            .args(["--shared", "--version-script"])
            .arg(&script)
            .arg(&missing_object)
            .output()
            .unwrap();

        assert!(!link.status.success());
        assert!(link.stdout.is_empty());
        let stderr = String::from_utf8_lossy(&link.stderr);
        assert!(stderr.contains(expected), "{stderr}");
        assert!(!stderr.contains("missing.o"), "{stderr}");
        assert!(!output.exists());
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn version_script_and_explicit_symver_mix_fails_closed() {
    if !command_reports("as", "GNU assembler") {
        return;
    }

    let dir = temp_dir("symver-mix");
    let object = assemble(
        &dir,
        "provider",
        r#".data
.globl impl_value
.type impl_value,@object
impl_value:
    .quad 1
.size impl_value, .-impl_value
.symver impl_value,public_value@@VERS_1
"#,
    );
    let script = dir.join("provider.map");
    fs::write(&script, "VERS_1 { global: public_value; local: *; };\n").unwrap();
    let output = dir.join("must-not-exist.so");

    let link = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&output)
        .args(["--shared", "--version-script"])
        .arg(&script)
        .arg(&object)
        .output()
        .unwrap();

    assert!(!link.status.success());
    assert!(link.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&link.stderr);
    assert!(
        stderr.contains("symver") || stderr.contains("explicit"),
        "{stderr}"
    );
    assert!(!output.exists());

    let _ = fs::remove_dir_all(dir);
}
