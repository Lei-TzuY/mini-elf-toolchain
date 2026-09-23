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
        "mini-elf-toolchain-version-provider-{label}-{}-{nonce}",
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

fn versioned_provider(dir: &Path, stem: &str, source: &str, script: &str, soname: &str) -> PathBuf {
    let object = assemble(dir, stem, source);
    let script_path = dir.join(format!("{stem}.map"));
    fs::write(&script_path, script).unwrap();
    let shared = dir.join(format!("{stem}.so"));
    let output = Command::new("ld")
        .arg("-shared")
        .arg("--hash-style=gnu")
        .arg(format!("--soname={soname}"))
        .arg(format!("--version-script={}", script_path.display()))
        .args(["-o"])
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

fn consumer_object(dir: &Path) -> PathBuf {
    assemble(
        dir,
        "consumer",
        r#".section .data
.align 8
.globl imported_pointer
.type imported_pointer,@object
.extern provider_value
.type provider_value,@object
imported_pointer:
    .quad provider_value
.size imported_pointer, .-imported_pointer
"#,
    )
}

#[test]
fn needed_from_accepts_default_version_export_and_runtime_matches() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("default");
    let provider = versioned_provider(
        &dir,
        "provider",
        r#".section .data
.globl provider_value
.type provider_value,@object
provider_value:
    .quad 0x1122334455667788
.size provider_value, .-provider_value
"#,
        "VERS_1 { global: provider_value; local: *; };\n",
        "libprovider.so",
    );

    let symbols = Command::new("readelf")
        .arg("-sDW")
        .arg(&provider)
        .output()
        .unwrap();
    assert!(symbols.status.success());
    let symbols = String::from_utf8_lossy(&symbols.stdout);
    assert!(
        symbols.contains("provider_value@@VERS_1"),
        "fixture must expose a default GNU symbol version: {symbols}"
    );

    let consumer_object = consumer_object(&dir);
    let consumer = dir.join("libconsumer.so");
    let link = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&consumer)
        .args(["--shared", "--soname", "libconsumer.so"])
        .arg("--needed-from")
        .arg(&provider)
        .args(["--runpath", "$ORIGIN"])
        .arg(&consumer_object)
        .output()
        .unwrap();
    assert!(
        link.status.success(),
        "{}",
        String::from_utf8_lossy(&link.stderr)
    );

    let dynamic = Command::new("readelf")
        .arg("-dW")
        .arg(&consumer)
        .output()
        .unwrap();
    assert!(dynamic.status.success());
    let dynamic = String::from_utf8_lossy(&dynamic.stdout);
    assert!(dynamic.contains("NEEDED") && dynamic.contains("libprovider.so"));

    #[cfg(target_os = "linux")]
    {
        let source = dir.join("runner.c");
        let runner = dir.join("runner");
        fs::write(
            &source,
            r#"#include <dlfcn.h>
#include <stdint.h>

int main(int argc, char **argv) {
    if (argc != 2) return 60;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) return 61;
    uint64_t **pointer = (uint64_t **)dlsym(handle, "imported_pointer");
    if (!pointer) return 62;
    if (!*pointer) return 63;
    if (**pointer != UINT64_C(0x1122334455667788)) return 64;
    return dlclose(handle) == 0 ? 0 : 65;
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
            "versioned-provider dlopen runner returned {status}"
        );
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn needed_from_rejects_nondefault_only_version_for_unversioned_import() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("nondefault");
    let provider = versioned_provider(
        &dir,
        "provider-old",
        r#".section .data
.globl provider_impl
.type provider_impl,@object
provider_impl:
    .quad 7
.size provider_impl, .-provider_impl
.symver provider_impl,provider_value@VERS_1
"#,
        "VERS_1 { global: provider_value; local: *; };\n",
        "libprovider-old.so",
    );

    let symbols = Command::new("readelf")
        .arg("-sDW")
        .arg(&provider)
        .output()
        .unwrap();
    assert!(symbols.status.success());
    let symbols = String::from_utf8_lossy(&symbols.stdout);
    assert!(
        symbols.contains("provider_value@VERS_1") && !symbols.contains("provider_value@@VERS_1"),
        "fixture must expose only a non-default GNU symbol version: {symbols}"
    );

    let consumer_object = consumer_object(&dir);

    let gnu_output = Command::new("ld")
        .args(["-shared", "-z", "defs", "-o"])
        .arg(dir.join("gnu-must-not-link.so"))
        .arg(&consumer_object)
        .arg(&provider)
        .output()
        .unwrap();
    assert!(
        !gnu_output.status.success(),
        "GNU ld unexpectedly satisfied an unversioned import from a non-default-only export"
    );

    let output = dir.join("must-not-exist.so");
    let mini = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&output)
        .arg("--shared")
        .arg("--needed-from")
        .arg(&provider)
        .arg(&consumer_object)
        .output()
        .unwrap();

    assert!(!mini.status.success());
    assert!(mini.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&mini.stderr);
    assert!(
        stderr.contains("exports none") || stderr.contains("bounded external imports"),
        "{stderr}"
    );
    assert!(!output.exists());

    let _ = fs::remove_dir_all(dir);
}
