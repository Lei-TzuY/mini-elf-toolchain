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
        "mini-elf-toolchain-versioned-import-{label}-{}-{nonce}",
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

fn provider(dir: &Path, version: &str, value: u64) -> PathBuf {
    let object = assemble(
        dir,
        &format!("provider-{version}"),
        &format!(
            ".section .data\n.globl provider_value\n.type provider_value,@object\nprovider_value:\n  .quad {value}\n.size provider_value, .-provider_value\n"
        ),
    );
    let map = dir.join(format!("provider-{version}.map"));
    fs::write(
        &map,
        format!("{version} {{ global: provider_value; local: *; }};\n"),
    )
    .unwrap();
    let soname = "libprovider.so";
    let shared = dir.join(soname);
    let output = Command::new("ld")
        .arg("-shared")
        .arg("--hash-style=gnu")
        .arg(format!("--soname={soname}"))
        .arg(format!("--version-script={}", map.display()))
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

fn versioned_consumer_object(dir: &Path) -> PathBuf {
    assemble(
        dir,
        "consumer",
        r#".section .data
.align 8
.globl imported_pointer
.type imported_pointer,@object
.extern provider_value
.type provider_value,@object
.symver provider_value,provider_value@VERS_1
imported_pointer:
    .quad provider_value
.size imported_pointer, .-imported_pointer
"#,
    )
}

#[test]
fn shared_named_version_import_emits_verneed_and_loads_requested_provider_version() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("runtime");
    let provider = provider(&dir, "VERS_1", 0x1122334455667788);
    let object = versioned_consumer_object(&dir);

    let input_symbols = Command::new("readelf")
        .args(["-sW"])
        .arg(&object)
        .output()
        .unwrap();
    assert!(input_symbols.status.success());
    let input_symbols = String::from_utf8_lossy(&input_symbols.stdout);
    assert!(
        input_symbols.contains("provider_value@VERS_1"),
        "GNU ET_REL fixture must carry a version-qualified undefined symbol: {input_symbols}"
    );

    let consumer = dir.join("libconsumer.so");
    let mini = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&consumer)
        .args(["--shared", "--soname", "libconsumer.so"])
        .arg("--needed-from")
        .arg(&provider)
        .args(["--runpath", "$ORIGIN"])
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        mini.status.success(),
        "{}",
        String::from_utf8_lossy(&mini.stderr)
    );

    let dynamic = Command::new("readelf")
        .arg("-dW")
        .arg(&consumer)
        .output()
        .unwrap();
    assert!(dynamic.status.success());
    let dynamic = String::from_utf8_lossy(&dynamic.stdout);
    assert!(dynamic.contains("VERNEED"), "{dynamic}");
    assert!(dynamic.contains("VERNEEDNUM"), "{dynamic}");

    let gnu_versions = Command::new("readelf")
        .arg("-VW")
        .arg(&consumer)
        .output()
        .unwrap();
    assert!(
        gnu_versions.status.success(),
        "{}",
        String::from_utf8_lossy(&gnu_versions.stderr)
    );
    let gnu_versions = String::from_utf8_lossy(&gnu_versions.stdout);
    assert!(gnu_versions.contains("libprovider.so"), "{gnu_versions}");
    assert!(gnu_versions.contains("VERS_1"), "{gnu_versions}");

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
        versions.contains("requirement=libprovider.so:VERS_1"),
        "{versions}"
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
    uint64_t **pointer = (uint64_t **)dlsym(handle, "imported_pointer");
    if (!pointer) return 72;
    if (!*pointer) return 73;
    if (**pointer != UINT64_C(0x1122334455667788)) return 74;
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
        let status = Command::new(&runner).arg(&consumer).status().unwrap();
        assert!(
            status.success(),
            "versioned consumer dlopen runner returned {status}"
        );
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn shared_named_version_import_rejects_provider_with_different_version() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("mismatch");
    let provider = provider(&dir, "VERS_2", 7);
    let object = versioned_consumer_object(&dir);

    let gnu = Command::new("ld")
        .args(["-shared", "-z", "defs", "-o"])
        .arg(dir.join("gnu-must-not-link.so"))
        .arg(&object)
        .arg(&provider)
        .output()
        .unwrap();
    assert!(
        !gnu.status.success(),
        "GNU ld unexpectedly satisfied provider_value@VERS_1 from a VERS_2-only provider"
    );

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
        stderr.contains("VERS_1") || stderr.contains("version"),
        "{stderr}"
    );
    assert!(!output.exists());

    let _ = fs::remove_dir_all(dir);
}
