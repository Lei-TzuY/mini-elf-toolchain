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
        "mini-elf-toolchain-version-def-{label}-{}-{nonce}",
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

fn versioned_provider_object(dir: &Path, version: &str, value: u64) -> PathBuf {
    assemble(
        dir,
        "provider",
        &format!(
            r#".section .data
.globl provider_impl
.type provider_impl,@object
provider_impl:
    .quad {value}
.size provider_impl, .-provider_impl
.symver provider_impl,provider_value@@{version}
"#
        ),
    )
}

fn versioned_consumer_object(dir: &Path, version: &str) -> PathBuf {
    assemble(
        dir,
        "consumer",
        &format!(
            r#".section .data
.align 8
.globl imported_pointer
.type imported_pointer,@object
.extern provider_value
.type provider_value,@object
.symver provider_value,provider_value@{version}
imported_pointer:
    .quad provider_value
.size imported_pointer, .-imported_pointer
"#
        ),
    )
}

#[test]
fn mini_provider_emits_default_named_version_and_mini_consumer_binds_it() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("roundtrip");
    let provider_object = versioned_provider_object(&dir, "VERS_1", 0x1122334455667788);
    let provider = dir.join("libprovider.so");

    let input_symbols = Command::new("readelf")
        .args(["-sW"])
        .arg(&provider_object)
        .output()
        .unwrap();
    assert!(input_symbols.status.success());
    let input_symbols = String::from_utf8_lossy(&input_symbols.stdout);
    assert!(
        input_symbols.contains("provider_value@@VERS_1"),
        "GNU ET_REL fixture must carry a defined default-version alias: {input_symbols}"
    );

    let provider_link = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&provider)
        .args(["--shared", "--soname", "libprovider.so"])
        .arg(&provider_object)
        .output()
        .unwrap();
    assert!(
        provider_link.status.success(),
        "{}",
        String::from_utf8_lossy(&provider_link.stderr)
    );

    let dynamic = Command::new("readelf")
        .arg("-dW")
        .arg(&provider)
        .output()
        .unwrap();
    assert!(dynamic.status.success());
    let dynamic = String::from_utf8_lossy(&dynamic.stdout);
    assert!(dynamic.contains("VERDEF"), "{dynamic}");
    assert!(dynamic.contains("VERDEFNUM"), "{dynamic}");
    assert!(dynamic.contains("VERSYM"), "{dynamic}");

    let symbols = Command::new("readelf")
        .arg("-sDW")
        .arg(&provider)
        .output()
        .unwrap();
    assert!(
        symbols.status.success(),
        "{}",
        String::from_utf8_lossy(&symbols.stderr)
    );
    let symbols = String::from_utf8_lossy(&symbols.stdout);
    assert!(
        symbols.contains("provider_value@@VERS_1"),
        "producer dynsym must expose the canonical default-version name: {symbols}"
    );

    let definitions = Command::new(env!("CARGO_BIN_EXE_mini-elf-verdef"))
        .arg(&provider)
        .output()
        .unwrap();
    assert!(
        definitions.status.success(),
        "{}",
        String::from_utf8_lossy(&definitions.stderr)
    );
    assert!(
        String::from_utf8_lossy(&definitions.stdout).contains("VERS_1"),
        "{}",
        String::from_utf8_lossy(&definitions.stdout)
    );

    let namespace = Command::new(env!("CARGO_BIN_EXE_mini-elf-vercheck"))
        .arg(&provider)
        .output()
        .unwrap();
    assert!(
        namespace.status.success(),
        "{}",
        String::from_utf8_lossy(&namespace.stderr)
    );
    let namespace = String::from_utf8_lossy(&namespace.stdout);
    assert!(namespace.contains("provider_value"), "{namespace}");
    assert!(namespace.contains("source=definition"), "{namespace}");
    assert!(namespace.contains("version=VERS_1"), "{namespace}");

    let consumer_object = versioned_consumer_object(&dir, "VERS_1");
    let consumer = dir.join("libconsumer.so");
    let consumer_link = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
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
        consumer_link.status.success(),
        "{}",
        String::from_utf8_lossy(&consumer_link.stderr)
    );

    let needed = Command::new(env!("CARGO_BIN_EXE_mini-elf-versym-needed"))
        .arg(&consumer)
        .output()
        .unwrap();
    assert!(
        needed.status.success(),
        "{}",
        String::from_utf8_lossy(&needed.stderr)
    );
    let needed = String::from_utf8_lossy(&needed.stdout);
    assert!(
        needed.contains("requirement=libprovider.so:VERS_1"),
        "{needed}"
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
    if (argc != 2) return 80;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) return 81;
    uint64_t **pointer = (uint64_t **)dlsym(handle, "imported_pointer");
    if (!pointer || !*pointer) return 82;
    if (**pointer != UINT64_C(0x1122334455667788)) return 83;
    return dlclose(handle) == 0 ? 0 : 84;
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
            "version-definition roundtrip returned {status}"
        );
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn local_verdef_and_external_verneed_share_one_noncolliding_namespace() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("mixed-namespace");

    let dependency_object = assemble(
        &dir,
        "dependency",
        r#".section .data
.globl dependency_value
.type dependency_value,@object
dependency_value:
    .quad 0x55aa55aa55aa55aa
.size dependency_value, .-dependency_value
"#,
    );
    let map = dir.join("dependency.map");
    fs::write(
        &map,
        "DEP_1 { global: dependency_value; local: *; };
",
    )
    .unwrap();
    let dependency = dir.join("libdependency.so");
    let gnu_provider = Command::new("ld")
        .args(["-shared", "--hash-style=gnu", "--soname=libdependency.so"])
        .arg(format!("--version-script={}", map.display()))
        .args(["-o"])
        .arg(&dependency)
        .arg(&dependency_object)
        .output()
        .unwrap();
    assert!(
        gnu_provider.status.success(),
        "{}",
        String::from_utf8_lossy(&gnu_provider.stderr)
    );

    let mixed_object = assemble(
        &dir,
        "mixed",
        r#".section .data
.globl local_impl
.type local_impl,@object
local_impl:
    .quad 0x0123456789abcdef
.size local_impl, .-local_impl
.symver local_impl,local_value@@LOCAL_1

.extern dependency_value
.type dependency_value,@object
.symver dependency_value,dependency_value@DEP_1
.globl dependency_pointer
.type dependency_pointer,@object
dependency_pointer:
    .quad dependency_value
.size dependency_pointer, .-dependency_pointer
"#,
    );
    let mixed = dir.join("libmixed.so");
    let link = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&mixed)
        .args(["--shared", "--soname", "libmixed.so"])
        .arg("--needed-from")
        .arg(&dependency)
        .args(["--runpath", "$ORIGIN"])
        .arg(&mixed_object)
        .output()
        .unwrap();
    assert!(
        link.status.success(),
        "{}",
        String::from_utf8_lossy(&link.stderr)
    );

    let check = Command::new(env!("CARGO_BIN_EXE_mini-elf-vercheck"))
        .arg(&mixed)
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "{}",
        String::from_utf8_lossy(&check.stderr)
    );
    let check = String::from_utf8_lossy(&check.stdout);
    assert!(check.contains("source=definition"), "{check}");
    assert!(check.contains("version=LOCAL_1"), "{check}");
    assert!(check.contains("source=requirement"), "{check}");
    assert!(check.contains("dependency=libdependency.so"), "{check}");
    assert!(check.contains("version=DEP_1"), "{check}");

    let symbols = Command::new("readelf")
        .arg("-sDW")
        .arg(&mixed)
        .output()
        .unwrap();
    assert!(symbols.status.success());
    let symbols = String::from_utf8_lossy(&symbols.stdout);
    assert!(symbols.contains("local_value@@LOCAL_1"), "{symbols}");
    assert!(symbols.contains("dependency_value@DEP_1"), "{symbols}");

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn producer_emits_default_and_nondefault_aliases_for_one_dynamic_name() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("dual-alias");
    let provider_object = assemble(
        &dir,
        "dual-provider",
        r#".section .data
.globl old_impl
.type old_impl,@object
old_impl:
    .quad 0x1111222233334444
.size old_impl, .-old_impl
.symver old_impl,provider_value@VERS_1

.globl new_impl
.type new_impl,@object
new_impl:
    .quad 0xaaaabbbbccccdddd
.size new_impl, .-new_impl
.symver new_impl,provider_value@@VERS_2
"#,
    );
    let provider = dir.join("libprovider.so");

    let link = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&provider)
        .args(["--shared", "--soname", "libprovider.so"])
        .arg(&provider_object)
        .output()
        .unwrap();
    assert!(
        link.status.success(),
        "{}",
        String::from_utf8_lossy(&link.stderr)
    );

    let symbols = Command::new("readelf")
        .arg("-sDW")
        .arg(&provider)
        .output()
        .unwrap();
    assert!(symbols.status.success());
    let symbols = String::from_utf8_lossy(&symbols.stdout);
    assert!(symbols.contains("provider_value@VERS_1"), "{symbols}");
    assert!(symbols.contains("provider_value@@VERS_2"), "{symbols}");

    let versions = Command::new(env!("CARGO_BIN_EXE_mini-elf-vercheck"))
        .arg(&provider)
        .output()
        .unwrap();
    assert!(
        versions.status.success(),
        "{}",
        String::from_utf8_lossy(&versions.stderr)
    );
    let versions = String::from_utf8_lossy(&versions.stdout);
    assert!(versions.contains("version=VERS_1"), "{versions}");
    assert!(versions.contains("version=VERS_2"), "{versions}");

    let consumer_object = assemble(
        &dir,
        "dual-consumer",
        r#".section .data
.extern provider_v1
.type provider_v1,@object
.symver provider_v1,provider_value@VERS_1
.globl pointer_v1
.type pointer_v1,@object
pointer_v1:
    .quad provider_v1
.size pointer_v1, .-pointer_v1

.extern provider_v2
.type provider_v2,@object
.symver provider_v2,provider_value@VERS_2
.globl pointer_v2
.type pointer_v2,@object
pointer_v2:
    .quad provider_v2
.size pointer_v2, .-pointer_v2
"#,
    );
    let consumer = dir.join("libconsumer.so");
    let consumer_link = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
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
        consumer_link.status.success(),
        "{}",
        String::from_utf8_lossy(&consumer_link.stderr)
    );

    let requirements = Command::new(env!("CARGO_BIN_EXE_mini-elf-versym-needed"))
        .arg(&consumer)
        .output()
        .unwrap();
    assert!(
        requirements.status.success(),
        "{}",
        String::from_utf8_lossy(&requirements.stderr)
    );
    let requirements = String::from_utf8_lossy(&requirements.stdout);
    assert!(
        requirements.contains("requirement=libprovider.so:VERS_1"),
        "{requirements}"
    );
    assert!(
        requirements.contains("requirement=libprovider.so:VERS_2"),
        "{requirements}"
    );

    #[cfg(target_os = "linux")]
    {
        let source = dir.join("dual-runner.c");
        let runner = dir.join("dual-runner");
        fs::write(
            &source,
            r#"#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>

int main(int argc, char **argv) {
    if (argc != 3) return 90;

    void *provider = dlopen(argv[1], RTLD_NOW | RTLD_GLOBAL);
    if (!provider) return 91;

    uint64_t *default_value = (uint64_t *)dlsym(provider, "provider_value");
    uint64_t *old_value = (uint64_t *)dlvsym(provider, "provider_value", "VERS_1");
    uint64_t *new_value = (uint64_t *)dlvsym(provider, "provider_value", "VERS_2");
    if (!default_value || !old_value || !new_value) return 92;
    if (*default_value != UINT64_C(0xaaaabbbbccccdddd)) return 93;
    if (*old_value != UINT64_C(0x1111222233334444)) return 94;
    if (*new_value != UINT64_C(0xaaaabbbbccccdddd)) return 95;

    void *consumer = dlopen(argv[2], RTLD_NOW | RTLD_LOCAL);
    if (!consumer) return 96;
    uint64_t **pointer_v1 = (uint64_t **)dlsym(consumer, "pointer_v1");
    uint64_t **pointer_v2 = (uint64_t **)dlsym(consumer, "pointer_v2");
    if (!pointer_v1 || !pointer_v2 || !*pointer_v1 || !*pointer_v2) return 97;
    if (**pointer_v1 != UINT64_C(0x1111222233334444)) return 98;
    if (**pointer_v2 != UINT64_C(0xaaaabbbbccccdddd)) return 99;

    if (dlclose(consumer) != 0) return 100;
    return dlclose(provider) == 0 ? 0 : 101;
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
            .arg(&provider)
            .arg(&consumer)
            .status()
            .unwrap();
        assert!(status.success(), "dual-version runtime returned {status}");
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn multiple_default_aliases_for_one_dynamic_name_fail_before_output() {
    if !command_reports("as", "GNU assembler") {
        return;
    }

    let dir = temp_dir("duplicate-default");
    let object = assemble(
        &dir,
        "duplicate-default",
        r#".section .data
.globl first_impl
.type first_impl,@object
first_impl:
    .quad 1
.size first_impl, .-first_impl
.symver first_impl,provider_value@@VERS_1

.globl second_impl
.type second_impl,@object
second_impl:
    .quad 2
.size second_impl, .-second_impl
.symver second_impl,provider_value@@VERS_2
"#,
    );
    let output = dir.join("must-not-exist.so");

    let mini = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&output)
        .arg("--shared")
        .arg(&object)
        .output()
        .unwrap();

    assert!(!mini.status.success());
    assert!(mini.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&mini.stderr);
    assert!(
        stderr.contains("default") || stderr.contains("dynamic name"),
        "{stderr}"
    );
    assert!(!output.exists());

    let _ = fs::remove_dir_all(dir);
}
