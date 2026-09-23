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
        "mini-elf-toolchain-weak-function-address-{label}-{}-{nonce}",
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

fn provider(dir: &Path, include_function: bool) -> PathBuf {
    fs::create_dir_all(dir).unwrap();
    let source = if include_function {
        r#".section .note.GNU-stack,"",@progbits
.text
.globl provider_function
.type provider_function,@function
provider_function:
    mov $0x5a, %eax
    ret
.size provider_function, .-provider_function
"#
    } else {
        r#".section .note.GNU-stack,"",@progbits
.data
.globl provider_other
.type provider_other,@object
provider_other:
    .quad 1
.size provider_other, .-provider_other
"#
    };
    let object = assemble(dir, "provider", source);
    let map = dir.join("provider.map");
    fs::write(
        &map,
        "VERS_1 { global: provider_function; provider_other; local: *; };\n",
    )
    .unwrap();
    let shared = dir.join("libprovider.so");
    let output = Command::new("ld")
        .args(["-shared", "--hash-style=sysv", "--soname=libprovider.so"])
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

fn consumer_object(dir: &Path) -> PathBuf {
    assemble(
        dir,
        "consumer",
        r#".section .note.GNU-stack,"",@progbits
.data
.align 8
.globl imported_function_pointer
.type imported_function_pointer,@object
.weak provider_function
.type provider_function,@function
.symver provider_function,provider_function@VERS_1
imported_function_pointer:
    .quad provider_function
.size imported_function_pointer, .-imported_function_pointer

.text
.globl imported_function_via_got
.type imported_function_via_got,@function
imported_function_via_got:
    mov provider_function@GOTPCREL(%rip), %rax
    ret
.size imported_function_via_got, .-imported_function_via_got
"#,
    )
}

#[test]
fn weak_named_version_function_addresses_match_gnu_and_zero_when_runtime_definition_is_absent() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("runtime");
    let link_provider_dir = dir.join("link-provider");
    let runtime_provider_dir = dir.join("runtime-provider");
    let link_provider = provider(&link_provider_dir, true);
    let _runtime_provider = provider(&runtime_provider_dir, false);
    let object = consumer_object(&dir);

    let input_symbols = Command::new("readelf")
        .args(["-sW"])
        .arg(&object)
        .output()
        .unwrap();
    assert!(input_symbols.status.success());
    let input_symbols = String::from_utf8_lossy(&input_symbols.stdout);
    assert!(
        input_symbols.lines().any(|line| line.contains("WEAK")
            && line.contains("UND")
            && line.contains("provider_function@VERS_1")),
        "{input_symbols}"
    );

    let mini = dir.join("libmini.so");
    let mini_link = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&mini)
        .args(["--shared", "--soname", "libmini.so", "--needed-from"])
        .arg(&link_provider)
        .arg("--runpath")
        .arg(runtime_provider_dir.to_str().unwrap())
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        mini_link.status.success(),
        "{}",
        String::from_utf8_lossy(&mini_link.stderr)
    );

    let gnu = dir.join("libgnu.so");
    let gnu_link = Command::new("ld")
        .args(["-shared", "--hash-style=sysv"])
        .arg(format!("-rpath={}", runtime_provider_dir.to_string_lossy()))
        .args(["-o"])
        .arg(&gnu)
        .arg(&object)
        .arg(&link_provider)
        .output()
        .unwrap();
    assert!(
        gnu_link.status.success(),
        "{}",
        String::from_utf8_lossy(&gnu_link.stderr)
    );

    for (label, shared) in [("mini", &mini), ("gnu", &gnu)] {
        let symbols = Command::new("readelf")
            .arg("-sDW")
            .arg(shared)
            .output()
            .unwrap();
        assert!(symbols.status.success());
        let symbols = String::from_utf8_lossy(&symbols.stdout);
        assert!(
            symbols.lines().any(|line| line.contains("WEAK")
                && line.contains("UND")
                && line.contains("provider_function@VERS_1")),
            "{label} dynamic symbols:\n{symbols}"
        );

        let relocations = Command::new("readelf")
            .args(["-rW", "--use-dynamic"])
            .arg(shared)
            .output()
            .unwrap();
        assert!(relocations.status.success());
        let relocations = String::from_utf8_lossy(&relocations.stdout);
        assert!(
            relocations.contains("R_X86_64_64")
                && relocations.contains("R_X86_64_GLOB_DAT")
                && relocations.contains("provider_function@VERS_1"),
            "{label} dynamic relocations:\n{relocations}"
        );
    }

    let mini_versions = Command::new(env!("CARGO_BIN_EXE_mini-elf-versym-needed"))
        .arg(&mini)
        .output()
        .unwrap();
    assert!(
        mini_versions.status.success(),
        "{}",
        String::from_utf8_lossy(&mini_versions.stderr)
    );
    let mini_versions = String::from_utf8_lossy(&mini_versions.stdout);
    assert!(
        mini_versions.contains("requirement=libprovider.so:VERS_1"),
        "{mini_versions}"
    );

    let gnu_versions = Command::new("readelf")
        .arg("-VW")
        .arg(&gnu)
        .output()
        .unwrap();
    assert!(gnu_versions.status.success());
    let gnu_versions = String::from_utf8_lossy(&gnu_versions.stdout);
    assert!(gnu_versions.contains("libprovider.so"), "{gnu_versions}");
    assert!(gnu_versions.contains("VERS_1"), "{gnu_versions}");

    #[cfg(target_os = "linux")]
    {
        let source = dir.join("runner.c");
        let runner = dir.join("runner");
        fs::write(
            &source,
            r#"#include <dlfcn.h>
#include <stdint.h>

typedef uint64_t (*provider_fn)(void);

int main(int argc, char **argv) {
    if (argc != 2) return 140;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) return 141;

    provider_fn *direct =
        (provider_fn *)dlsym(handle, "imported_function_pointer");
    provider_fn (*via_got)(void) =
        (provider_fn (*)(void))dlsym(handle, "imported_function_via_got");
    if (!direct || !via_got) return 142;

    if (*direct != 0) return 143;
    if (via_got() != 0) return 144;

    return dlclose(handle) == 0 ? 0 : 145;
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

        for shared in [&mini, &gnu] {
            let status = Command::new(&runner).arg(shared).status().unwrap();
            assert!(
                status.success(),
                "weak function-address runtime returned {status} for {}",
                shared.display()
            );
        }
    }

    let _ = fs::remove_dir_all(dir);
}
