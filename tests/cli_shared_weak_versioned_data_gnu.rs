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
        "mini-elf-toolchain-weak-versioned-data-{label}-{}-{nonce}",
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

fn provider(dir: &Path, include_value: bool, include_function: bool) -> PathBuf {
    fs::create_dir_all(dir).unwrap();
    let mut source = String::from(".section .note.GNU-stack,\"\",@progbits\n");
    if include_value {
        source.push_str(
            ".data\n.globl provider_value\n.type provider_value,@object\nprovider_value:\n  .quad 0x1122334455667788\n.size provider_value, .-provider_value\n",
        );
    } else {
        source.push_str(
            ".data\n.globl provider_other\n.type provider_other,@object\nprovider_other:\n  .quad 1\n.size provider_other, .-provider_other\n",
        );
    }
    if include_function {
        source.push_str(
            ".text\n.globl provider_function\n.type provider_function,@function\nprovider_function:\n  mov $0x5a, %eax\n  ret\n.size provider_function, .-provider_function\n",
        );
    }
    let object = assemble(dir, "provider", &source);
    let map = dir.join("provider.map");
    fs::write(
        &map,
        "VERS_1 { global: provider_value; provider_other; provider_function; local: *; };\n",
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

fn weak_data_consumer(dir: &Path) -> PathBuf {
    assemble(
        dir,
        "consumer",
        r#".section .note.GNU-stack,"",@progbits
.data
.align 8
.globl weak_value_pointer
.type weak_value_pointer,@object
.weak provider_value
.type provider_value,@object
.symver provider_value,provider_value@VERS_1
weak_value_pointer:
    .quad provider_value
.size weak_value_pointer, .-weak_value_pointer

.text
.globl weak_value_via_got
.type weak_value_via_got,@function
weak_value_via_got:
    mov provider_value@GOTPCREL(%rip), %rax
    ret
.size weak_value_via_got, .-weak_value_via_got
"#,
    )
}

fn version_flags(path: &Path, version: &str) -> String {
    let output = Command::new("readelf")
        .arg("-VW")
        .arg(path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let rendered = String::from_utf8_lossy(&output.stdout);
    rendered
        .lines()
        .find(|line| line.contains("Name:") && line.contains(version))
        .unwrap_or_else(|| panic!("missing version {version} in:\n{rendered}"))
        .to_owned()
}

#[test]
fn weak_named_version_data_matches_gnu_flags_and_zero_or_bind_runtime() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("runtime");
    let link_provider_dir = dir.join("link-provider");
    let runtime_missing_dir = dir.join("runtime-missing");
    let link_provider = provider(&link_provider_dir, true, false);
    let _missing_provider = provider(&runtime_missing_dir, false, false);
    let object = weak_data_consumer(&dir);

    let mini = dir.join("libmini.so");
    let mini_link = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&mini)
        .args(["--shared", "--soname", "libmini.so", "--needed-from"])
        .arg(&link_provider)
        .arg("--runpath")
        .arg(runtime_missing_dir.to_str().unwrap())
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
        .arg(format!("-rpath={}", runtime_missing_dir.to_string_lossy()))
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
        let flags = version_flags(shared, "VERS_1");
        assert!(
            flags.contains("Flags: WEAK"),
            "{label} weak version requirement must carry VER_FLG_WEAK: {flags}"
        );

        let symbols = Command::new("readelf")
            .arg("-sDW")
            .arg(shared)
            .output()
            .unwrap();
        assert!(symbols.status.success());
        let symbols = String::from_utf8_lossy(&symbols.stdout);
        assert!(
            symbols.lines().any(|line| line.contains("WEAK")
                && line.contains("OBJECT")
                && line.contains("UND")
                && line.contains("provider_value@VERS_1")),
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
                && relocations.contains("provider_value@VERS_1"),
            "{label} dynamic relocations:\n{relocations}"
        );
    }

    #[cfg(target_os = "linux")]
    {
        let source = dir.join("runner.c");
        let runner = dir.join("runner");
        fs::write(
            &source,
            r#"#include <dlfcn.h>
#include <stdint.h>

int main(int argc, char **argv) {
    if (argc != 3) return 170;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) return 171;

    uintptr_t *direct = (uintptr_t *)dlsym(handle, "weak_value_pointer");
    uintptr_t (*via_got)(void) =
        (uintptr_t (*)(void))dlsym(handle, "weak_value_via_got");
    if (!direct || !via_got) return 172;

    uintptr_t direct_value = *direct;
    uintptr_t got_value = via_got();
    if (argv[2][0] == '1') {
        if (!direct_value || !got_value) return 173;
        if (direct_value != got_value) return 174;
        if (*(uint64_t *)direct_value != UINT64_C(0x1122334455667788)) return 175;
    } else {
        if (direct_value != 0) return 176;
        if (got_value != 0) return 177;
    }

    return dlclose(handle) == 0 ? 0 : 178;
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
            for (provider_dir, expect_present) in
                [(&link_provider_dir, "1"), (&runtime_missing_dir, "0")]
            {
                let status = Command::new(&runner)
                    .arg(shared)
                    .arg(expect_present)
                    .env("LD_LIBRARY_PATH", provider_dir)
                    .status()
                    .unwrap();
                assert!(
                    status.success(),
                    "weak versioned data runtime returned {status} for {} with provider directory {} and expected-present={expect_present}",
                    shared.display(),
                    provider_dir.display()
                );
            }
        }
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn strong_requirement_dominates_weak_requirement_for_same_version_group() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("mixed-binding");
    let provider = provider(&dir.join("provider"), true, true);
    let object = assemble(
        &dir,
        "mixed-consumer",
        r#".section .note.GNU-stack,"",@progbits
.data
.globl weak_value_pointer
.type weak_value_pointer,@object
.weak provider_value
.type provider_value,@object
.symver provider_value,provider_value@VERS_1
weak_value_pointer:
    .quad provider_value
.size weak_value_pointer, .-weak_value_pointer

.globl strong_function_pointer
.type strong_function_pointer,@object
.globl provider_function
.type provider_function,@function
.symver provider_function,provider_function@VERS_1
strong_function_pointer:
    .quad provider_function
.size strong_function_pointer, .-strong_function_pointer
"#,
    );

    let mini = dir.join("libmini-mixed.so");
    let mini_link = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&mini)
        .args(["--shared", "--needed-from"])
        .arg(&provider)
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        mini_link.status.success(),
        "{}",
        String::from_utf8_lossy(&mini_link.stderr)
    );

    let gnu = dir.join("libgnu-mixed.so");
    let gnu_link = Command::new("ld")
        .args(["-shared", "--hash-style=sysv", "-o"])
        .arg(&gnu)
        .arg(&object)
        .arg(&provider)
        .output()
        .unwrap();
    assert!(
        gnu_link.status.success(),
        "{}",
        String::from_utf8_lossy(&gnu_link.stderr)
    );

    for (label, shared) in [("mini", &mini), ("gnu", &gnu)] {
        let flags = version_flags(shared, "VERS_1");
        assert!(
            !flags.contains("Flags: WEAK"),
            "{label} shared version group has a strong import and must not remain weak: {flags}"
        );
    }

    let _ = fs::remove_dir_all(dir);
}
