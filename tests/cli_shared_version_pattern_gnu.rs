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
        "mini-elf-toolchain-version-pattern-{label}-{}-{nonce}",
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

fn dynamic_symbols(path: &Path) -> String {
    let output = Command::new("readelf")
        .arg("-sDW")
        .arg(path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn prefix_patterns_match_gnu_and_keep_unmatched_parent_version_node() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("prefix");
    let object = assemble(
        &dir,
        "provider",
        r#".section .data
.globl api_alpha
.type api_alpha,@object
api_alpha:
    .quad 0x1111222233334444
.size api_alpha, .-api_alpha

.globl api_beta
.type api_beta,@object
api_beta:
    .quad 0xaaaabbbbccccdddd
.size api_beta, .-api_beta

.globl private_value
.type private_value,@object
private_value:
    .quad 0x5555666677778888
.size private_value, .-private_value
"#,
    );
    let script = dir.join("provider.map");
    fs::write(
        &script,
        "BASE { global: legacy_*; };\nVERS_2 { global: api_*; local: *; } BASE;\n",
    )
    .unwrap();

    let mini = dir.join("libmini.so");
    let mini_link = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&mini)
        .args(["--shared", "--soname", "libmini.so", "--version-script"])
        .arg(&script)
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
        .args(["-shared", "--hash-style=sysv", "--soname=libgnu.so"])
        .arg(format!("--version-script={}", script.display()))
        .args(["-o"])
        .arg(&gnu)
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        gnu_link.status.success(),
        "{}",
        String::from_utf8_lossy(&gnu_link.stderr)
    );

    for symbols in [dynamic_symbols(&mini), dynamic_symbols(&gnu)] {
        assert!(symbols.contains("api_alpha@@VERS_2"), "{symbols}");
        assert!(symbols.contains("api_beta@@VERS_2"), "{symbols}");
        assert!(!symbols.contains("private_value"), "{symbols}");
    }

    let definitions = Command::new(env!("CARGO_BIN_EXE_mini-elf-verdef"))
        .arg(&mini)
        .output()
        .unwrap();
    assert!(
        definitions.status.success(),
        "{}",
        String::from_utf8_lossy(&definitions.stderr)
    );
    let definitions = String::from_utf8_lossy(&definitions.stdout);
    assert!(definitions.contains("name=BASE"), "{definitions}");
    assert!(definitions.contains("name=VERS_2"), "{definitions}");
    assert!(definitions.contains("parent=BASE"), "{definitions}");

    let gnu_versions = Command::new("readelf")
        .arg("-VW")
        .arg(&gnu)
        .output()
        .unwrap();
    assert!(gnu_versions.status.success());
    let gnu_versions = String::from_utf8_lossy(&gnu_versions.stdout);
    assert!(gnu_versions.contains("Parent 1: BASE"), "{gnu_versions}");

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
    if (argc != 2) return 130;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) return 131;
    uint64_t *alpha = (uint64_t *)dlvsym(handle, "api_alpha", "VERS_2");
    uint64_t *beta = (uint64_t *)dlvsym(handle, "api_beta", "VERS_2");
    void *hidden = dlsym(handle, "private_value");
    if (!alpha || !beta) return 132;
    if (*alpha != UINT64_C(0x1111222233334444)) return 133;
    if (*beta != UINT64_C(0xaaaabbbbccccdddd)) return 134;
    if (hidden != 0) return 135;
    return dlclose(handle) == 0 ? 0 : 136;
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

        let status = Command::new(&runner).arg(&mini).status().unwrap();
        assert!(status.success(), "prefix-pattern runtime returned {status}");
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn exact_rule_precedes_matching_prefix_pattern_like_gnu() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("exact-precedence");
    let object = assemble(
        &dir,
        "provider",
        r#".section .data
.globl api_special
.type api_special,@object
api_special:
    .quad 7
.size api_special, .-api_special
"#,
    );
    let script = dir.join("provider.map");
    fs::write(
        &script,
        "VERS_1 { global: api_special; };\nVERS_2 { global: api_*; local: *; } VERS_1;\n",
    )
    .unwrap();

    let mini = dir.join("libmini.so");
    let mini_link = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&mini)
        .args(["--shared", "--version-script"])
        .arg(&script)
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
        .arg(format!("--version-script={}", script.display()))
        .args(["-o"])
        .arg(&gnu)
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        gnu_link.status.success(),
        "{}",
        String::from_utf8_lossy(&gnu_link.stderr)
    );

    let mini_symbols = dynamic_symbols(&mini);
    let gnu_symbols = dynamic_symbols(&gnu);
    assert!(mini_symbols.contains("api_special@@VERS_1"), "{mini_symbols}");
    assert!(gnu_symbols.contains("api_special@@VERS_1"), "{gnu_symbols}");
    assert!(!mini_symbols.contains("api_special@@VERS_2"), "{mini_symbols}");

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn conflicting_prefix_patterns_fail_before_output() {
    if !command_reports("as", "GNU assembler") {
        return;
    }

    let dir = temp_dir("conflict");
    let object = assemble(
        &dir,
        "provider",
        ".data\n.globl api_v2\n.type api_v2,@object\napi_v2:\n  .quad 2\n.size api_v2, .-api_v2\n",
    );
    let script = dir.join("provider.map");
    fs::write(
        &script,
        "VERS_A { global: api_*; };\nVERS_B { global: api_v*; local: *; };\n",
    )
    .unwrap();
    let output = dir.join("must-not-exist.so");

    let mini = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&output)
        .args(["--shared", "--version-script"])
        .arg(&script)
        .arg(&object)
        .output()
        .unwrap();

    assert!(!mini.status.success());
    assert!(mini.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&mini.stderr);
    assert!(
        stderr.contains("multiple") && stderr.contains("pattern"),
        "{stderr}"
    );
    assert!(!output.exists());

    let _ = fs::remove_dir_all(dir);
}
