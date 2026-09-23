use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const WEAK_NAME: &str = "mini_elf_optional_weak_plt_323";

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
        "mini-elf-toolchain-weak-plt-{label}-{}-{nonce}",
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

fn assert_weak_jump_slot(shared: &Path, name: &str, version: Option<&str>) {
    let symbols = Command::new("readelf")
        .arg("-sDW")
        .arg(shared)
        .output()
        .unwrap();
    assert!(symbols.status.success());
    let symbols = String::from_utf8_lossy(&symbols.stdout);
    let display_name = version
        .map(|version| format!("{name}@{version}"))
        .unwrap_or_else(|| name.to_owned());
    assert!(
        symbols.lines().any(|line| {
            line.contains("WEAK")
                && line.contains("FUNC")
                && line.contains("UND")
                && line.contains(&display_name)
        }),
        "{} dynamic symbols:\n{symbols}",
        shared.display()
    );

    let relocations = Command::new("readelf")
        .args(["-rW", "--use-dynamic"])
        .arg(shared)
        .output()
        .unwrap();
    assert!(relocations.status.success());
    let relocations = String::from_utf8_lossy(&relocations.stdout);
    assert!(
        relocations
            .lines()
            .any(|line| { line.contains("R_X86_64_JUMP_SLOT") && line.contains(&display_name) }),
        "{} dynamic relocations:\n{relocations}",
        shared.display()
    );
}

#[test]
fn unversioned_weak_plt_matches_gnu_and_zero_bind_load_semantics() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("unversioned");
    let object = assemble(
        &dir,
        "consumer",
        &format!(
            r#".section .note.GNU-stack,"",@progbits
.text
.globl call_optional
.type call_optional,@function
.weak {WEAK_NAME}
.type {WEAK_NAME},@function
call_optional:
    call {WEAK_NAME}@PLT
    ret
.size call_optional, .-call_optional
"#
        ),
    );

    let mini = dir.join("libmini.so");
    let mini_link = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&mini)
        .arg("--shared")
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
        .args(["-shared", "--hash-style=sysv", "-o"])
        .arg(&gnu)
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        gnu_link.status.success(),
        "{}",
        String::from_utf8_lossy(&gnu_link.stderr)
    );

    for shared in [&mini, &gnu] {
        assert_weak_jump_slot(shared, WEAK_NAME, None);

        let dynamic = Command::new("readelf")
            .arg("-dW")
            .arg(shared)
            .output()
            .unwrap();
        assert!(dynamic.status.success());
        let dynamic = String::from_utf8_lossy(&dynamic.stdout);
        assert!(
            !dynamic.contains("(NEEDED)"),
            "unversioned weak PLT imports must not invent a provider dependency: {dynamic}"
        );
    }

    #[cfg(target_os = "linux")]
    {
        let absent_source = dir.join("absent.c");
        let absent_runner = dir.join("absent");
        fs::write(
            &absent_source,
            r#"#include <dlfcn.h>

int main(int argc, char **argv) {
    if (argc != 2) return 180;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) return 181;
    void *call = dlsym(handle, "call_optional");
    if (!call) return 182;
    return dlclose(handle) == 0 ? 0 : 183;
}
"#,
        )
        .unwrap();
        let compile_absent = Command::new("cc")
            .args(["-o"])
            .arg(&absent_runner)
            .arg(&absent_source)
            .arg("-ldl")
            .output()
            .unwrap();
        assert!(
            compile_absent.status.success(),
            "{}",
            String::from_utf8_lossy(&compile_absent.stderr)
        );

        let bound_source = dir.join("bound.c");
        let bound_runner = dir.join("bound");
        fs::write(
            &bound_source,
            format!(
                r#"#include <dlfcn.h>
#include <stdint.h>

uint64_t {WEAK_NAME}(void) {{
    return UINT64_C(0x73);
}}

int main(int argc, char **argv) {{
    if (argc != 2) return 184;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) return 185;
    uint64_t (*call)(void) = (uint64_t (*)(void))dlsym(handle, "call_optional");
    if (!call) return 186;
    if (call() != UINT64_C(0x73)) return 187;
    return dlclose(handle) == 0 ? 0 : 188;
}}
"#
            ),
        )
        .unwrap();
        let compile_bound = Command::new("cc")
            .args(["-rdynamic", "-o"])
            .arg(&bound_runner)
            .arg(&bound_source)
            .arg("-ldl")
            .output()
            .unwrap();
        assert!(
            compile_bound.status.success(),
            "{}",
            String::from_utf8_lossy(&compile_bound.stderr)
        );

        for shared in [&mini, &gnu] {
            let absent_status = Command::new(&absent_runner).arg(shared).status().unwrap();
            assert!(
                absent_status.success(),
                "absent weak PLT load returned {absent_status} for {}",
                shared.display()
            );

            let bound_status = Command::new(&bound_runner).arg(shared).status().unwrap();
            assert!(
                bound_status.success(),
                "bound weak PLT call returned {bound_status} for {}",
                shared.display()
            );
        }
    }

    let _ = fs::remove_dir_all(dir);
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

#[test]
fn named_version_weak_plt_preserves_requirement_and_runtime_binding() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("versioned");
    let link_provider_dir = dir.join("link-provider");
    let runtime_provider_dir = dir.join("runtime-provider");
    let link_provider = provider(&link_provider_dir, true);
    let _runtime_provider = provider(&runtime_provider_dir, false);
    let object = assemble(
        &dir,
        "versioned-consumer",
        r#".section .note.GNU-stack,"",@progbits
.text
.globl call_provider
.type call_provider,@function
.weak provider_function
.type provider_function,@function
.symver provider_function,provider_function@VERS_1
call_provider:
    call provider_function@PLT
    ret
.size call_provider, .-call_provider
"#,
    );

    let mini = dir.join("libmini-versioned.so");
    let mini_link = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&mini)
        .args([
            "--shared",
            "--soname",
            "libmini-versioned.so",
            "--needed-from",
        ])
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

    let gnu = dir.join("libgnu-versioned.so");
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

    for shared in [&mini, &gnu] {
        assert_weak_jump_slot(shared, "provider_function", Some("VERS_1"));
    }

    let versions = Command::new(env!("CARGO_BIN_EXE_mini-elf-versym-needed"))
        .arg(&mini)
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
    if (argc != 3) return 190;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) return 191;
    uint64_t (*call)(void) = (uint64_t (*)(void))dlsym(handle, "call_provider");
    if (!call) return 192;
    if (argv[2][0] == '1' && call() != UINT64_C(0x5a)) return 193;
    return dlclose(handle) == 0 ? 0 : 194;
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
            let present = Command::new(&runner)
                .arg(shared)
                .arg("1")
                .env("LD_LIBRARY_PATH", &link_provider_dir)
                .status()
                .unwrap();
            assert!(
                present.success(),
                "versioned weak PLT present-provider runtime returned {present} for {}",
                shared.display()
            );

            let absent = Command::new(&runner)
                .arg(shared)
                .arg("0")
                .env("LD_LIBRARY_PATH", &runtime_provider_dir)
                .status()
                .unwrap();
            assert!(
                absent.success(),
                "versioned weak PLT absent-symbol load returned {absent} for {}",
                shared.display()
            );
        }
    }

    let _ = fs::remove_dir_all(dir);
}
