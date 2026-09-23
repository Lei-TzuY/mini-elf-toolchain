use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const FUNCTION: &str = "mini_elf_defined_plt_interposable_function";
const CALLER: &str = "call_mini_elf_defined_plt_interposable_function";

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
        "mini-elf-toolchain-defined-plt-interposition-{label}-{}-{nonce}",
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

fn assert_defined_jump_slot(shared: &Path) {
    let symbols = Command::new("readelf")
        .arg("-sDW")
        .arg(shared)
        .output()
        .unwrap();
    assert!(symbols.status.success());
    let symbols = String::from_utf8_lossy(&symbols.stdout);
    assert!(
        symbols.lines().any(|line| {
            line.contains("GLOBAL")
                && line.contains(" FUNC ")
                && !line.contains(" UND ")
                && line.ends_with(FUNCTION)
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
            .any(|line| line.contains("R_X86_64_JUMP_SLOT") && line.contains(FUNCTION)),
        "{} dynamic relocations:\n{relocations}",
        shared.display()
    );

    let dynamic = Command::new("readelf")
        .arg("-dW")
        .arg(shared)
        .output()
        .unwrap();
    assert!(dynamic.status.success());
    let dynamic = String::from_utf8_lossy(&dynamic.stdout);
    for tag in ["JMPREL", "PLTRELSZ", "PLTREL", "PLTGOT"] {
        assert!(
            dynamic.contains(tag),
            "{} dynamic section is missing {tag}:\n{dynamic}",
            shared.display()
        );
    }
    assert!(
        !dynamic.contains("BIND_NOW"),
        "defined-function PLT interposition should preserve the existing lazy PLT policy: {dynamic}"
    );
}

#[test]
fn defined_default_visible_function_plt_matches_gnu_and_is_runtime_preemptible() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("runtime");
    let object = assemble(
        &dir,
        "provider",
        &format!(
            r#".section .note.GNU-stack,"",@progbits
.text
.globl {FUNCTION}
.type {FUNCTION},@function
{FUNCTION}:
    mov $7, %eax
    ret
.size {FUNCTION}, .-{FUNCTION}

.globl {CALLER}
.type {CALLER},@function
{CALLER}:
    sub $8, %rsp
    call {FUNCTION}@PLT
    add $8, %rsp
    ret
.size {CALLER}, .-{CALLER}
"#
        ),
    );

    let input_relocations = Command::new("readelf")
        .arg("-rW")
        .arg(&object)
        .output()
        .unwrap();
    assert!(input_relocations.status.success());
    let input_relocations = String::from_utf8_lossy(&input_relocations.stdout);
    assert!(
        input_relocations
            .lines()
            .any(|line| line.contains("R_X86_64_PLT32") && line.contains(FUNCTION)),
        "{input_relocations}"
    );

    let mini = dir.join("libmini.so");
    let mini_link = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&mini)
        .args(["--shared", "--soname", "libmini.so"])
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
        .args(["-shared", "--hash-style=sysv", "--soname=libgnu.so", "-o"])
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
        assert_defined_jump_slot(shared);
    }

    #[cfg(target_os = "linux")]
    {
        let own_source = dir.join("own.c");
        let own_runner = dir.join("own");
        fs::write(
            &own_source,
            format!(
                r#"#include <dlfcn.h>

typedef int (*call_fn)(void);

int main(int argc, char **argv) {{
    if (argc != 2) return 260;
    void *handle = dlopen(argv[1], RTLD_LAZY | RTLD_LOCAL);
    if (!handle) return 261;
    call_fn call = (call_fn)dlsym(handle, "{CALLER}");
    if (!call) return 262;
    if (call() != 7) return 263;
    if (call() != 7) return 264;
    return dlclose(handle) == 0 ? 0 : 265;
}}
"#
            ),
        )
        .unwrap();
        let own_compile = Command::new("cc")
            .args(["-o"])
            .arg(&own_runner)
            .arg(&own_source)
            .arg("-ldl")
            .output()
            .unwrap();
        assert!(
            own_compile.status.success(),
            "{}",
            String::from_utf8_lossy(&own_compile.stderr)
        );

        let bound_source = dir.join("bound.c");
        let bound_runner = dir.join("bound");
        fs::write(
            &bound_source,
            format!(
                r#"#include <dlfcn.h>

__attribute__((noinline, visibility("default")))
int {FUNCTION}(void) {{
    return 42;
}}

typedef int (*call_fn)(void);

int main(int argc, char **argv) {{
    if (argc != 2) return 266;
    void *handle = dlopen(argv[1], RTLD_LAZY | RTLD_LOCAL);
    if (!handle) return 267;
    call_fn call = (call_fn)dlsym(handle, "{CALLER}");
    if (!call) return 268;
    if (call() != 42) return 269;
    if (call() != 42) return 270;
    return dlclose(handle) == 0 ? 0 : 271;
}}
"#
            ),
        )
        .unwrap();
        let bound_compile = Command::new("cc")
            .args(["-rdynamic", "-o"])
            .arg(&bound_runner)
            .arg(&bound_source)
            .arg("-ldl")
            .output()
            .unwrap();
        assert!(
            bound_compile.status.success(),
            "{}",
            String::from_utf8_lossy(&bound_compile.stderr)
        );

        for shared in [&mini, &gnu] {
            let own = Command::new(&own_runner)
                .env_remove("LD_BIND_NOW")
                .arg(shared)
                .status()
                .unwrap();
            assert!(
                own.success(),
                "defined PLT self-binding runtime returned {own} for {}",
                shared.display()
            );

            let bound = Command::new(&bound_runner)
                .env_remove("LD_BIND_NOW")
                .arg(shared)
                .status()
                .unwrap();
            assert!(
                bound.success(),
                "defined PLT preemption runtime returned {bound} for {}",
                shared.display()
            );
        }
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn hidden_defined_function_plt_remains_fail_closed() {
    if !command_reports("as", "GNU assembler") {
        return;
    }

    let dir = temp_dir("hidden");
    let object = assemble(
        &dir,
        "hidden-provider",
        &format!(
            r#".section .note.GNU-stack,"",@progbits
.text
.globl {FUNCTION}
.hidden {FUNCTION}
.type {FUNCTION},@function
{FUNCTION}:
    mov $7, %eax
    ret
.size {FUNCTION}, .-{FUNCTION}

.globl {CALLER}
.type {CALLER},@function
{CALLER}:
    sub $8, %rsp
    call {FUNCTION}@PLT
    add $8, %rsp
    ret
.size {CALLER}, .-{CALLER}
"#
        ),
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
        stderr.contains("visibility")
            || stderr.contains("default-visible")
            || stderr.contains("preemptible"),
        "{stderr}"
    );
    assert!(!output.exists());

    let _ = fs::remove_dir_all(dir);
}
