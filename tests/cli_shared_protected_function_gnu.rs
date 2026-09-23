use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const FUNCTION: &str = "mini_elf_protected_function";
const CALLER: &str = "call_mini_elf_protected_function";

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
        "mini-elf-toolchain-protected-function-{label}-{}-{nonce}",
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

fn protected_source(caller_body: &str) -> String {
    format!(
        r#".section .note.GNU-stack,"",@progbits
.text
.globl {FUNCTION}
.protected {FUNCTION}
.type {FUNCTION},@function
{FUNCTION}:
    mov $7, %eax
    ret
.size {FUNCTION}, .-{FUNCTION}

.globl {CALLER}
.type {CALLER},@function
{CALLER}:
{caller_body}
.size {CALLER}, .-{CALLER}
"#
    )
}

fn assert_protected_export_without_jump_slot(shared: &Path) {
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
                && line.contains("PROTECTED")
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
        !relocations
            .lines()
            .any(|line| line.contains("R_X86_64_JUMP_SLOT") && line.contains(FUNCTION)),
        "{} must bind its protected internal call locally:\n{relocations}",
        shared.display()
    );
}

#[test]
fn protected_function_plt_matches_gnu_and_resists_preemption() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("plt");
    let object = assemble(
        &dir,
        "provider",
        &protected_source(
            "    sub $8, %rsp\n    call mini_elf_protected_function@PLT\n    add $8, %rsp\n    ret",
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
        assert_protected_export_without_jump_slot(shared);
    }

    #[cfg(target_os = "linux")]
    {
        let source = dir.join("runner.c");
        let runner = dir.join("runner");
        fs::write(
            &source,
            format!(
                r#"#define _GNU_SOURCE
#include <dlfcn.h>

__attribute__((noinline, visibility("default")))
int {FUNCTION}(void) {{
    return 42;
}}

typedef int (*fn)(void);

int main(int argc, char **argv) {{
    if (argc != 2) return 280;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) return 281;

    fn caller = (fn)dlsym(handle, "{CALLER}");
    fn protected_fn = (fn)dlsym(handle, "{FUNCTION}");
    fn global_fn = (fn)dlsym(RTLD_DEFAULT, "{FUNCTION}");
    if (!caller || !protected_fn || !global_fn) return 282;

    if (caller() != 7) return 283;
    if (protected_fn() != 7) return 284;
    if (global_fn() != 42) return 285;
    if (caller() != 7) return 286;

    return dlclose(handle) == 0 ? 0 : 287;
}}
"#
            ),
        )
        .unwrap();

        let compile = Command::new("cc")
            .args(["-rdynamic", "-o"])
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
                "protected-function runtime returned {status} for {}",
                shared.display()
            );
        }
    }

    let _ = fs::remove_dir_all(dir);
}


#[test]
fn protected_function_cross_object_plt_and_provider_lookup_work() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("cross-object");
    let definition = assemble(
        &dir,
        "definition",
        &format!(
            r#".section .note.GNU-stack,"",@progbits
.text
.globl {FUNCTION}
.protected {FUNCTION}
.type {FUNCTION},@function
{FUNCTION}:
    mov $7, %eax
    ret
.size {FUNCTION}, .-{FUNCTION}
"#
        ),
    );
    let caller = assemble(
        &dir,
        "caller",
        &format!(
            r#".section .note.GNU-stack,"",@progbits
.text
.type {FUNCTION},@function
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
        .arg(&caller)
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

    let mini = dir.join("libmini-cross.so");
    let mini_link = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&mini)
        .args(["--shared", "--soname", "libmini-cross.so"])
        .arg(&definition)
        .arg(&caller)
        .output()
        .unwrap();
    assert!(
        mini_link.status.success(),
        "{}",
        String::from_utf8_lossy(&mini_link.stderr)
    );

    let gnu = dir.join("libgnu-cross.so");
    let gnu_link = Command::new("ld")
        .args([
            "-shared",
            "--hash-style=sysv",
            "--soname=libgnu-cross.so",
            "-o",
        ])
        .arg(&gnu)
        .arg(&definition)
        .arg(&caller)
        .output()
        .unwrap();
    assert!(
        gnu_link.status.success(),
        "{}",
        String::from_utf8_lossy(&gnu_link.stderr)
    );

    for shared in [&mini, &gnu] {
        assert_protected_export_without_jump_slot(shared);
    }

    let consumer_object = assemble(
        &dir,
        "consumer",
        &format!(
            r#".section .note.GNU-stack,"",@progbits
.text
.type {FUNCTION},@function
.globl consume_protected_function
.type consume_protected_function,@function
consume_protected_function:
    sub $8, %rsp
    call {FUNCTION}@PLT
    add $8, %rsp
    ret
.size consume_protected_function, .-consume_protected_function
"#
        ),
    );
    let consumer = dir.join("libconsumer.so");
    let consumer_link = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&consumer)
        .args(["--shared", "--soname", "libconsumer.so", "--needed-from"])
        .arg(&mini)
        .arg(&consumer_object)
        .output()
        .unwrap();
    assert!(
        consumer_link.status.success(),
        "{}",
        String::from_utf8_lossy(&consumer_link.stderr)
    );

    let dynamic = Command::new("readelf")
        .arg("-dW")
        .arg(&consumer)
        .output()
        .unwrap();
    assert!(dynamic.status.success());
    let dynamic = String::from_utf8_lossy(&dynamic.stdout);
    assert!(
        dynamic.contains("NEEDED") && dynamic.contains("libmini-cross.so"),
        "{dynamic}"
    );

    #[cfg(target_os = "linux")]
    {
        let source = dir.join("cross-runner.c");
        let runner = dir.join("cross-runner");
        fs::write(
            &source,
            format!(
                r#"#include <dlfcn.h>

typedef int (*fn)(void);

int main(int argc, char **argv) {{
    if (argc != 2) return 288;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) return 289;
    fn caller = (fn)dlsym(handle, "{CALLER}");
    if (!caller) return 290;
    if (caller() != 7) return 291;
    return dlclose(handle) == 0 ? 0 : 292;
}}
"#
            ),
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
                "cross-object protected runtime returned {status} for {}",
                shared.display()
            );
        }
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn protected_function_got_interposition_remains_out_of_scope() {
    if !command_reports("as", "GNU assembler") {
        return;
    }

    let dir = temp_dir("got-boundary");
    let object = assemble(
        &dir,
        "provider",
        &protected_source(
            "    mov mini_elf_protected_function@GOTPCREL(%rip), %rax\n    jmp *%rax",
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
        stderr.contains("preemptible")
            || stderr.contains("default-visible")
            || stderr.contains("visibility"),
        "{stderr}"
    );
    assert!(!output.exists());

    let _ = fs::remove_dir_all(dir);
}
