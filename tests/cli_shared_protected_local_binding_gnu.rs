use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const VALUE: &str = "mini_elf_protected_value";
const FUNCTION: &str = "mini_elf_protected_function_local";
const READ_GOT: &str = "read_mini_elf_protected_value_got";
const VALUE_SLOT: &str = "mini_elf_protected_value_slot";
const CALL_GOT: &str = "call_mini_elf_protected_function_got";
const FUNCTION_SLOT: &str = "mini_elf_protected_function_slot";
const CALL_PLT: &str = "call_mini_elf_protected_function_plt";

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
        "mini-elf-toolchain-protected-local-{label}-{}-{nonce}",
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
        .args(["--64", "-mrelax-relocations=no", "-o"])
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

fn assert_protected_exports(shared: &Path) {
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
                && line.contains(" OBJECT ")
                && line.contains("PROTECTED")
                && line.ends_with(VALUE)
        }),
        "{} dynamic symbols:\n{symbols}",
        shared.display()
    );
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
}

fn dynamic_relocations(shared: &Path) -> String {
    let output = Command::new("readelf")
        .args(["-rW", "--use-dynamic"])
        .arg(shared)
        .output()
        .unwrap();
    assert!(output.status.success());
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn assert_no_loader_preemptible_got_or_plt(shared: &Path) {
    let relocations = dynamic_relocations(shared);
    for symbol in [VALUE, FUNCTION] {
        assert!(
            !relocations.lines().any(|line| {
                line.contains(symbol)
                    && (line.contains("R_X86_64_GLOB_DAT") || line.contains("R_X86_64_JUMP_SLOT"))
            }),
            "{} must not create preemptible GOT/PLT relocation for {symbol}:\n{relocations}",
            shared.display()
        );
    }
}

fn assert_mini_uses_relative_local_binding(shared: &Path) {
    let relocations = dynamic_relocations(shared);
    for symbol in [VALUE, FUNCTION] {
        assert!(
            !relocations
                .lines()
                .any(|line| line.contains(symbol) && line.contains("R_X86_64_64")),
            "{} must use symbol-free RELATIVE binding for protected pointer {symbol}:\n{relocations}",
            shared.display()
        );
    }
    let relative_count = relocations
        .lines()
        .filter(|line| line.contains("R_X86_64_RELATIVE"))
        .count();
    assert!(
        relative_count >= 4,
        "{} expected protected pointer and GOT slots to use RELATIVE relocations:\n{relocations}",
        shared.display()
    );
}

#[test]
fn protected_data_and_function_absolute_got_and_plt_bind_locally_like_gnu() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("runtime");
    let object = assemble(
        &dir,
        "provider",
        &format!(
            r#".section .note.GNU-stack,"",@progbits
.data
.align 8
.globl {VALUE}
.protected {VALUE}
.type {VALUE},@object
{VALUE}:
    .quad 0x1111222233334444
.size {VALUE}, .-{VALUE}

.align 8
.globl {VALUE_SLOT}
.type {VALUE_SLOT},@object
{VALUE_SLOT}:
    .quad {VALUE}
.size {VALUE_SLOT}, .-{VALUE_SLOT}

.align 8
.globl {FUNCTION_SLOT}
.type {FUNCTION_SLOT},@object
{FUNCTION_SLOT}:
    .quad {FUNCTION}
.size {FUNCTION_SLOT}, .-{FUNCTION_SLOT}

.text
.globl {FUNCTION}
.protected {FUNCTION}
.type {FUNCTION},@function
{FUNCTION}:
    mov $7, %eax
    ret
.size {FUNCTION}, .-{FUNCTION}

.globl {READ_GOT}
.type {READ_GOT},@function
{READ_GOT}:
    movq {VALUE}@GOTPCREL(%rip), %rax
    movq (%rax), %rax
    ret
.size {READ_GOT}, .-{READ_GOT}

.globl {CALL_GOT}
.type {CALL_GOT},@function
{CALL_GOT}:
    movq {FUNCTION}@GOTPCREL(%rip), %rax
    jmp *%rax
.size {CALL_GOT}, .-{CALL_GOT}

.globl {CALL_PLT}
.type {CALL_PLT},@function
{CALL_PLT}:
    sub $8, %rsp
    call {FUNCTION}@PLT
    add $8, %rsp
    ret
.size {CALL_PLT}, .-{CALL_PLT}
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
        input_relocations.contains("R_X86_64_GOTPCREL")
            && input_relocations.contains("R_X86_64_64")
            && input_relocations.contains("R_X86_64_PLT32")
            && input_relocations.contains(VALUE)
            && input_relocations.contains(FUNCTION),
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
        assert_protected_exports(shared);
        assert_no_loader_preemptible_got_or_plt(shared);
    }
    assert_mini_uses_relative_local_binding(&mini);

    #[cfg(target_os = "linux")]
    {
        let source = dir.join("runner.c");
        let runner = dir.join("runner");
        fs::write(
            &source,
            format!(
                r#"#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>

uint64_t {VALUE} = UINT64_C(0x5555666677778888);

__attribute__((noinline, visibility("default")))
int {FUNCTION}(void) {{
    return 42;
}}

typedef uint64_t (*read_fn)(void);
typedef int (*call_fn)(void);

int main(int argc, char **argv) {{
    if (argc != 2) return 300;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) return 301;

    read_fn read_got = (read_fn)dlsym(handle, "{READ_GOT}");
    uint64_t **value_slot = (uint64_t **)dlsym(handle, "{VALUE_SLOT}");
    call_fn call_got = (call_fn)dlsym(handle, "{CALL_GOT}");
    call_fn *function_slot = (call_fn *)dlsym(handle, "{FUNCTION_SLOT}");
    call_fn call_plt = (call_fn)dlsym(handle, "{CALL_PLT}");
    uint64_t *protected_value = (uint64_t *)dlsym(handle, "{VALUE}");
    call_fn protected_function = (call_fn)dlsym(handle, "{FUNCTION}");
    uint64_t *global_value = (uint64_t *)dlsym(RTLD_DEFAULT, "{VALUE}");
    call_fn global_function = (call_fn)dlsym(RTLD_DEFAULT, "{FUNCTION}");

    if (!read_got || !value_slot || !call_got || !function_slot || !call_plt
        || !protected_value || !protected_function || !global_value || !global_function)
        return 302;

    if (read_got() != UINT64_C(0x1111222233334444)) return 303;
    if (!*value_slot || **value_slot != UINT64_C(0x1111222233334444)) return 304;
    if (*protected_value != UINT64_C(0x1111222233334444)) return 305;
    if (call_got() != 7 || !*function_slot || (*function_slot)() != 7 || call_plt() != 7)
        return 306;
    if (protected_function() != 7) return 307;

    if (global_value != &{VALUE} || *global_value != UINT64_C(0x5555666677778888))
        return 308;
    if (global_function() != 42) return 309;

    {VALUE} = UINT64_C(0x9999aaaabbbbcccc);
    if (read_got() != UINT64_C(0x1111222233334444)) return 310;
    if (**value_slot != UINT64_C(0x1111222233334444)) return 311;
    if (call_got() != 7 || (*function_slot)() != 7 || call_plt() != 7) return 312;

    return dlclose(handle) == 0 ? 0 : 313;
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
                "protected local-binding runtime returned {status} for {}",
                shared.display()
            );
        }
    }

    let _ = fs::remove_dir_all(dir);
}
