use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const DATA: &str = "mini_elf_absolute_interposable_data_327";
const FUNCTION: &str = "mini_elf_absolute_interposable_function_327";
const DATA_SLOT: &str = "mini_elf_absolute_data_pointer_slot_327";
const FUNCTION_SLOT: &str = "mini_elf_absolute_function_pointer_slot_327";

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
        "mini-elf-toolchain-defined-absolute-interposition-{label}-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&path).unwrap();
    path
}

fn assemble(dir: &Path, source: &str) -> PathBuf {
    let asm = dir.join("provider.s");
    let object = dir.join("provider.o");
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

fn assert_dynamic_metadata(shared: &Path) {
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
                && !line.contains(" UND ")
                && line.ends_with(DATA)
        }),
        "{} dynamic symbols:\n{symbols}",
        shared.display()
    );
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
    for name in [DATA, FUNCTION] {
        assert!(
            relocations
                .lines()
                .any(|line| line.contains("R_X86_64_64") && line.contains(name)),
            "{} dynamic relocations missing {name}:\n{relocations}",
            shared.display()
        );
    }
}

#[test]
fn defined_writable_absolute_relocations_match_gnu_and_are_runtime_preemptible() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("runtime");
    let object = assemble(
        &dir,
        &format!(
            r#".section .note.GNU-stack,"",@progbits

.data
.align 8
.globl {DATA}
.type {DATA},@object
{DATA}:
    .quad 0x1111222233334444
.size {DATA}, .-{DATA}

.globl {DATA_SLOT}
.type {DATA_SLOT},@object
{DATA_SLOT}:
    .quad {DATA}
.size {DATA_SLOT}, .-{DATA_SLOT}

.globl {FUNCTION_SLOT}
.type {FUNCTION_SLOT},@object
{FUNCTION_SLOT}:
    .quad {FUNCTION}
.size {FUNCTION_SLOT}, .-{FUNCTION_SLOT}

.text
.globl {FUNCTION}
.type {FUNCTION},@function
{FUNCTION}:
    mov $7, %eax
    ret
.size {FUNCTION}, .-{FUNCTION}
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
    for name in [DATA, FUNCTION] {
        assert!(
            input_relocations
                .lines()
                .any(|line| line.contains("R_X86_64_64") && line.contains(name)),
            "{input_relocations}"
        );
    }
    assert!(
        !input_relocations.contains("R_X86_64_PC32"),
        "fixture must isolate the writable absolute relocation plane: {input_relocations}"
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
        assert_dynamic_metadata(shared);
    }

    #[cfg(target_os = "linux")]
    {
        let own_source = dir.join("own.c");
        let own_runner = dir.join("own");
        fs::write(
            &own_source,
            r#"#include <dlfcn.h>
#include <stdint.h>

typedef int (*target_fn)(void);

int main(int argc, char **argv) {
    if (argc != 2) return 241;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) return 242;
    uint64_t **data_slot = (uint64_t **)dlsym(handle, "mini_elf_absolute_data_pointer_slot_327");
    target_fn *function_slot = (target_fn *)dlsym(handle, "mini_elf_absolute_function_pointer_slot_327");
    if (!data_slot || !function_slot || !*data_slot || !*function_slot) return 243;
    if (**data_slot != UINT64_C(0x1111222233334444)) return 244;
    if ((*function_slot)() != 7) return 245;
    return dlclose(handle) == 0 ? 0 : 246;
}
"#,
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
#include <stdint.h>

uint64_t {DATA} = UINT64_C(0x5555666677778888);

__attribute__((noinline, visibility("default")))
int {FUNCTION}(void) {{
    return 42;
}}

typedef int (*target_fn)(void);

int main(int argc, char **argv) {{
    if (argc != 2) return 247;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) return 248;
    uint64_t **data_slot = (uint64_t **)dlsym(handle, "mini_elf_absolute_data_pointer_slot_327");
    target_fn *function_slot = (target_fn *)dlsym(handle, "mini_elf_absolute_function_pointer_slot_327");
    if (!data_slot || !function_slot || !*data_slot || !*function_slot) return 249;
    if (**data_slot != UINT64_C(0x5555666677778888)) return 250;
    if ((*function_slot)() != 42) return 251;
    {DATA} = UINT64_C(0x9999aaaabbbbcccc);
    if (**data_slot != UINT64_C(0x9999aaaabbbbcccc)) return 252;
    return dlclose(handle) == 0 ? 0 : 253;
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
            let own = Command::new(&own_runner).arg(shared).status().unwrap();
            assert!(
                own.success(),
                "defined absolute self-binding runtime returned {own} for {}",
                shared.display()
            );

            let bound = Command::new(&bound_runner).arg(shared).status().unwrap();
            assert!(
                bound.success(),
                "defined absolute preemption runtime returned {bound} for {}",
                shared.display()
            );
        }
    }

    let _ = fs::remove_dir_all(dir);
}
