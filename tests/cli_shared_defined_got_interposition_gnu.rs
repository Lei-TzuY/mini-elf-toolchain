use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const VALUE: &str = "mini_elf_interposable_value_325";

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
        "mini-elf-toolchain-defined-got-interposition-{label}-{}-{nonce}",
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

fn assert_interposable_metadata(shared: &Path) {
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
                && line.ends_with(VALUE)
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
            .any(|line| line.contains("R_X86_64_GLOB_DAT") && line.contains(VALUE)),
        "{} dynamic relocations:\n{relocations}",
        shared.display()
    );
}

#[test]
fn defined_default_visible_data_got_matches_gnu_and_is_runtime_preemptible() {
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
.type {VALUE},@object
{VALUE}:
    .quad 0x1111222233334444
.size {VALUE}, .-{VALUE}

.text
.globl read_interposable_value
.type read_interposable_value,@function
read_interposable_value:
    movq {VALUE}@GOTPCREL(%rip), %rax
    movq (%rax), %rax
    ret
.size read_interposable_value, .-read_interposable_value
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
        input_relocations.contains("R_X86_64_GOTPCREL") && input_relocations.contains(VALUE),
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
        assert_interposable_metadata(shared);
    }

    #[cfg(target_os = "linux")]
    {
        let own_source = dir.join("own.c");
        let own_runner = dir.join("own");
        fs::write(
            &own_source,
            r#"#include <dlfcn.h>
#include <stdint.h>

typedef uint64_t (*read_fn)(void);

int main(int argc, char **argv) {
    if (argc != 2) return 220;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) return 221;
    read_fn read_value = (read_fn)dlsym(handle, "read_interposable_value");
    if (!read_value) return 222;
    if (read_value() != UINT64_C(0x1111222233334444)) return 223;
    return dlclose(handle) == 0 ? 0 : 224;
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

uint64_t {VALUE} = UINT64_C(0x5555666677778888);

typedef uint64_t (*read_fn)(void);

int main(int argc, char **argv) {{
    if (argc != 2) return 225;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) return 226;
    read_fn read_value = (read_fn)dlsym(handle, "read_interposable_value");
    if (!read_value) return 227;
    if (read_value() != UINT64_C(0x5555666677778888)) return 228;
    {VALUE} = UINT64_C(0x9999aaaabbbbcccc);
    if (read_value() != UINT64_C(0x9999aaaabbbbcccc)) return 229;
    return dlclose(handle) == 0 ? 0 : 230;
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
                "defined GOT self-binding runtime returned {own} for {}",
                shared.display()
            );

            let bound = Command::new(&bound_runner).arg(shared).status().unwrap();
            assert!(
                bound.success(),
                "defined GOT preemption runtime returned {bound} for {}",
                shared.display()
            );
        }
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn defined_default_visible_function_got_matches_gnu_and_is_runtime_preemptible() {
    if !have_tools() {
        return;
    }

    const FUNCTION: &str = "mini_elf_interposable_function_326";
    let dir = temp_dir("function-runtime");
    let object = assemble(
        &dir,
        "function-provider",
        &format!(
            r#".section .note.GNU-stack,"",@progbits
.text
.globl {FUNCTION}
.type {FUNCTION},@function
{FUNCTION}:
    mov $7, %eax
    ret
.size {FUNCTION}, .-{FUNCTION}

.globl call_interposable_function
.type call_interposable_function,@function
call_interposable_function:
    movq {FUNCTION}@GOTPCREL(%rip), %rax
    jmp *%rax
.size call_interposable_function, .-call_interposable_function
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
        input_relocations.contains("R_X86_64_GOTPCREL") && input_relocations.contains(FUNCTION),
        "{input_relocations}"
    );

    let mini = dir.join("libmini-function.so");
    let mini_link = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&mini)
        .args(["--shared", "--soname", "libmini-function.so"])
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        mini_link.status.success(),
        "{}",
        String::from_utf8_lossy(&mini_link.stderr)
    );

    let gnu = dir.join("libgnu-function.so");
    let gnu_link = Command::new("ld")
        .args([
            "-shared",
            "--hash-style=sysv",
            "--soname=libgnu-function.so",
            "-o",
        ])
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
                .any(|line| { line.contains("R_X86_64_GLOB_DAT") && line.contains(FUNCTION) }),
            "{} dynamic relocations:\n{relocations}",
            shared.display()
        );
    }

    #[cfg(target_os = "linux")]
    {
        let own_source = dir.join("function-own.c");
        let own_runner = dir.join("function-own");
        fs::write(
            &own_source,
            r#"#include <dlfcn.h>

typedef int (*call_fn)(void);

int main(int argc, char **argv) {
    if (argc != 2) return 231;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) return 232;
    call_fn call_value = (call_fn)dlsym(handle, "call_interposable_function");
    if (!call_value) return 233;
    if (call_value() != 7) return 234;
    return dlclose(handle) == 0 ? 0 : 235;
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

        let bound_source = dir.join("function-bound.c");
        let bound_runner = dir.join("function-bound");
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
    if (argc != 2) return 236;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) return 237;
    call_fn call_value = (call_fn)dlsym(handle, "call_interposable_function");
    if (!call_value) return 238;
    if (call_value() != 42) return 239;
    return dlclose(handle) == 0 ? 0 : 240;
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
                "defined function GOT self-binding runtime returned {own} for {}",
                shared.display()
            );

            let bound = Command::new(&bound_runner).arg(shared).status().unwrap();
            assert!(
                bound.success(),
                "defined function GOT preemption runtime returned {bound} for {}",
                shared.display()
            );
        }
    }

    let _ = fs::remove_dir_all(dir);
}
