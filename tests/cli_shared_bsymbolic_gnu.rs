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
        "mini-elf-toolchain-bsymbolic-{label}-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&path).unwrap();
    path
}

fn assemble(dir: &Path) -> PathBuf {
    let source = dir.join("symbols.s");
    let object = dir.join("symbols.o");
    fs::write(
        &source,
        r#".section .note.GNU-stack,"",@progbits
.data
.align 8
.globl symbolic_data
.type symbolic_data,@object
symbolic_data:
    .quad 0x1111222233334444
.size symbolic_data, .-symbolic_data

.section .tdata,"awT",@progbits
.align 8
.globl symbolic_tls
.type symbolic_tls,@tls_object
symbolic_tls:
    .quad 0x5555666677778888
.size symbolic_tls, .-symbolic_tls

.text
.globl symbolic_function
.type symbolic_function,@function
symbolic_function:
    mov $0x1357, %eax
    ret
.size symbolic_function, .-symbolic_function

.globl read_symbolic_data
.type read_symbolic_data,@function
read_symbolic_data:
    mov symbolic_data@GOTPCREL(%rip), %rax
    mov (%rax), %rax
    ret
.size read_symbolic_data, .-read_symbolic_data

.globl call_symbolic_function
.type call_symbolic_function,@function
call_symbolic_function:
    call symbolic_function@PLT
    ret
.size call_symbolic_function, .-call_symbolic_function

.globl read_symbolic_tls
.type read_symbolic_tls,@function
read_symbolic_tls:
    leaq symbolic_tls@tlsgd(%rip), %rdi
    call __tls_get_addr@PLT
    mov (%rax), %rax
    ret
.size read_symbolic_tls, .-read_symbolic_tls
"#,
    )
    .unwrap();

    let output = Command::new("as")
        .args(["--64", "-o"])
        .arg(&object)
        .arg(&source)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    object
}

fn assert_symbolic_dynamic_flag(path: &Path) {
    let dynamic = Command::new("readelf")
        .args(["-dW"])
        .arg(path)
        .output()
        .unwrap();
    assert!(
        dynamic.status.success(),
        "{}",
        String::from_utf8_lossy(&dynamic.stderr)
    );
    let dynamic = String::from_utf8_lossy(&dynamic.stdout);
    assert!(
        dynamic.contains("SYMBOLIC"),
        "{} dynamic section does not advertise symbolic binding:\n{dynamic}",
        path.display()
    );
}

#[test]
fn bsymbolic_matches_gnu_loader_binding_across_data_function_and_tls() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("runtime");
    let object = assemble(&dir);

    let mini = dir.join("libmini.so");
    let mini_link = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&mini)
        .args(["--shared", "-Bsymbolic", "--soname", "libmini.so"])
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
        .args([
            "-shared",
            "--hash-style=sysv",
            "--no-relax",
            "-Bsymbolic",
            "--soname=libgnu.so",
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

    assert_symbolic_dynamic_flag(&mini);
    assert_symbolic_dynamic_flag(&gnu);

    let mini_relocations = Command::new("readelf")
        .args(["-rW", "--use-dynamic"])
        .arg(&mini)
        .output()
        .unwrap();
    assert!(mini_relocations.status.success());
    let mini_relocations = String::from_utf8_lossy(&mini_relocations.stdout);
    assert!(
        mini_relocations.contains("symbolic_data")
            && mini_relocations.contains("R_X86_64_GLOB_DAT"),
        "{mini_relocations}"
    );
    assert!(
        mini_relocations.contains("symbolic_function")
            && mini_relocations.contains("R_X86_64_JUMP_SLOT"),
        "{mini_relocations}"
    );
    assert!(
        mini_relocations.contains("symbolic_tls")
            && mini_relocations.contains("R_X86_64_DTPMOD64")
            && mini_relocations.contains("R_X86_64_DTPOFF64"),
        "{mini_relocations}"
    );

    #[cfg(target_os = "linux")]
    {
        let source = dir.join("runner.c");
        let runner = dir.join("runner");
        fs::write(
            &source,
            r#"#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>

uint64_t symbolic_data = UINT64_C(0xaaaabbbbccccdddd);
__thread uint64_t symbolic_tls = UINT64_C(0x9999aaaabbbbcccc);

uint64_t symbolic_function(void) {
    return UINT64_C(0x2468);
}

typedef uint64_t (*read_fn)(void);

int main(int argc, char **argv) {
    if (argc != 2) return 160;

    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) return 161;

    read_fn read_data = (read_fn)dlsym(handle, "read_symbolic_data");
    read_fn call_function = (read_fn)dlsym(handle, "call_symbolic_function");
    read_fn read_tls = (read_fn)dlsym(handle, "read_symbolic_tls");
    uint64_t *dso_data = (uint64_t *)dlsym(handle, "symbolic_data");
    read_fn dso_function = (read_fn)dlsym(handle, "symbolic_function");
    uint64_t *dso_tls = (uint64_t *)dlsym(handle, "symbolic_tls");

    if (!read_data || !call_function || !read_tls) return 162;
    if (!dso_data || !dso_function || !dso_tls) return 163;

    if (read_data() != UINT64_C(0x1111222233334444)) return 164;
    if (call_function() != UINT64_C(0x1357)) return 165;
    if (read_tls() != UINT64_C(0x5555666677778888)) return 166;

    if (*dso_data != UINT64_C(0x1111222233334444)) return 167;
    if (dso_function() != UINT64_C(0x1357)) return 168;
    if (*dso_tls != UINT64_C(0x5555666677778888)) return 169;

    uint64_t *root_data = (uint64_t *)dlsym(RTLD_DEFAULT, "symbolic_data");
    read_fn root_function = (read_fn)dlsym(RTLD_DEFAULT, "symbolic_function");
    uint64_t *root_tls = (uint64_t *)dlsym(RTLD_DEFAULT, "symbolic_tls");
    if (root_data != &symbolic_data) return 170;
    if (root_function != symbolic_function) return 171;
    if (root_tls != &symbolic_tls) return 172;
    if (*root_data != UINT64_C(0xaaaabbbbccccdddd)) return 173;
    if (root_function() != UINT64_C(0x2468)) return 174;
    if (*root_tls != UINT64_C(0x9999aaaabbbbcccc)) return 175;

    return dlclose(handle) == 0 ? 0 : 176;
}
"#,
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
                "-Bsymbolic runtime returned {status} for {}",
                shared.display()
            );
        }
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn bsymbolic_is_rejected_outside_shared_mode_before_input_io() {
    let dir = temp_dir("usage");
    let output = dir.join("must-not-exist");

    let result = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&output)
        .arg("-Bsymbolic")
        .arg(dir.join("missing.o"))
        .output()
        .unwrap();

    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(
        stderr.contains("-Bsymbolic is only supported with --shared"),
        "{stderr}"
    );
    assert!(!output.exists());

    let _ = fs::remove_dir_all(dir);
}
