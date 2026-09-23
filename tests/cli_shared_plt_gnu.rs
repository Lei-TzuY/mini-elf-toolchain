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
        && command_reports("readelf", "GNU readelf")
        && command_available("cc")
}

fn temp_dir(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after Unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "mini-elf-toolchain-shared-plt-{label}-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&path).unwrap();
    path
}

fn jump_slot_offset(readelf_output: &str, symbol: &str) -> u64 {
    readelf_output
        .lines()
        .find(|line| line.contains("R_X86_64_JUMP_SLOT") && line.contains(symbol))
        .and_then(|line| line.split_whitespace().next())
        .and_then(|value| u64::from_str_radix(value, 16).ok())
        .expect("expected loader-visible JUMP_SLOT relocation offset")
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

#[test]
fn shared_object_direct_external_call_uses_lazy_plt_jump_slot() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("strong");
    let object = assemble(
        &dir,
        "plt-call",
        r#".section .text
.globl call_host_direct
.type call_host_direct,@function
.extern host_function
.type host_function,@function
call_host_direct:
    mov $41, %edi
    sub $8, %rsp
    call host_function
    add $8, %rsp
    ret
.size call_host_direct, .-call_host_direct
"#,
    );

    let input_relocations = Command::new("readelf")
        .args(["-rW"])
        .arg(&object)
        .output()
        .unwrap();
    assert!(input_relocations.status.success());
    let input_relocations = String::from_utf8_lossy(&input_relocations.stdout);
    assert!(
        input_relocations.contains("R_X86_64_PLT32"),
        "{input_relocations}"
    );
    assert!(
        input_relocations.contains("host_function"),
        "{input_relocations}"
    );

    let shared = dir.join("libplt.so");
    let mini = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&shared)
        .arg("--shared")
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        mini.status.success(),
        "{}",
        String::from_utf8_lossy(&mini.stderr)
    );

    let dynamic = Command::new("readelf")
        .args(["-dW"])
        .arg(&shared)
        .output()
        .unwrap();
    assert!(dynamic.status.success());
    let dynamic = String::from_utf8_lossy(&dynamic.stdout);
    assert!(dynamic.contains("JMPREL"), "{dynamic}");
    assert!(dynamic.contains("PLTRELSZ"), "{dynamic}");
    assert!(
        dynamic.contains("PLTREL") && dynamic.contains("RELA"),
        "{dynamic}"
    );
    assert!(dynamic.contains("PLTGOT"), "{dynamic}");
    assert!(
        !dynamic.contains("BIND_NOW"),
        "lazy PLT must not force eager binding: {dynamic}"
    );

    let symbols = Command::new("readelf")
        .arg("-sDW")
        .arg(&shared)
        .output()
        .unwrap();
    assert!(symbols.status.success());
    let symbols = String::from_utf8_lossy(&symbols.stdout);
    assert!(
        symbols.lines().any(|line| {
            line.contains("FUNC") && line.contains("UND") && line.ends_with(" host_function")
        }),
        "{symbols}"
    );

    let relocations = Command::new("readelf")
        .args(["-rW", "--use-dynamic"])
        .arg(&shared)
        .output()
        .unwrap();
    assert!(relocations.status.success());
    let relocations = String::from_utf8_lossy(&relocations.stdout);
    assert!(
        relocations
            .lines()
            .any(|line| line.contains("R_X86_64_JUMP_SLOT") && line.contains("host_function")),
        "{relocations}"
    );
    let host_jump_slot = jump_slot_offset(&relocations, "host_function");

    #[cfg(target_os = "linux")]
    {
        let source = dir.join("consumer.c");
        let consumer = dir.join("consumer");
        fs::write(
            &source,
            format!(
                r#"#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <stdint.h>

static uint64_t host_calls;

uint64_t host_function(uint64_t value) {{
    host_calls += 1;
    return value + host_calls;
}}

int main(int argc, char **argv) {{
    if (argc != 2) return 70;
    void *handle = dlopen(argv[1], RTLD_LAZY | RTLD_LOCAL);
    if (!handle) return 71;
    uint64_t (*call_host_direct)(void) =
        (uint64_t (*)(void))dlsym(handle, "call_host_direct");
    if (!call_host_direct) return 72;

    struct link_map *map = 0;
    if (dlinfo(handle, RTLD_DI_LINKMAP, &map) != 0 || !map) return 76;
    uintptr_t *slot = (uintptr_t *)(map->l_addr + UINT64_C(0x{host_jump_slot:x}));
    uintptr_t before = *slot;
    if (before == (uintptr_t)&host_function) return 77;

    if (call_host_direct() != UINT64_C(42)) return 73;
    uintptr_t after_first = *slot;
    if (after_first != (uintptr_t)&host_function) return 78;

    if (call_host_direct() != UINT64_C(43)) return 74;
    if (*slot != after_first) return 79;

    return dlclose(handle) == 0 ? 0 : 75;
}}
"#
            ),
        )
        .unwrap();
        let compile = Command::new("cc")
            .args(["-rdynamic", "-o"])
            .arg(&consumer)
            .arg(&source)
            .arg("-ldl")
            .output()
            .unwrap();
        assert!(
            compile.status.success(),
            "{}",
            String::from_utf8_lossy(&compile.stderr)
        );

        let status = Command::new(&consumer)
            .env_remove("LD_BIND_NOW")
            .arg(&shared)
            .status()
            .unwrap();
        assert!(status.success(), "PLT/JUMP_SLOT consumer returned {status}");
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn shared_plt_rejects_weak_notype_import() {
    if !command_reports("as", "GNU assembler") {
        return;
    }

    let dir = temp_dir("weak-notype");
    let object = assemble(
        &dir,
        "weak",
        r#".section .text
.globl call_weak
.type call_weak,@function
.weak weak_target
call_weak:
    call weak_target@PLT
    ret
.size call_weak, .-call_weak
"#,
    );
    let shared = dir.join("must-not-exist.so");

    let mini = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&shared)
        .arg("--shared")
        .arg(&object)
        .output()
        .unwrap();

    assert!(!mini.status.success());
    assert!(mini.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&mini.stderr);
    assert!(
        stderr.contains("PLT") || stderr.contains("symbol type"),
        "{stderr}"
    );
    assert!(!shared.exists());

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn static_link_does_not_inherit_shared_plt_import_semantics() {
    if !command_reports("as", "GNU assembler") {
        return;
    }

    let dir = temp_dir("static");
    let object = assemble(
        &dir,
        "static-plt",
        r#".section .text
.globl _start
.type _start,@function
.extern host_function
.type host_function,@function
_start:
    call host_function
    mov $60, %eax
    xor %edi, %edi
    syscall
.size _start, .-_start
"#,
    );
    let output = dir.join("must-not-link");

    let mini = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&output)
        .arg(&object)
        .output()
        .unwrap();

    assert!(!mini.status.success());
    assert!(mini.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&mini.stderr).contains("resolved global address"),
        "{}",
        String::from_utf8_lossy(&mini.stderr)
    );
    assert!(!output.exists());

    let _ = fs::remove_dir_all(dir);
}
