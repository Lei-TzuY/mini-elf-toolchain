use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const WEAK_TLS: &str = "mini_elf_optional_weak_tls_324";

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
        "mini-elf-toolchain-weak-tlsgd-{label}-{}-{nonce}",
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

fn consumer_object(dir: &Path) -> PathBuf {
    assemble(
        dir,
        "consumer",
        &format!(
            r#".section .note.GNU-stack,"",@progbits
.text
.globl read_optional_tls
.type read_optional_tls,@function
.weak {WEAK_TLS}
.type {WEAK_TLS},@tls_object
read_optional_tls:
    leaq {WEAK_TLS}@tlsgd(%rip), %rdi
    call __tls_get_addr@PLT
    mov (%rax), %rax
    ret
.size read_optional_tls, .-read_optional_tls

.globl write_optional_tls
.type write_optional_tls,@function
write_optional_tls:
    push %rbx
    mov %rdi, %rbx
    leaq {WEAK_TLS}@tlsgd(%rip), %rdi
    call __tls_get_addr@PLT
    mov %rbx, (%rax)
    pop %rbx
    ret
.size write_optional_tls, .-write_optional_tls
"#
        ),
    )
}

fn assert_weak_tlsgd_metadata(shared: &Path) {
    let symbols = Command::new("readelf")
        .arg("-sDW")
        .arg(shared)
        .output()
        .unwrap();
    assert!(symbols.status.success());
    let symbols = String::from_utf8_lossy(&symbols.stdout);
    assert!(
        symbols.lines().any(|line| {
            line.contains("WEAK")
                && line.contains(" TLS ")
                && line.contains(" UND ")
                && line.ends_with(WEAK_TLS)
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
        relocations.lines().any(|line| {
            line.contains("R_X86_64_DTPMOD64") && line.contains(WEAK_TLS)
        }),
        "{} dynamic relocations:\n{relocations}",
        shared.display()
    );
    assert!(
        relocations.lines().any(|line| {
            line.contains("R_X86_64_DTPOFF64") && line.contains(WEAK_TLS)
        }),
        "{} dynamic relocations:\n{relocations}",
        shared.display()
    );
    assert!(
        relocations
            .lines()
            .any(|line| { line.contains("R_X86_64_JUMP_SLOT") && line.contains("__tls_get_addr") }),
        "{} dynamic relocations:\n{relocations}",
        shared.display()
    );
}

#[test]
fn weak_tlsgd_matches_gnu_and_binds_host_tls_per_thread() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("runtime");
    let object = consumer_object(&dir);

    let input_symbols = Command::new("readelf")
        .arg("-sW")
        .arg(&object)
        .output()
        .unwrap();
    assert!(input_symbols.status.success());
    let input_symbols = String::from_utf8_lossy(&input_symbols.stdout);
    assert!(
        input_symbols.lines().any(|line| {
            line.contains("WEAK")
                && line.contains(" TLS ")
                && line.contains(" UND ")
                && line.ends_with(WEAK_TLS)
        }),
        "{input_symbols}"
    );

    let input_relocations = Command::new("readelf")
        .arg("-rW")
        .arg(&object)
        .output()
        .unwrap();
    assert!(input_relocations.status.success());
    let input_relocations = String::from_utf8_lossy(&input_relocations.stdout);
    assert!(
        input_relocations.contains("R_X86_64_TLSGD")
            && input_relocations.contains(WEAK_TLS)
            && input_relocations.contains("__tls_get_addr"),
        "{input_relocations}"
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
        assert_weak_tlsgd_metadata(shared);
    }

    #[cfg(target_os = "linux")]
    {
        let absent_source = dir.join("absent.c");
        let absent_runner = dir.join("absent");
        fs::write(
            &absent_source,
            r#"#include <dlfcn.h>

int main(int argc, char **argv) {
    if (argc != 2) return 200;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) return 201;
    if (!dlsym(handle, "read_optional_tls")) return 202;
    if (!dlsym(handle, "write_optional_tls")) return 203;
    return dlclose(handle) == 0 ? 0 : 204;
}
"#,
        )
        .unwrap();
        let absent_compile = Command::new("cc")
            .args(["-o"])
            .arg(&absent_runner)
            .arg(&absent_source)
            .args(["-ldl", "-pthread"])
            .output()
            .unwrap();
        assert!(
            absent_compile.status.success(),
            "{}",
            String::from_utf8_lossy(&absent_compile.stderr)
        );

        let bound_source = dir.join("bound.c");
        let bound_runner = dir.join("bound");
        fs::write(
            &bound_source,
            format!(
                r#"#include <dlfcn.h>
#include <pthread.h>
#include <stdint.h>

__thread uint64_t {WEAK_TLS} = UINT64_C(0x1122334455667788);

typedef uint64_t (*read_fn)(void);
typedef void (*write_fn)(uint64_t);

struct ctx {{
    read_fn read_tls;
    write_fn write_tls;
    int result;
}};

static void *worker(void *opaque) {{
    struct ctx *ctx = (struct ctx *)opaque;
    if (ctx->read_tls() != UINT64_C(0x1122334455667788)) {{
        ctx->result = 211;
        return 0;
    }}
    ctx->write_tls(UINT64_C(0x3333333333333333));
    if (ctx->read_tls() != UINT64_C(0x3333333333333333)) {{
        ctx->result = 212;
        return 0;
    }}
    ctx->result = 0;
    return 0;
}}

int main(int argc, char **argv) {{
    if (argc != 2) return 205;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) return 206;
    read_fn read_tls = (read_fn)dlsym(handle, "read_optional_tls");
    write_fn write_tls = (write_fn)dlsym(handle, "write_optional_tls");
    if (!read_tls || !write_tls) return 207;

    if (read_tls() != UINT64_C(0x1122334455667788)) return 208;
    write_tls(UINT64_C(0xaaaaaaaaaaaaaaaa));
    if (read_tls() != UINT64_C(0xaaaaaaaaaaaaaaaa)) return 209;

    struct ctx ctx = {{ read_tls, write_tls, -1 }};
    pthread_t thread;
    if (pthread_create(&thread, 0, worker, &ctx) != 0) return 210;
    if (pthread_join(thread, 0) != 0) return 213;
    if (ctx.result != 0) return ctx.result;
    if (read_tls() != UINT64_C(0xaaaaaaaaaaaaaaaa)) return 214;

    return dlclose(handle) == 0 ? 0 : 215;
}}
"#
            ),
        )
        .unwrap();
        let bound_compile = Command::new("cc")
            .args(["-rdynamic", "-o"])
            .arg(&bound_runner)
            .arg(&bound_source)
            .args(["-ldl", "-pthread"])
            .output()
            .unwrap();
        assert!(
            bound_compile.status.success(),
            "{}",
            String::from_utf8_lossy(&bound_compile.stderr)
        );

        for shared in [&mini, &gnu] {
            let absent = Command::new(&absent_runner).arg(shared).status().unwrap();
            assert!(
                absent.success(),
                "weak TLSGD absent-symbol load returned {absent} for {}",
                shared.display()
            );

            let bound = Command::new(&bound_runner).arg(shared).status().unwrap();
            assert!(
                bound.success(),
                "weak TLSGD host-binding runtime returned {bound} for {}",
                shared.display()
            );
        }
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn versioned_weak_tlsgd_remains_fail_closed_with_matching_provider() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("versioned-boundary");
    let provider_object = assemble(
        &dir,
        "provider",
        r#".section .tdata,"awT",@progbits
.align 8
.globl provider_tls
.type provider_tls,@tls_object
provider_tls:
    .quad 0x55
.size provider_tls, .-provider_tls
"#,
    );
    let map = dir.join("provider.map");
    fs::write(&map, "VERS_1 { global: provider_tls; local: *; };\n").unwrap();
    let provider = dir.join("libprovider.so");
    let provider_link = Command::new("ld")
        .args(["-shared", "--hash-style=sysv", "--soname=libprovider.so"])
        .arg(format!("--version-script={}", map.display()))
        .args(["-o"])
        .arg(&provider)
        .arg(&provider_object)
        .output()
        .unwrap();
    assert!(
        provider_link.status.success(),
        "{}",
        String::from_utf8_lossy(&provider_link.stderr)
    );

    let consumer = assemble(
        &dir,
        "versioned-consumer",
        r#".section .note.GNU-stack,"",@progbits
.text
.globl read_provider_tls
.type read_provider_tls,@function
.weak provider_tls
.type provider_tls,@tls_object
.symver provider_tls,provider_tls@VERS_1
read_provider_tls:
    leaq provider_tls@tlsgd(%rip), %rdi
    call __tls_get_addr@PLT
    mov (%rax), %rax
    ret
.size read_provider_tls, .-read_provider_tls
"#,
    );
    let output = dir.join("must-not-exist.so");
    let mini = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&output)
        .args(["--shared", "--needed-from"])
        .arg(&provider)
        .arg(&consumer)
        .output()
        .unwrap();

    assert!(!mini.status.success());
    assert!(mini.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&mini.stderr);
    assert!(
        stderr.contains("TLS import") || stderr.contains("version") || stderr.contains("weak"),
        "{stderr}"
    );
    assert!(!output.exists());

    let _ = fs::remove_dir_all(dir);
}
