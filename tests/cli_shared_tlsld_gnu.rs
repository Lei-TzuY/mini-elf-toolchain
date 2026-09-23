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
        "mini-elf-toolchain-shared-tlsld-{label}-{}-{nonce}",
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

#[test]
fn shared_local_dynamic_tls_reuses_module_base_for_multiple_symbols() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("access");
    let object = assemble(
        &dir,
        "tlsld",
        r#".section .tdata,"awT",@progbits
.align 8
.local tls_a
.type tls_a,@tls_object
tls_a:
    .quad 11
.size tls_a, .-tls_a

.section .tbss,"awT",@nobits
.align 8
.local tls_b
.type tls_b,@tls_object
tls_b:
    .zero 8
.size tls_b, .-tls_b

.section .text
.globl read_tls_pair
.type read_tls_pair,@function
read_tls_pair:
    leaq tls_a@tlsld(%rip), %rdi
    call __tls_get_addr@PLT
    mov tls_a@dtpoff(%rax), %rcx
    add tls_b@dtpoff(%rax), %rcx
    mov %rcx, %rax
    ret
.size read_tls_pair, .-read_tls_pair

.globl bump_tls_pair
.type bump_tls_pair,@function
bump_tls_pair:
    leaq tls_a@tlsld(%rip), %rdi
    call __tls_get_addr@PLT
    addq $1, tls_a@dtpoff(%rax)
    addq $1, tls_b@dtpoff(%rax)
    ret
.size bump_tls_pair, .-bump_tls_pair
"#,
    );

    let input = Command::new("readelf")
        .args(["-rW"])
        .arg(&object)
        .output()
        .unwrap();
    assert!(input.status.success());
    let input = String::from_utf8_lossy(&input.stdout);
    assert!(input.contains("R_X86_64_TLSLD"), "{input}");
    assert!(input.contains("R_X86_64_DTPOFF32"), "{input}");
    assert!(input.contains("__tls_get_addr"), "{input}");

    let shared = dir.join("libtlsld.so");
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

    let headers = Command::new("readelf")
        .args(["-lW"])
        .arg(&shared)
        .output()
        .unwrap();
    assert!(headers.status.success());
    assert!(String::from_utf8_lossy(&headers.stdout).contains("TLS"));

    let relocations = Command::new("readelf")
        .args(["-rW", "--use-dynamic"])
        .arg(&shared)
        .output()
        .unwrap();
    assert!(relocations.status.success());
    let relocations = String::from_utf8_lossy(&relocations.stdout);
    assert!(relocations.contains("R_X86_64_DTPMOD64"), "{relocations}");
    assert!(
        !relocations.contains("R_X86_64_DTPOFF64"),
        "TLSLD must link local offsets instead of emitting per-symbol DTPOFF64: {relocations}"
    );
    assert!(relocations.contains("R_X86_64_JUMP_SLOT"), "{relocations}");
    assert!(relocations.contains("__tls_get_addr"), "{relocations}");

    let symbols = Command::new("readelf")
        .arg("-sDW")
        .arg(&shared)
        .output()
        .unwrap();
    assert!(symbols.status.success());
    let symbols = String::from_utf8_lossy(&symbols.stdout);
    assert!(!symbols.lines().any(|line| line.ends_with(" tls_a")));
    assert!(!symbols.lines().any(|line| line.ends_with(" tls_b")));

    #[cfg(target_os = "linux")]
    {
        let source = dir.join("runner.c");
        let runner = dir.join("runner");
        fs::write(
            &source,
            r#"#include <dlfcn.h>
#include <pthread.h>
#include <stdint.h>

typedef uint64_t (*read_fn)(void);
typedef void (*bump_fn)(void);

struct ctx {
    read_fn read_pair;
    bump_fn bump_pair;
    int result;
};

static void *worker(void *opaque) {
    struct ctx *ctx = (struct ctx *)opaque;
    if (ctx->read_pair() != 11) {
        ctx->result = 91;
        return 0;
    }
    ctx->bump_pair();
    if (ctx->read_pair() != 13) {
        ctx->result = 92;
        return 0;
    }
    ctx->result = 0;
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) return 80;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) return 81;
    read_fn read_pair = (read_fn)dlsym(handle, "read_tls_pair");
    bump_fn bump_pair = (bump_fn)dlsym(handle, "bump_tls_pair");
    if (!read_pair || !bump_pair) return 82;

    if (read_pair() != 11) return 83;
    bump_pair();
    if (read_pair() != 13) return 84;

    struct ctx ctx = { read_pair, bump_pair, -1 };
    pthread_t thread;
    if (pthread_create(&thread, 0, worker, &ctx) != 0) return 85;
    if (pthread_join(thread, 0) != 0) return 86;
    if (ctx.result != 0) return ctx.result;
    if (read_pair() != 13) return 87;

    return dlclose(handle) == 0 ? 0 : 88;
}
"#,
        )
        .unwrap();

        let compile = Command::new("cc")
            .args(["-o"])
            .arg(&runner)
            .arg(&source)
            .args(["-ldl", "-pthread"])
            .output()
            .unwrap();
        assert!(
            compile.status.success(),
            "{}",
            String::from_utf8_lossy(&compile.stderr)
        );

        let status = Command::new(&runner).arg(&shared).status().unwrap();
        assert!(status.success(), "TLSLD runner returned {status}");
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn shared_tlsld_rejects_nonlocal_tls_symbols() {
    if !command_reports("as", "GNU assembler") {
        return;
    }

    let dir = temp_dir("nonlocal");
    let object = assemble(
        &dir,
        "nonlocal",
        r#".section .tdata,"awT",@progbits
.globl nonlocal_tls
.type nonlocal_tls,@tls_object
nonlocal_tls:
    .quad 3
.size nonlocal_tls, .-nonlocal_tls

.section .text
.globl read_nonlocal
.type read_nonlocal,@function
read_nonlocal:
    leaq nonlocal_tls@tlsld(%rip), %rdi
    call __tls_get_addr@PLT
    mov nonlocal_tls@dtpoff(%rax), %rax
    ret
.size read_nonlocal, .-read_nonlocal
"#,
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
        stderr.contains("local-dynamic") || stderr.contains("local TLS"),
        "{stderr}"
    );
    assert!(!output.exists());

    let _ = fs::remove_dir_all(dir);
}
