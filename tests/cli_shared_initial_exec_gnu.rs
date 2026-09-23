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
        "mini-elf-toolchain-shared-ie-tls-{label}-{}-{nonce}",
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
fn shared_initial_exec_tls_uses_loader_tpoff64_and_static_tls_instances() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("access");
    let object = assemble(
        &dir,
        "initial-exec",
        r#".section .tdata,"awT",@progbits
.align 8
.globl tls_ie
.type tls_ie,@tls_object
tls_ie:
    .quad 41
.size tls_ie, .-tls_ie

.section .text
.globl read_tls_ie
.type read_tls_ie,@function
read_tls_ie:
    mov tls_ie@gottpoff(%rip), %rax
    mov %fs:(%rax), %rax
    ret
.size read_tls_ie, .-read_tls_ie

.globl bump_tls_ie
.type bump_tls_ie,@function
bump_tls_ie:
    mov tls_ie@gottpoff(%rip), %rax
    addq $1, %fs:(%rax)
    ret
.size bump_tls_ie, .-bump_tls_ie
"#,
    );

    let input = Command::new("readelf")
        .args(["-rW"])
        .arg(&object)
        .output()
        .unwrap();
    assert!(input.status.success());
    let input = String::from_utf8_lossy(&input.stdout);
    assert!(input.contains("R_X86_64_GOTTPOFF"), "{input}");
    assert!(input.contains("tls_ie"), "{input}");

    let shared = dir.join("libinitialexec.so");
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

    let dynamic = Command::new("readelf")
        .args(["-dW"])
        .arg(&shared)
        .output()
        .unwrap();
    assert!(dynamic.status.success());
    let dynamic = String::from_utf8_lossy(&dynamic.stdout);
    assert!(
        dynamic.contains("FLAGS") && dynamic.contains("STATIC_TLS"),
        "initial-exec DSO must advertise DF_STATIC_TLS: {dynamic}"
    );

    let relocations = Command::new("readelf")
        .args(["-rW", "--use-dynamic"])
        .arg(&shared)
        .output()
        .unwrap();
    assert!(relocations.status.success());
    let relocations = String::from_utf8_lossy(&relocations.stdout);
    assert!(relocations.contains("R_X86_64_TPOFF64"), "{relocations}");
    assert!(relocations.contains("tls_ie"), "{relocations}");
    assert!(
        !relocations.contains("R_X86_64_DTPMOD64")
            && !relocations.contains("R_X86_64_DTPOFF64"),
        "initial-exec must use a TPOFF64 GOT relocation rather than a dynamic descriptor: {relocations}"
    );

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
    read_fn read_tls;
    bump_fn bump_tls;
    int result;
};

static void *worker(void *opaque) {
    struct ctx *ctx = (struct ctx *)opaque;
    if (ctx->read_tls() != 41) {
        ctx->result = 101;
        return 0;
    }
    ctx->bump_tls();
    if (ctx->read_tls() != 42) {
        ctx->result = 102;
        return 0;
    }
    ctx->result = 0;
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) return 90;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) return 91;
    read_fn read_tls = (read_fn)dlsym(handle, "read_tls_ie");
    bump_fn bump_tls = (bump_fn)dlsym(handle, "bump_tls_ie");
    if (!read_tls || !bump_tls) return 92;

    if (read_tls() != 41) return 93;
    bump_tls();
    if (read_tls() != 42) return 94;

    struct ctx ctx = { read_tls, bump_tls, -1 };
    pthread_t thread;
    if (pthread_create(&thread, 0, worker, &ctx) != 0) return 95;
    if (pthread_join(thread, 0) != 0) return 96;
    if (ctx.result != 0) return ctx.result;
    if (read_tls() != 42) return 97;

    return dlclose(handle) == 0 ? 0 : 98;
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
        assert!(status.success(), "initial-exec TLS runner returned {status}");
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn shared_initial_exec_tls_rejects_undefined_tls_symbol() {
    if !command_reports("as", "GNU assembler") {
        return;
    }

    let dir = temp_dir("undefined");
    let object = assemble(
        &dir,
        "undefined",
        r#".section .text
.globl read_external_ie
.type read_external_ie,@function
.extern external_tls
.type external_tls,@tls_object
read_external_ie:
    mov external_tls@gottpoff(%rip), %rax
    mov %fs:(%rax), %rax
    ret
.size read_external_ie, .-read_external_ie
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
        stderr.contains("initial-exec") || stderr.contains("defined"),
        "{stderr}"
    );
    assert!(!output.exists());

    let _ = fs::remove_dir_all(dir);
}
