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
        "mini-elf-toolchain-shared-tls-{label}-{}-{nonce}",
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
fn shared_tls_exports_are_loader_allocated_per_thread() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("exports");
    let object = assemble(
        &dir,
        "tls",
        r#".section .tdata,"awT",@progbits
.align 8
.globl tls_init
.type tls_init,@tls_object
tls_init:
    .quad 0x1122334455667788
.size tls_init, .-tls_init

.section .tbss,"awT",@nobits
.align 8
.globl tls_zero
.type tls_zero,@tls_object
tls_zero:
    .zero 8
.size tls_zero, .-tls_zero
"#,
    );

    let ours = dir.join("libtls-mini.so");
    let mini = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&ours)
        .arg("--shared")
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        mini.status.success(),
        "{}",
        String::from_utf8_lossy(&mini.stderr)
    );

    let gnu = dir.join("libtls-gnu.so");
    let gnu_link = Command::new("ld")
        .args(["-shared", "-o"])
        .arg(&gnu)
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        gnu_link.status.success(),
        "{}",
        String::from_utf8_lossy(&gnu_link.stderr)
    );

    for shared in [&ours, &gnu] {
        let headers = Command::new("readelf")
            .args(["-lW"])
            .arg(shared)
            .output()
            .unwrap();
        assert!(headers.status.success());
        assert!(
            String::from_utf8_lossy(&headers.stdout).contains("TLS"),
            "{} is missing PT_TLS",
            shared.display()
        );

        let symbols = Command::new("readelf")
            .arg("-sDW")
            .arg(shared)
            .output()
            .unwrap();
        assert!(symbols.status.success());
        let symbols = String::from_utf8_lossy(&symbols.stdout);
        assert!(
            symbols.lines().any(|line| {
                line.contains(" TLS ") && line.ends_with(" tls_init")
            }),
            "{} is missing dynamic STT_TLS tls_init: {symbols}",
            shared.display()
        );
        assert!(
            symbols.lines().any(|line| {
                line.contains(" TLS ") && line.ends_with(" tls_zero")
            }),
            "{} is missing dynamic STT_TLS tls_zero: {symbols}",
            shared.display()
        );
    }

    #[cfg(target_os = "linux")]
    {
        let source = dir.join("consumer.c");
        let consumer = dir.join("consumer");
        fs::write(
            &source,
            r#"#include <dlfcn.h>
#include <pthread.h>
#include <stdint.h>

struct thread_ctx {
    void *handle;
    int result;
};

static void *worker(void *opaque) {
    struct thread_ctx *ctx = (struct thread_ctx *)opaque;
    uint64_t *tls_init = (uint64_t *)dlsym(ctx->handle, "tls_init");
    uint64_t *tls_zero = (uint64_t *)dlsym(ctx->handle, "tls_zero");
    if (!tls_init || !tls_zero) {
        ctx->result = 61;
        return 0;
    }
    if (*tls_init != UINT64_C(0x1122334455667788) || *tls_zero != 0) {
        ctx->result = 62;
        return 0;
    }
    *tls_init = UINT64_C(0x2222222222222222);
    *tls_zero = UINT64_C(0x3333333333333333);
    if (*tls_init != UINT64_C(0x2222222222222222)
        || *tls_zero != UINT64_C(0x3333333333333333)) {
        ctx->result = 63;
        return 0;
    }
    ctx->result = 0;
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) return 50;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) return 51;

    uint64_t *tls_init = (uint64_t *)dlsym(handle, "tls_init");
    uint64_t *tls_zero = (uint64_t *)dlsym(handle, "tls_zero");
    if (!tls_init || !tls_zero) return 52;
    if (*tls_init != UINT64_C(0x1122334455667788) || *tls_zero != 0) return 53;

    *tls_init = UINT64_C(0xaaaaaaaaaaaaaaaa);
    *tls_zero = UINT64_C(0xbbbbbbbbbbbbbbbb);

    struct thread_ctx ctx = { handle, -1 };
    pthread_t thread;
    if (pthread_create(&thread, 0, worker, &ctx) != 0) return 54;
    if (pthread_join(thread, 0) != 0) return 55;
    if (ctx.result != 0) return ctx.result;

    if (*tls_init != UINT64_C(0xaaaaaaaaaaaaaaaa)) return 56;
    if (*tls_zero != UINT64_C(0xbbbbbbbbbbbbbbbb)) return 57;

    return dlclose(handle) == 0 ? 0 : 58;
}
"#,
        )
        .unwrap();
        let compile = Command::new("cc")
            .args(["-o"])
            .arg(&consumer)
            .arg(&source)
            .args(["-ldl", "-pthread"])
            .output()
            .unwrap();
        assert!(
            compile.status.success(),
            "{}",
            String::from_utf8_lossy(&compile.stderr)
        );

        for shared in [&ours, &gnu] {
            let status = Command::new(&consumer).arg(shared).status().unwrap();
            assert!(
                status.success(),
                "{} TLS consumer returned {status}",
                shared.display()
            );
        }
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn shared_tls_relocation_remains_fail_closed() {
    if !command_reports("as", "GNU assembler") {
        return;
    }

    let dir = temp_dir("relocation");
    let object = assemble(
        &dir,
        "tls-relocation",
        r#".section .tdata,"awT",@progbits
.globl tls_value
.type tls_value,@tls_object
tls_value:
    .quad 7
.size tls_value, .-tls_value

.section .text
.globl tls_offset
.type tls_offset,@function
tls_offset:
    mov tls_value@gottpoff(%rip), %rax
    ret
.size tls_offset, .-tls_offset
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
    assert!(
        String::from_utf8_lossy(&mini.stderr).contains("TLS"),
        "{}",
        String::from_utf8_lossy(&mini.stderr)
    );
    assert!(!output.exists());

    let _ = fs::remove_dir_all(dir);
}
