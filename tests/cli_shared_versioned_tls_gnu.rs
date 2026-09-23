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
        "mini-elf-toolchain-versioned-tls-{label}-{}-{nonce}",
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

fn mini_provider(dir: &Path, version: &str) -> PathBuf {
    let object = assemble(
        dir,
        &format!("provider-{version}"),
        &format!(
            r#".section .tdata,"awT",@progbits
.align 8
.globl provider_tls_impl
.type provider_tls_impl,@tls_object
provider_tls_impl:
    .quad 0x123456789abcdef0
.size provider_tls_impl, .-provider_tls_impl
.symver provider_tls_impl,provider_tls@@{version}
"#
        ),
    );
    let shared = dir.join("libprovider.so");
    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&shared)
        .args(["--shared", "--soname", "libprovider.so"])
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    shared
}

fn consumer_object(dir: &Path) -> PathBuf {
    assemble(
        dir,
        "consumer",
        r#".section .text
.extern provider_tls
.type provider_tls,@tls_object
.symver provider_tls,provider_tls@VERS_1

.globl read_tls_gd
.type read_tls_gd,@function
read_tls_gd:
    leaq provider_tls@tlsgd(%rip), %rdi
    call __tls_get_addr@PLT
    mov (%rax), %rax
    ret
.size read_tls_gd, .-read_tls_gd

.globl write_tls_gd
.type write_tls_gd,@function
write_tls_gd:
    push %rbx
    mov %rdi, %rbx
    leaq provider_tls@tlsgd(%rip), %rdi
    call __tls_get_addr@PLT
    mov %rbx, (%rax)
    pop %rbx
    ret
.size write_tls_gd, .-write_tls_gd

.globl read_tls_ie
.type read_tls_ie,@function
read_tls_ie:
    mov provider_tls@gottpoff(%rip), %rax
    mov %fs:(%rax), %rax
    ret
.size read_tls_ie, .-read_tls_ie

.globl read_tls_desc
.type read_tls_desc,@function
read_tls_desc:
    leaq provider_tls@TLSDESC(%rip), %rax
    call *provider_tls@TLSCALL(%rax)
    mov %fs:(%rax), %rax
    ret
.size read_tls_desc, .-read_tls_desc
"#,
    )
}

#[test]
fn named_version_tls_import_composes_across_gd_ie_and_tlsdesc() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("runtime");
    let provider = mini_provider(&dir, "VERS_1");
    let object = consumer_object(&dir);

    let input_relocations = Command::new("readelf")
        .args(["-rW"])
        .arg(&object)
        .output()
        .unwrap();
    assert!(input_relocations.status.success());
    let input_relocations = String::from_utf8_lossy(&input_relocations.stdout);
    assert!(
        input_relocations.contains("R_X86_64_TLSGD"),
        "{input_relocations}"
    );
    assert!(
        input_relocations.contains("R_X86_64_GOTTPOFF"),
        "{input_relocations}"
    );
    assert!(
        input_relocations.contains("R_X86_64_GOTPC32_TLSDESC"),
        "{input_relocations}"
    );
    assert!(
        input_relocations.contains("R_X86_64_TLSDESC_CALL"),
        "{input_relocations}"
    );
    assert!(
        input_relocations.matches("provider_tls@VERS_1").count() >= 4,
        "{input_relocations}"
    );

    let provider_symbols = Command::new("readelf")
        .arg("-sDW")
        .arg(&provider)
        .output()
        .unwrap();
    assert!(provider_symbols.status.success());
    let provider_symbols = String::from_utf8_lossy(&provider_symbols.stdout);
    assert!(
        provider_symbols
            .lines()
            .any(|line| { line.contains(" TLS ") && line.contains("provider_tls@@VERS_1") }),
        "{provider_symbols}"
    );

    let consumer = dir.join("libconsumer.so");
    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&consumer)
        .args(["--shared", "--soname", "libconsumer.so"])
        .arg("--needed-from")
        .arg(&provider)
        .args(["--runpath", "$ORIGIN"])
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let symbols = Command::new("readelf")
        .arg("-sDW")
        .arg(&consumer)
        .output()
        .unwrap();
    assert!(symbols.status.success());
    let symbols = String::from_utf8_lossy(&symbols.stdout);
    assert!(
        symbols.lines().any(|line| {
            line.contains(" TLS ") && line.contains(" UND ") && line.contains("provider_tls@VERS_1")
        }),
        "{symbols}"
    );

    let dynamic = Command::new("readelf")
        .arg("-dW")
        .arg(&consumer)
        .output()
        .unwrap();
    assert!(dynamic.status.success());
    let dynamic = String::from_utf8_lossy(&dynamic.stdout);
    assert!(
        dynamic.contains("NEEDED") && dynamic.contains("libprovider.so"),
        "{dynamic}"
    );
    assert!(
        dynamic.contains("RUNPATH") && dynamic.contains("$ORIGIN"),
        "{dynamic}"
    );
    assert!(
        dynamic.contains("FLAGS") && dynamic.contains("STATIC_TLS"),
        "{dynamic}"
    );

    let relocations = Command::new("readelf")
        .args(["-rW", "--use-dynamic"])
        .arg(&consumer)
        .output()
        .unwrap();
    assert!(relocations.status.success());
    let relocations = String::from_utf8_lossy(&relocations.stdout);
    for relocation in [
        "R_X86_64_DTPMOD64",
        "R_X86_64_DTPOFF64",
        "R_X86_64_TPOFF64",
        "R_X86_64_TLSDESC",
    ] {
        assert!(relocations.contains(relocation), "{relocations}");
    }
    assert!(
        relocations.matches("provider_tls@VERS_1").count() >= 4,
        "{relocations}"
    );
    assert!(relocations.contains("R_X86_64_JUMP_SLOT"), "{relocations}");
    assert!(relocations.contains("__tls_get_addr"), "{relocations}");

    let versions = Command::new(env!("CARGO_BIN_EXE_mini-elf-vercheck"))
        .arg(&consumer)
        .output()
        .unwrap();
    assert!(
        versions.status.success(),
        "{}",
        String::from_utf8_lossy(&versions.stderr)
    );
    let versions = String::from_utf8_lossy(&versions.stdout);
    assert!(versions.contains("provider_tls"), "{versions}");
    assert!(versions.contains("source=requirement"), "{versions}");
    assert!(versions.contains("version=VERS_1"), "{versions}");

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
typedef void (*write_fn)(uint64_t);

struct ctx {
    read_fn read_gd;
    read_fn read_ie;
    read_fn read_desc;
    write_fn write_gd;
    int result;
};

static void *worker(void *opaque) {
    struct ctx *ctx = (struct ctx *)opaque;
    if (ctx->read_gd() != UINT64_C(0x123456789abcdef0)) {
        ctx->result = 101;
        return 0;
    }
    if (ctx->read_ie() != UINT64_C(0x123456789abcdef0)) {
        ctx->result = 102;
        return 0;
    }
    if (ctx->read_desc() != UINT64_C(0x123456789abcdef0)) {
        ctx->result = 103;
        return 0;
    }
    ctx->write_gd(UINT64_C(0x2222222222222222));
    if (ctx->read_ie() != UINT64_C(0x2222222222222222)
        || ctx->read_desc() != UINT64_C(0x2222222222222222)) {
        ctx->result = 104;
        return 0;
    }
    ctx->result = 0;
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) return 90;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) return 91;

    read_fn read_gd = (read_fn)dlsym(handle, "read_tls_gd");
    read_fn read_ie = (read_fn)dlsym(handle, "read_tls_ie");
    read_fn read_desc = (read_fn)dlsym(handle, "read_tls_desc");
    write_fn write_gd = (write_fn)dlsym(handle, "write_tls_gd");
    if (!read_gd || !read_ie || !read_desc || !write_gd) return 92;

    if (read_gd() != UINT64_C(0x123456789abcdef0)) return 93;
    if (read_ie() != UINT64_C(0x123456789abcdef0)) return 94;
    if (read_desc() != UINT64_C(0x123456789abcdef0)) return 95;

    write_gd(UINT64_C(0xaaaaaaaaaaaaaaaa));
    if (read_ie() != UINT64_C(0xaaaaaaaaaaaaaaaa)) return 96;
    if (read_desc() != UINT64_C(0xaaaaaaaaaaaaaaaa)) return 97;

    struct ctx ctx = { read_gd, read_ie, read_desc, write_gd, -1 };
    pthread_t thread;
    if (pthread_create(&thread, 0, worker, &ctx) != 0) return 98;
    if (pthread_join(thread, 0) != 0) return 99;
    if (ctx.result != 0) return ctx.result;

    if (read_gd() != UINT64_C(0xaaaaaaaaaaaaaaaa)) return 105;
    if (read_ie() != UINT64_C(0xaaaaaaaaaaaaaaaa)) return 106;
    if (read_desc() != UINT64_C(0xaaaaaaaaaaaaaaaa)) return 107;

    return dlclose(handle) == 0 ? 0 : 108;
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

        let status = Command::new(&runner).arg(&consumer).status().unwrap();
        assert!(status.success(), "versioned TLS consumer returned {status}");
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn named_version_tls_import_rejects_different_provider_version() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("mismatch");
    let provider = mini_provider(&dir, "VERS_2");
    let object = consumer_object(&dir);
    let output = dir.join("must-not-exist.so");

    let mini = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&output)
        .arg("--shared")
        .arg("--needed-from")
        .arg(&provider)
        .arg(&object)
        .output()
        .unwrap();

    assert!(!mini.status.success());
    assert!(mini.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&mini.stderr);
    assert!(
        stderr.contains("VERS_1") || stderr.contains("version"),
        "{stderr}"
    );
    assert!(!output.exists());

    let _ = fs::remove_dir_all(dir);
}
