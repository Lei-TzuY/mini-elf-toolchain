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
        "mini-elf-toolchain-shared-tlsgd-import-{label}-{}-{nonce}",
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
fn shared_tlsgd_import_binds_provider_tls_and_preserves_thread_instances() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("provider");
    let provider_object = assemble(
        &dir,
        "provider",
        r#".section .tdata,"awT",@progbits
.align 8
.globl provider_tls
.type provider_tls,@tls_object
provider_tls:
    .quad 0x123456789abcdef0
.size provider_tls, .-provider_tls
"#,
    );
    let provider = dir.join("libprovider.so");
    let provider_link = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&provider)
        .args(["--shared", "--soname", "libprovider.so"])
        .arg(&provider_object)
        .output()
        .unwrap();
    assert!(
        provider_link.status.success(),
        "{}",
        String::from_utf8_lossy(&provider_link.stderr)
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
            .any(|line| line.contains(" TLS ") && line.ends_with(" provider_tls")),
        "{provider_symbols}"
    );

    let consumer_object = assemble(
        &dir,
        "consumer",
        r#".section .text
.globl read_provider_tls
.type read_provider_tls,@function
.extern provider_tls
.type provider_tls,@tls_object
read_provider_tls:
    leaq provider_tls@tlsgd(%rip), %rdi
    call __tls_get_addr@PLT
    mov (%rax), %rax
    ret
.size read_provider_tls, .-read_provider_tls

.globl write_provider_tls
.type write_provider_tls,@function
write_provider_tls:
    push %rbx
    mov %rdi, %rbx
    leaq provider_tls@tlsgd(%rip), %rdi
    call __tls_get_addr@PLT
    mov %rbx, (%rax)
    pop %rbx
    ret
.size write_provider_tls, .-write_provider_tls
"#,
    );

    let input_relocations = Command::new("readelf")
        .args(["-rW"])
        .arg(&consumer_object)
        .output()
        .unwrap();
    assert!(input_relocations.status.success());
    let input_relocations = String::from_utf8_lossy(&input_relocations.stdout);
    assert!(input_relocations.contains("R_X86_64_TLSGD"), "{input_relocations}");
    assert!(input_relocations.contains("provider_tls"), "{input_relocations}");
    assert!(input_relocations.contains("__tls_get_addr"), "{input_relocations}");

    let consumer = dir.join("libconsumer.so");
    let consumer_link = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&consumer)
        .args(["--shared", "--soname", "libconsumer.so"])
        .arg("--needed-from")
        .arg(&provider)
        .args(["--runpath", "$ORIGIN"])
        .arg(&consumer_object)
        .output()
        .unwrap();
    assert!(
        consumer_link.status.success(),
        "{}",
        String::from_utf8_lossy(&consumer_link.stderr)
    );

    let dynamic = Command::new("readelf")
        .arg("-dW")
        .arg(&consumer)
        .output()
        .unwrap();
    assert!(dynamic.status.success());
    let dynamic = String::from_utf8_lossy(&dynamic.stdout);
    assert!(dynamic.contains("NEEDED") && dynamic.contains("libprovider.so"), "{dynamic}");
    assert!(dynamic.contains("RUNPATH") && dynamic.contains("$ORIGIN"), "{dynamic}");

    let symbols = Command::new("readelf")
        .arg("-sDW")
        .arg(&consumer)
        .output()
        .unwrap();
    assert!(symbols.status.success());
    let symbols = String::from_utf8_lossy(&symbols.stdout);
    assert!(
        symbols
            .lines()
            .any(|line| line.contains(" TLS ") && line.contains(" UND ") && line.ends_with(" provider_tls")),
        "{symbols}"
    );

    let relocations = Command::new("readelf")
        .args(["-rW", "--use-dynamic"])
        .arg(&consumer)
        .output()
        .unwrap();
    assert!(relocations.status.success());
    let relocations = String::from_utf8_lossy(&relocations.stdout);
    assert!(relocations.contains("R_X86_64_DTPMOD64"), "{relocations}");
    assert!(relocations.contains("R_X86_64_DTPOFF64"), "{relocations}");
    assert!(relocations.contains("provider_tls"), "{relocations}");
    assert!(relocations.contains("R_X86_64_JUMP_SLOT"), "{relocations}");
    assert!(relocations.contains("__tls_get_addr"), "{relocations}");

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
    read_fn read_tls;
    write_fn write_tls;
    int result;
};

static void *worker(void *opaque) {
    struct ctx *ctx = (struct ctx *)opaque;
    if (ctx->read_tls() != UINT64_C(0x123456789abcdef0)) {
        ctx->result = 81;
        return 0;
    }
    ctx->write_tls(UINT64_C(0x2222222222222222));
    if (ctx->read_tls() != UINT64_C(0x2222222222222222)) {
        ctx->result = 82;
        return 0;
    }
    ctx->result = 0;
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) return 70;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) return 71;
    read_fn read_tls = (read_fn)dlsym(handle, "read_provider_tls");
    write_fn write_tls = (write_fn)dlsym(handle, "write_provider_tls");
    if (!read_tls || !write_tls) return 72;

    if (read_tls() != UINT64_C(0x123456789abcdef0)) return 73;
    write_tls(UINT64_C(0xaaaaaaaaaaaaaaaa));
    if (read_tls() != UINT64_C(0xaaaaaaaaaaaaaaaa)) return 74;

    struct ctx ctx = { read_tls, write_tls, -1 };
    pthread_t thread;
    if (pthread_create(&thread, 0, worker, &ctx) != 0) return 75;
    if (pthread_join(thread, 0) != 0) return 76;
    if (ctx.result != 0) return ctx.result;
    if (read_tls() != UINT64_C(0xaaaaaaaaaaaaaaaa)) return 77;

    return dlclose(handle) == 0 ? 0 : 78;
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
        assert!(status.success(), "cross-DSO TLSGD runner returned {status}");
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn shared_tlsgd_provider_matching_requires_tls_symbol_type() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("type-mismatch");
    let provider_object = assemble(
        &dir,
        "wrong-provider",
        r#".section .data
.globl provider_tls
.type provider_tls,@object
provider_tls:
    .quad 7
.size provider_tls, .-provider_tls
"#,
    );
    let provider = dir.join("libwrong.so");
    let provider_link = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&provider)
        .args(["--shared", "--soname", "libwrong.so"])
        .arg(&provider_object)
        .output()
        .unwrap();
    assert!(provider_link.status.success());

    let consumer_object = assemble(
        &dir,
        "tls-consumer",
        r#".section .text
.globl read_provider_tls
.type read_provider_tls,@function
.extern provider_tls
.type provider_tls,@tls_object
read_provider_tls:
    leaq provider_tls@tlsgd(%rip), %rdi
    call __tls_get_addr@PLT
    mov (%rax), %rax
    ret
.size read_provider_tls, .-read_provider_tls
"#,
    );
    let output = dir.join("must-not-exist.so");
    let consumer_link = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&output)
        .arg("--shared")
        .arg("--needed-from")
        .arg(&provider)
        .arg(&consumer_object)
        .output()
        .unwrap();

    assert!(!consumer_link.status.success());
    assert!(consumer_link.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&consumer_link.stderr);
    assert!(
        stderr.contains("exports none") || stderr.contains("bounded external imports"),
        "{stderr}"
    );
    assert!(!output.exists());

    let _ = fs::remove_dir_all(dir);
}
