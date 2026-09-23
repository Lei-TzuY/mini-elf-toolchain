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
        "mini-elf-toolchain-shared-tlsdesc-{label}-{}-{nonce}",
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
fn shared_tlsdesc_executes_defined_tls_across_threads() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("defined");
    let object = assemble(
        &dir,
        "tlsdesc",
        r#".section .tdata,"awT",@progbits
.align 8
.globl tlsdesc_value
.type tlsdesc_value,@tls_object
tlsdesc_value:
    .quad 0x123456789abcdef0
.size tlsdesc_value, .-tlsdesc_value

.section .text
.globl read_tlsdesc_value
.type read_tlsdesc_value,@function
read_tlsdesc_value:
    leaq tlsdesc_value@TLSDESC(%rip), %rax
    call *tlsdesc_value@TLSCALL(%rax)
    mov %fs:(%rax), %rax
    ret
.size read_tlsdesc_value, .-read_tlsdesc_value

.globl write_tlsdesc_value
.type write_tlsdesc_value,@function
write_tlsdesc_value:
    leaq tlsdesc_value@TLSDESC(%rip), %rax
    call *tlsdesc_value@TLSCALL(%rax)
    mov %rdi, %fs:(%rax)
    ret
.size write_tlsdesc_value, .-write_tlsdesc_value
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
        input_relocations.contains("R_X86_64_GOTPC32_TLSDESC"),
        "{input_relocations}"
    );
    assert!(
        input_relocations.contains("R_X86_64_TLSDESC_CALL"),
        "{input_relocations}"
    );

    let shared = dir.join("libtlsdesc.so");
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

    let relocations = Command::new("readelf")
        .args(["-rW", "--use-dynamic"])
        .arg(&shared)
        .output()
        .unwrap();
    assert!(relocations.status.success());
    let relocations = String::from_utf8_lossy(&relocations.stdout);
    assert!(relocations.contains("R_X86_64_TLSDESC"), "{relocations}");
    assert!(relocations.contains("tlsdesc_value"), "{relocations}");
    assert!(
        !relocations.contains("R_X86_64_DTPMOD64")
            && !relocations.contains("R_X86_64_DTPOFF64")
            && !relocations.contains("R_X86_64_TPOFF64"),
        "TLSDESC slice must remain descriptor-based without model relaxation: {relocations}"
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
            line.contains(" TLS ")
                && !line.contains(" UND ")
                && line.ends_with(" tlsdesc_value")
        }),
        "{symbols}"
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
typedef void (*write_fn)(uint64_t);

struct ctx {
    read_fn read_tls;
    write_fn write_tls;
    int result;
};

static void *worker(void *opaque) {
    struct ctx *ctx = (struct ctx *)opaque;
    if (ctx->read_tls() != UINT64_C(0x123456789abcdef0)) {
        ctx->result = 121;
        return 0;
    }
    ctx->write_tls(UINT64_C(0x2222222222222222));
    if (ctx->read_tls() != UINT64_C(0x2222222222222222)) {
        ctx->result = 122;
        return 0;
    }
    ctx->result = 0;
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) return 110;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) return 111;

    read_fn read_tls = (read_fn)dlsym(handle, "read_tlsdesc_value");
    write_fn write_tls = (write_fn)dlsym(handle, "write_tlsdesc_value");
    if (!read_tls || !write_tls) return 112;

    if (read_tls() != UINT64_C(0x123456789abcdef0)) return 113;
    write_tls(UINT64_C(0xaaaaaaaaaaaaaaaa));
    if (read_tls() != UINT64_C(0xaaaaaaaaaaaaaaaa)) return 114;

    struct ctx ctx = { read_tls, write_tls, -1 };
    pthread_t thread;
    if (pthread_create(&thread, 0, worker, &ctx) != 0) return 115;
    if (pthread_join(thread, 0) != 0) return 116;
    if (ctx.result != 0) return ctx.result;
    if (read_tls() != UINT64_C(0xaaaaaaaaaaaaaaaa)) return 117;

    return dlclose(handle) == 0 ? 0 : 118;
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
        assert!(status.success(), "TLSDESC runner returned {status}");
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn shared_tlsdesc_rejects_undefined_tls_symbol_in_first_slice() {
    if !command_reports("as", "GNU assembler") {
        return;
    }

    let dir = temp_dir("undefined");
    let object = assemble(
        &dir,
        "undefined",
        r#".section .text
.globl read_external_tlsdesc
.type read_external_tlsdesc,@function
.extern external_tlsdesc
.type external_tlsdesc,@tls_object
read_external_tlsdesc:
    leaq external_tlsdesc@TLSDESC(%rip), %rax
    call *external_tlsdesc@TLSCALL(%rax)
    mov %fs:(%rax), %rax
    ret
.size read_external_tlsdesc, .-read_external_tlsdesc
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
        stderr.contains("TLSDESC") || stderr.contains("defined"),
        "{stderr}"
    );
    assert!(!output.exists());

    let _ = fs::remove_dir_all(dir);
}
