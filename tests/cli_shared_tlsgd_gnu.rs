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
        "mini-elf-toolchain-shared-tlsgd-{label}-{}-{nonce}",
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
fn shared_defined_tls_is_accessible_through_general_dynamic_model() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("access");
    let object = assemble(
        &dir,
        "tlsgd",
        r#".section .tdata,"awT",@progbits
.align 8
.globl tls_value
.type tls_value,@tls_object
tls_value:
    .quad 0x1122334455667788
.size tls_value, .-tls_value

.section .text
.globl read_tls
.type read_tls,@function
read_tls:
    leaq tls_value@tlsgd(%rip), %rdi
    call __tls_get_addr@PLT
    mov (%rax), %rax
    ret
.size read_tls, .-read_tls

.globl write_tls
.type write_tls,@function
write_tls:
    push %rbx
    mov %rdi, %rbx
    leaq tls_value@tlsgd(%rip), %rdi
    call __tls_get_addr@PLT
    mov %rbx, (%rax)
    pop %rbx
    ret
.size write_tls, .-write_tls
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
        input_relocations.contains("R_X86_64_TLSGD"),
        "{input_relocations}"
    );
    assert!(
        input_relocations.contains("__tls_get_addr"),
        "{input_relocations}"
    );
    assert!(
        input_relocations.contains("R_X86_64_PLT32"),
        "{input_relocations}"
    );

    let shared = dir.join("libtlsgd.so");
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
    assert!(relocations.contains("R_X86_64_DTPMOD64"), "{relocations}");
    assert!(relocations.contains("R_X86_64_DTPOFF64"), "{relocations}");
    assert!(relocations.contains("tls_value"), "{relocations}");
    assert!(relocations.contains("R_X86_64_JUMP_SLOT"), "{relocations}");
    assert!(relocations.contains("__tls_get_addr"), "{relocations}");

    #[cfg(target_os = "linux")]
    {
        let source = dir.join("consumer.c");
        let consumer = dir.join("consumer");
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
    if (ctx->read_tls() != UINT64_C(0x1122334455667788)) {
        ctx->result = 71;
        return 0;
    }
    ctx->write_tls(UINT64_C(0x3333333333333333));
    if (ctx->read_tls() != UINT64_C(0x3333333333333333)) {
        ctx->result = 72;
        return 0;
    }
    ctx->result = 0;
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) return 60;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) return 61;
    read_fn read_tls = (read_fn)dlsym(handle, "read_tls");
    write_fn write_tls = (write_fn)dlsym(handle, "write_tls");
    if (!read_tls || !write_tls) return 62;
    if (read_tls() != UINT64_C(0x1122334455667788)) return 63;

    write_tls(UINT64_C(0xaaaaaaaaaaaaaaaa));
    if (read_tls() != UINT64_C(0xaaaaaaaaaaaaaaaa)) return 64;

    struct ctx ctx = { read_tls, write_tls, -1 };
    pthread_t thread;
    if (pthread_create(&thread, 0, worker, &ctx) != 0) return 65;
    if (pthread_join(thread, 0) != 0) return 66;
    if (ctx.result != 0) return ctx.result;
    if (read_tls() != UINT64_C(0xaaaaaaaaaaaaaaaa)) return 67;

    return dlclose(handle) == 0 ? 0 : 68;
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

        let status = Command::new(&consumer).arg(&shared).status().unwrap();
        assert!(status.success(), "TLSGD consumer returned {status}");
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn shared_tlsgd_remains_bounded_to_defined_tls_symbols() {
    if !command_reports("as", "GNU assembler") {
        return;
    }

    let dir = temp_dir("undefined");
    let object = assemble(
        &dir,
        "undefined",
        r#".section .text
.globl read_external_tls
.type read_external_tls,@function
.extern external_tls
.type external_tls,@tls_object
read_external_tls:
    leaq external_tls@tlsgd(%rip), %rdi
    call __tls_get_addr@PLT
    mov (%rax), %rax
    ret
.size read_external_tls, .-read_external_tls
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
        stderr.contains("TLS import") || stderr.contains("undefined TLS"),
        "{stderr}"
    );
    assert!(!output.exists());

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn shared_tlsgd_notype_plt_exception_is_specific_to_tls_get_addr() {
    if !command_reports("as", "GNU assembler") {
        return;
    }

    let dir = temp_dir("notype-plt");
    let object = assemble(
        &dir,
        "notype-plt",
        r#".section .text
.globl call_unknown
.type call_unknown,@function
.extern unknown_runtime_helper
call_unknown:
    call unknown_runtime_helper@PLT
    ret
.size call_unknown, .-call_unknown
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
        stderr.contains("PLT") && stderr.contains("symbol type 0"),
        "{stderr}"
    );
    assert!(!output.exists());

    let _ = fs::remove_dir_all(dir);
}
