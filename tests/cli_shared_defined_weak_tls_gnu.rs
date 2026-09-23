use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const TLS_NAME: &str = "mini_elf_defined_weak_tls_334";
const INITIAL: u64 = 0x1122_3344_5566_7788;
const HOST_INITIAL: u64 = 0x8877_6655_4433_2211;

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
        "mini-elf-toolchain-defined-weak-tls-{label}-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&path).unwrap();
    path
}

fn assemble_source(dir: &Path, stem: &str, source: &str) -> PathBuf {
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

fn weak_tls_source(body: &str) -> String {
    format!(
        r#".section .note.GNU-stack,"",@progbits
.section .tdata,"awT",@progbits
.align 8
.weak {TLS_NAME}
.type {TLS_NAME},@tls_object
{TLS_NAME}:
    .quad {INITIAL}
.size {TLS_NAME}, .-{TLS_NAME}

.section .text
{body}
"#
    )
}

fn assemble_cross_model(dir: &Path) -> PathBuf {
    let body = format!(
        r#".globl read_tls_gd
.type read_tls_gd,@function
read_tls_gd:
    leaq {TLS_NAME}@tlsgd(%rip), %rdi
    call __tls_get_addr@PLT
    mov (%rax), %rax
    ret
.size read_tls_gd, .-read_tls_gd

.globl write_tls_gd
.type write_tls_gd,@function
write_tls_gd:
    push %rbx
    mov %rdi, %rbx
    leaq {TLS_NAME}@tlsgd(%rip), %rdi
    call __tls_get_addr@PLT
    mov %rbx, (%rax)
    pop %rbx
    ret
.size write_tls_gd, .-write_tls_gd

.globl read_tls_ie
.type read_tls_ie,@function
read_tls_ie:
    mov {TLS_NAME}@gottpoff(%rip), %rax
    mov %fs:(%rax), %rax
    ret
.size read_tls_ie, .-read_tls_ie

.globl write_tls_ie
.type write_tls_ie,@function
write_tls_ie:
    mov {TLS_NAME}@gottpoff(%rip), %rax
    mov %rdi, %fs:(%rax)
    ret
.size write_tls_ie, .-write_tls_ie

.globl read_tls_desc
.type read_tls_desc,@function
read_tls_desc:
    leaq {TLS_NAME}@TLSDESC(%rip), %rax
    call *{TLS_NAME}@TLSCALL(%rax)
    mov %fs:(%rax), %rax
    ret
.size read_tls_desc, .-read_tls_desc

.globl write_tls_desc
.type write_tls_desc,@function
write_tls_desc:
    leaq {TLS_NAME}@TLSDESC(%rip), %rax
    call *{TLS_NAME}@TLSCALL(%rax)
    mov %rdi, %fs:(%rax)
    ret
.size write_tls_desc, .-write_tls_desc
"#
    );
    assemble_source(dir, "defined-weak-tls-cross-model", &weak_tls_source(&body))
}

fn assemble_gnu_model(dir: &Path, stem: &str, body: String) -> PathBuf {
    assemble_source(dir, stem, &weak_tls_source(&body))
}

fn build_mini(dir: &Path, object: &Path) -> PathBuf {
    let shared = dir.join("libmini-defined-weak-tls.so");
    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&shared)
        .args(["--shared", "--soname", "libmini-defined-weak-tls.so"])
        .arg(object)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    shared
}

fn build_gnu(dir: &Path, stem: &str, object: &Path) -> PathBuf {
    let shared = dir.join(format!("libgnu-{stem}.so"));
    let output = Command::new("ld")
        .args(["-shared", "--hash-style=sysv", "--no-relax", "-o"])
        .arg(&shared)
        .arg(object)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    shared
}

fn assert_weak_tls_symbol(path: &Path) {
    let output = Command::new("readelf")
        .arg("-sDW")
        .arg(path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let symbols = String::from_utf8_lossy(&output.stdout);
    assert!(
        symbols.lines().any(|line| {
            line.contains("WEAK")
                && line.contains(" TLS ")
                && !line.contains(" UND ")
                && line.ends_with(TLS_NAME)
        }),
        "{} dynamic symbols:\n{symbols}",
        path.display()
    );
}

fn dynamic_relocations(path: &Path) -> String {
    let output = Command::new("readelf")
        .args(["-rW", "--use-dynamic"])
        .arg(path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn assert_static_tls_flag(path: &Path) {
    let output = Command::new("readelf")
        .arg("-dW")
        .arg(path)
        .output()
        .unwrap();
    assert!(output.status.success());
    let dynamic = String::from_utf8_lossy(&output.stdout);
    assert!(
        dynamic.contains("FLAGS") && dynamic.contains("STATIC_TLS"),
        "{} must advertise DF_STATIC_TLS: {dynamic}",
        path.display()
    );
}

fn assert_mini_metadata(path: &Path) {
    assert_weak_tls_symbol(path);
    let relocations = dynamic_relocations(path);
    for relocation in [
        "R_X86_64_DTPMOD64",
        "R_X86_64_DTPOFF64",
        "R_X86_64_TPOFF64",
        "R_X86_64_TLSDESC",
    ] {
        assert!(
            relocations
                .lines()
                .any(|line| line.contains(relocation) && line.contains(TLS_NAME)),
            "{} missing {relocation} for {TLS_NAME}:\n{relocations}",
            path.display()
        );
    }
    assert!(
        relocations
            .lines()
            .any(|line| line.contains("R_X86_64_JUMP_SLOT") && line.contains("__tls_get_addr")),
        "{} missing __tls_get_addr JUMP_SLOT:\n{relocations}",
        path.display()
    );
    assert_static_tls_flag(path);
}

fn assert_gnu_model_metadata(
    path: &Path,
    expected_relocations: &[&str],
    needs_tls_get_addr: bool,
    needs_static_tls: bool,
) {
    assert_weak_tls_symbol(path);
    let relocations = dynamic_relocations(path);
    for relocation in expected_relocations {
        assert!(
            relocations
                .lines()
                .any(|line| line.contains(relocation) && line.contains(TLS_NAME)),
            "{} missing {relocation} for {TLS_NAME}:\n{relocations}",
            path.display()
        );
    }
    if needs_tls_get_addr {
        assert!(
            relocations
                .lines()
                .any(|line| line.contains("R_X86_64_JUMP_SLOT") && line.contains("__tls_get_addr")),
            "{} missing __tls_get_addr JUMP_SLOT:\n{relocations}",
            path.display()
        );
    }
    if needs_static_tls {
        assert_static_tls_flag(path);
    }
}

fn compile_runner(dir: &Path, stem: &str, source: &str, rdynamic: bool) -> PathBuf {
    let source_path = dir.join(format!("{stem}.c"));
    let binary = dir.join(stem);
    fs::write(&source_path, source).unwrap();

    let mut command = Command::new("cc");
    if rdynamic {
        command.arg("-rdynamic");
    }
    let output = command
        .args(["-o"])
        .arg(&binary)
        .arg(&source_path)
        .args(["-ldl", "-pthread"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    binary
}

fn mini_self_runner_source() -> String {
    format!(
        r#"#include <dlfcn.h>
#include <pthread.h>
#include <stdint.h>

typedef uint64_t (*read_fn)(void);
typedef void (*write_fn)(uint64_t);

struct api {{
    read_fn gd_read;
    write_fn gd_write;
    read_fn ie_read;
    write_fn ie_write;
    read_fn desc_read;
    write_fn desc_write;
}};

struct ctx {{
    struct api api;
    int result;
}};

static int all_equal(struct api *api, uint64_t expected) {{
    if (api->gd_read() != expected) return 1;
    if (api->ie_read() != expected) return 2;
    if (api->desc_read() != expected) return 3;
    return 0;
}}

static void *worker(void *opaque) {{
    struct ctx *ctx = (struct ctx *)opaque;
    if (all_equal(&ctx->api, UINT64_C(0x{INITIAL:016x})) != 0) {{
        ctx->result = 121;
        return 0;
    }}
    ctx->api.ie_write(UINT64_C(0x3333333333333333));
    if (all_equal(&ctx->api, UINT64_C(0x3333333333333333)) != 0) {{
        ctx->result = 122;
        return 0;
    }}
    ctx->api.desc_write(UINT64_C(0x4444444444444444));
    if (all_equal(&ctx->api, UINT64_C(0x4444444444444444)) != 0) {{
        ctx->result = 123;
        return 0;
    }}
    ctx->result = 0;
    return 0;
}}

int main(int argc, char **argv) {{
    if (argc != 2) return 110;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) return 111;

    struct api api = {{
        (read_fn)dlsym(handle, "read_tls_gd"),
        (write_fn)dlsym(handle, "write_tls_gd"),
        (read_fn)dlsym(handle, "read_tls_ie"),
        (write_fn)dlsym(handle, "write_tls_ie"),
        (read_fn)dlsym(handle, "read_tls_desc"),
        (write_fn)dlsym(handle, "write_tls_desc")
    }};
    if (!api.gd_read || !api.gd_write || !api.ie_read || !api.ie_write ||
        !api.desc_read || !api.desc_write) return 112;

    if (all_equal(&api, UINT64_C(0x{INITIAL:016x})) != 0) return 113;
    api.gd_write(UINT64_C(0xaaaaaaaaaaaaaaaa));
    if (all_equal(&api, UINT64_C(0xaaaaaaaaaaaaaaaa)) != 0) return 114;
    api.ie_write(UINT64_C(0xbbbbbbbbbbbbbbbb));
    if (all_equal(&api, UINT64_C(0xbbbbbbbbbbbbbbbb)) != 0) return 115;
    api.desc_write(UINT64_C(0xcccccccccccccccc));
    if (all_equal(&api, UINT64_C(0xcccccccccccccccc)) != 0) return 116;

    struct ctx ctx = {{ api, -1 }};
    pthread_t thread;
    if (pthread_create(&thread, 0, worker, &ctx) != 0) return 117;
    if (pthread_join(thread, 0) != 0) return 118;
    if (ctx.result != 0) return ctx.result;
    if (all_equal(&api, UINT64_C(0xcccccccccccccccc)) != 0) return 119;

    return dlclose(handle) == 0 ? 0 : 120;
}}
"#
    )
}

fn mini_preempt_runner_source() -> String {
    format!(
        r#"#include <dlfcn.h>
#include <pthread.h>
#include <stdint.h>

__thread uint64_t {TLS_NAME} = UINT64_C(0x{HOST_INITIAL:016x});

typedef uint64_t (*read_fn)(void);
typedef void (*write_fn)(uint64_t);

struct api {{
    read_fn gd_read;
    write_fn gd_write;
    read_fn ie_read;
    write_fn ie_write;
    read_fn desc_read;
    write_fn desc_write;
}};

struct ctx {{
    struct api api;
    int result;
}};

static int all_equal(struct api *api, uint64_t expected) {{
    if (api->gd_read() != expected) return 1;
    if (api->ie_read() != expected) return 2;
    if (api->desc_read() != expected) return 3;
    return 0;
}}

static void *worker(void *opaque) {{
    struct ctx *ctx = (struct ctx *)opaque;
    if ({TLS_NAME} != UINT64_C(0x{HOST_INITIAL:016x})) {{
        ctx->result = 141;
        return 0;
    }}
    if (all_equal(&ctx->api, UINT64_C(0x{HOST_INITIAL:016x})) != 0) {{
        ctx->result = 142;
        return 0;
    }}
    ctx->api.gd_write(UINT64_C(0x5555555555555555));
    if ({TLS_NAME} != UINT64_C(0x5555555555555555) ||
        all_equal(&ctx->api, UINT64_C(0x5555555555555555)) != 0) {{
        ctx->result = 143;
        return 0;
    }}
    ctx->result = 0;
    return 0;
}}

int main(int argc, char **argv) {{
    if (argc != 2) return 130;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) return 131;

    struct api api = {{
        (read_fn)dlsym(handle, "read_tls_gd"),
        (write_fn)dlsym(handle, "write_tls_gd"),
        (read_fn)dlsym(handle, "read_tls_ie"),
        (write_fn)dlsym(handle, "write_tls_ie"),
        (read_fn)dlsym(handle, "read_tls_desc"),
        (write_fn)dlsym(handle, "write_tls_desc")
    }};
    if (!api.gd_read || !api.gd_write || !api.ie_read || !api.ie_write ||
        !api.desc_read || !api.desc_write) return 132;

    if ({TLS_NAME} != UINT64_C(0x{HOST_INITIAL:016x})) return 133;
    if (all_equal(&api, UINT64_C(0x{HOST_INITIAL:016x})) != 0) return 134;

    api.desc_write(UINT64_C(0xdddddddddddddddd));
    if ({TLS_NAME} != UINT64_C(0xdddddddddddddddd)) return 135;
    if (all_equal(&api, UINT64_C(0xdddddddddddddddd)) != 0) return 136;

    api.ie_write(UINT64_C(0xeeeeeeeeeeeeeeee));
    if ({TLS_NAME} != UINT64_C(0xeeeeeeeeeeeeeeee)) return 137;
    if (all_equal(&api, UINT64_C(0xeeeeeeeeeeeeeeee)) != 0) return 138;

    struct ctx ctx = {{ api, -1 }};
    pthread_t thread;
    if (pthread_create(&thread, 0, worker, &ctx) != 0) return 139;
    if (pthread_join(thread, 0) != 0) return 140;
    if (ctx.result != 0) return ctx.result;

    if ({TLS_NAME} != UINT64_C(0xeeeeeeeeeeeeeeee)) return 144;
    if (all_equal(&api, UINT64_C(0xeeeeeeeeeeeeeeee)) != 0) return 145;
    return dlclose(handle) == 0 ? 0 : 146;
}}
"#
    )
}

fn model_self_runner_source() -> String {
    format!(
        r#"#include <dlfcn.h>
#include <pthread.h>
#include <stdint.h>

typedef uint64_t (*read_fn)(void);
typedef void (*write_fn)(uint64_t);

struct ctx {{
    read_fn read_tls;
    write_fn write_tls;
    int result;
}};

static void *worker(void *opaque) {{
    struct ctx *ctx = (struct ctx *)opaque;
    if (ctx->read_tls() != UINT64_C(0x{INITIAL:016x})) {{
        ctx->result = 161;
        return 0;
    }}
    ctx->write_tls(UINT64_C(0x2222222222222222));
    if (ctx->read_tls() != UINT64_C(0x2222222222222222)) {{
        ctx->result = 162;
        return 0;
    }}
    ctx->result = 0;
    return 0;
}}

int main(int argc, char **argv) {{
    if (argc != 2) return 150;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) return 151;
    read_fn read_tls = (read_fn)dlsym(handle, "read_tls");
    write_fn write_tls = (write_fn)dlsym(handle, "write_tls");
    if (!read_tls || !write_tls) return 152;

    if (read_tls() != UINT64_C(0x{INITIAL:016x})) return 153;
    write_tls(UINT64_C(0xaaaaaaaaaaaaaaaa));
    if (read_tls() != UINT64_C(0xaaaaaaaaaaaaaaaa)) return 154;

    struct ctx ctx = {{ read_tls, write_tls, -1 }};
    pthread_t thread;
    if (pthread_create(&thread, 0, worker, &ctx) != 0) return 155;
    if (pthread_join(thread, 0) != 0) return 156;
    if (ctx.result != 0) return ctx.result;
    if (read_tls() != UINT64_C(0xaaaaaaaaaaaaaaaa)) return 157;

    return dlclose(handle) == 0 ? 0 : 158;
}}
"#
    )
}

fn model_preempt_runner_source() -> String {
    format!(
        r#"#include <dlfcn.h>
#include <pthread.h>
#include <stdint.h>

__thread uint64_t {TLS_NAME} = UINT64_C(0x{HOST_INITIAL:016x});

typedef uint64_t (*read_fn)(void);
typedef void (*write_fn)(uint64_t);

struct ctx {{
    read_fn read_tls;
    write_fn write_tls;
    int result;
}};

static void *worker(void *opaque) {{
    struct ctx *ctx = (struct ctx *)opaque;
    if ({TLS_NAME} != UINT64_C(0x{HOST_INITIAL:016x}) ||
        ctx->read_tls() != UINT64_C(0x{HOST_INITIAL:016x})) {{
        ctx->result = 181;
        return 0;
    }}
    ctx->write_tls(UINT64_C(0x3333333333333333));
    if ({TLS_NAME} != UINT64_C(0x3333333333333333) ||
        ctx->read_tls() != UINT64_C(0x3333333333333333)) {{
        ctx->result = 182;
        return 0;
    }}
    ctx->result = 0;
    return 0;
}}

int main(int argc, char **argv) {{
    if (argc != 2) return 170;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) return 171;
    read_fn read_tls = (read_fn)dlsym(handle, "read_tls");
    write_fn write_tls = (write_fn)dlsym(handle, "write_tls");
    if (!read_tls || !write_tls) return 172;

    if ({TLS_NAME} != UINT64_C(0x{HOST_INITIAL:016x}) ||
        read_tls() != UINT64_C(0x{HOST_INITIAL:016x})) return 173;

    write_tls(UINT64_C(0xbbbbbbbbbbbbbbbb));
    if ({TLS_NAME} != UINT64_C(0xbbbbbbbbbbbbbbbb) ||
        read_tls() != UINT64_C(0xbbbbbbbbbbbbbbbb)) return 174;

    struct ctx ctx = {{ read_tls, write_tls, -1 }};
    pthread_t thread;
    if (pthread_create(&thread, 0, worker, &ctx) != 0) return 175;
    if (pthread_join(thread, 0) != 0) return 176;
    if (ctx.result != 0) return ctx.result;

    if ({TLS_NAME} != UINT64_C(0xbbbbbbbbbbbbbbbb) ||
        read_tls() != UINT64_C(0xbbbbbbbbbbbbbbbb)) return 177;

    return dlclose(handle) == 0 ? 0 : 178;
}}
"#
    )
}

#[test]
fn defined_weak_tls_composes_dynamic_models_and_matches_gnu_per_model() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("binding");
    let cross_model_object = assemble_cross_model(&dir);

    let input = Command::new("readelf")
        .arg("-rW")
        .arg(&cross_model_object)
        .output()
        .unwrap();
    assert!(input.status.success());
    let input = String::from_utf8_lossy(&input.stdout);
    for relocation in [
        "R_X86_64_TLSGD",
        "R_X86_64_GOTTPOFF",
        "R_X86_64_GOTPC32_TLSDESC",
        "R_X86_64_TLSDESC_CALL",
    ] {
        assert!(input.contains(relocation), "missing {relocation}: {input}");
    }

    let mini = build_mini(&dir, &cross_model_object);
    assert_mini_metadata(&mini);

    let gnu_tlsgd_object = assemble_gnu_model(
        &dir,
        "gnu-tlsgd",
        format!(
            r#".globl read_tls
.type read_tls,@function
read_tls:
    leaq {TLS_NAME}@tlsgd(%rip), %rdi
    call __tls_get_addr@PLT
    mov (%rax), %rax
    ret
.size read_tls, .-read_tls

.globl write_tls
.type write_tls,@function
write_tls:
    push %rbx
    mov %rdi, %rbx
    leaq {TLS_NAME}@tlsgd(%rip), %rdi
    call __tls_get_addr@PLT
    mov %rbx, (%rax)
    pop %rbx
    ret
.size write_tls, .-write_tls
"#
        ),
    );
    let gnu_ie_object = assemble_gnu_model(
        &dir,
        "gnu-ie",
        format!(
            r#".globl read_tls
.type read_tls,@function
read_tls:
    mov {TLS_NAME}@gottpoff(%rip), %rax
    mov %fs:(%rax), %rax
    ret
.size read_tls, .-read_tls

.globl write_tls
.type write_tls,@function
write_tls:
    mov {TLS_NAME}@gottpoff(%rip), %rax
    mov %rdi, %fs:(%rax)
    ret
.size write_tls, .-write_tls
"#
        ),
    );
    let gnu_tlsdesc_object = assemble_gnu_model(
        &dir,
        "gnu-tlsdesc",
        format!(
            r#".globl read_tls
.type read_tls,@function
read_tls:
    leaq {TLS_NAME}@TLSDESC(%rip), %rax
    call *{TLS_NAME}@TLSCALL(%rax)
    mov %fs:(%rax), %rax
    ret
.size read_tls, .-read_tls

.globl write_tls
.type write_tls,@function
write_tls:
    leaq {TLS_NAME}@TLSDESC(%rip), %rax
    call *{TLS_NAME}@TLSCALL(%rax)
    mov %rdi, %fs:(%rax)
    ret
.size write_tls, .-write_tls
"#
        ),
    );

    let gnu_tlsgd = build_gnu(&dir, "tlsgd", &gnu_tlsgd_object);
    let gnu_ie = build_gnu(&dir, "ie", &gnu_ie_object);
    let gnu_tlsdesc = build_gnu(&dir, "tlsdesc", &gnu_tlsdesc_object);

    assert_gnu_model_metadata(
        &gnu_tlsgd,
        &["R_X86_64_DTPMOD64", "R_X86_64_DTPOFF64"],
        true,
        false,
    );
    assert_gnu_model_metadata(&gnu_ie, &["R_X86_64_TPOFF64"], false, true);
    assert_gnu_model_metadata(&gnu_tlsdesc, &["R_X86_64_TLSDESC"], false, false);

    #[cfg(target_os = "linux")]
    {
        let mini_self = compile_runner(&dir, "mini-self-bind", &mini_self_runner_source(), false);
        let mini_preempt =
            compile_runner(&dir, "mini-preempt", &mini_preempt_runner_source(), true);

        for runner in [&mini_self, &mini_preempt] {
            let status = Command::new(runner).arg(&mini).status().unwrap();
            assert!(
                status.success(),
                "{} returned {status} for {}",
                runner.display(),
                mini.display()
            );
        }

        let model_self = compile_runner(
            &dir,
            "gnu-model-self-bind",
            &model_self_runner_source(),
            false,
        );
        let model_preempt = compile_runner(
            &dir,
            "gnu-model-preempt",
            &model_preempt_runner_source(),
            true,
        );

        for shared in [&gnu_tlsgd, &gnu_ie, &gnu_tlsdesc] {
            for runner in [&model_self, &model_preempt] {
                let status = Command::new(runner).arg(shared).status().unwrap();
                assert!(
                    status.success(),
                    "{} returned {status} for {}",
                    runner.display(),
                    shared.display()
                );
            }
        }
    }

    let _ = fs::remove_dir_all(dir);
}
