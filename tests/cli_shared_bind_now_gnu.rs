use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const PT_GNU_RELRO: u32 = 0x6474_e552;

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
        "mini-elf-toolchain-shared-bind-now-{label}-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&path).unwrap();
    path
}

fn assemble(dir: &Path) -> PathBuf {
    let source = dir.join("caller.s");
    let object = dir.join("caller.o");
    fs::write(
        &source,
        r#".section .note.GNU-stack,"",@progbits
.text
.globl call_host_direct
.type call_host_direct,@function
.extern host_function
.type host_function,@function
call_host_direct:
    sub $8, %rsp
    call host_function@PLT
    add $8, %rsp
    ret
.size call_host_direct, .-call_host_direct
"#,
    )
    .unwrap();
    let output = Command::new("as")
        .args(["--64", "-o"])
        .arg(&object)
        .arg(&source)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    object
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn gnu_relro_contains(path: &Path, address: u64) -> bool {
    let bytes = fs::read(path).unwrap();
    let phoff = read_u64(&bytes, 32) as usize;
    let phentsize = read_u16(&bytes, 54) as usize;
    let phnum = read_u16(&bytes, 56) as usize;

    (0..phnum).any(|index| {
        let ph = phoff + index * phentsize;
        if read_u32(&bytes, ph) != PT_GNU_RELRO {
            return false;
        }
        let start = read_u64(&bytes, ph + 16);
        let size = read_u64(&bytes, ph + 40);
        start
            .checked_add(size)
            .is_some_and(|end| address >= start && address < end)
    })
}

fn jump_slot_offset(path: &Path, symbol: &str) -> u64 {
    let output = Command::new("readelf")
        .args(["-rW", "--use-dynamic"])
        .arg(path)
        .output()
        .unwrap();
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);
    text.lines()
        .find(|line| line.contains("R_X86_64_JUMP_SLOT") && line.contains(symbol))
        .and_then(|line| line.split_whitespace().next())
        .and_then(|value| u64::from_str_radix(value, 16).ok())
        .unwrap_or_else(|| panic!("missing JUMP_SLOT for {symbol}: {text}"))
}

fn assert_bind_now_metadata(path: &Path) {
    let output = Command::new("readelf")
        .args(["-dW"])
        .arg(path)
        .output()
        .unwrap();
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        text.contains("BIND_NOW") || text.contains("NOW"),
        "missing eager-binding policy: {text}"
    );

    let headers = Command::new("readelf")
        .args(["-lW"])
        .arg(path)
        .output()
        .unwrap();
    assert!(headers.status.success());
    assert!(
        String::from_utf8_lossy(&headers.stdout).contains("GNU_RELRO"),
        "{}",
        String::from_utf8_lossy(&headers.stdout)
    );
}

#[test]
fn shared_z_now_eagerly_binds_and_relro_protects_jump_slot() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("runtime");
    let object = assemble(&dir);

    let mini = dir.join("libmini.so");
    let mini_link = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&mini)
        .args(["--shared", "-z", "now"])
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        mini_link.status.success(),
        "{}",
        String::from_utf8_lossy(&mini_link.stderr)
    );

    let flags = Command::new(env!("CARGO_BIN_EXE_mini-elf-dynflags"))
        .arg(&mini)
        .output()
        .unwrap();
    assert!(
        flags.status.success(),
        "{}",
        String::from_utf8_lossy(&flags.stderr)
    );
    assert!(
        String::from_utf8_lossy(&flags.stdout).contains("BIND_NOW"),
        "{}",
        String::from_utf8_lossy(&flags.stdout)
    );

    let gnu = dir.join("libgnu.so");
    let gnu_link = Command::new("ld")
        .args([
            "-shared",
            "--hash-style=sysv",
            "--no-relax",
            "-z",
            "relro",
            "-z",
            "now",
            "-o",
        ])
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
        assert_bind_now_metadata(shared);
        let slot = jump_slot_offset(shared, "host_function");
        assert!(
            gnu_relro_contains(shared, slot),
            "{} JUMP_SLOT at {slot:#x} must be covered by PT_GNU_RELRO",
            shared.display()
        );
    }

    #[cfg(target_os = "linux")]
    {
        let source = dir.join("runner.c");
        let runner = dir.join("runner");
        fs::write(
            &source,
            r#"#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

static uint64_t calls;

uint64_t host_function(void) {
    calls += 1;
    return UINT64_C(60) + calls;
}

int main(int argc, char **argv) {
    if (argc != 3) return 220;
    uintptr_t slot_offset = (uintptr_t)strtoull(argv[2], 0, 16);

    void *handle = dlopen(argv[1], RTLD_LAZY | RTLD_LOCAL);
    if (!handle) return 221;
    uint64_t (*call_host)(void) =
        (uint64_t (*)(void))dlsym(handle, "call_host_direct");
    if (!call_host) return 222;

    struct link_map *map = 0;
    if (dlinfo(handle, RTLD_DI_LINKMAP, &map) != 0 || !map) return 223;
    uintptr_t *slot = (uintptr_t *)(map->l_addr + slot_offset);

    /* -z now must override the RTLD_LAZY request before user execution. */
    if (*slot != (uintptr_t)&host_function) return 224;
    if (call_host() != UINT64_C(61)) return 225;
    if (call_host() != UINT64_C(62)) return 226;

    pid_t child = fork();
    if (child < 0) return 227;
    if (child == 0) {
        *slot ^= UINT64_C(1);
        _exit(90);
    }

    int status = 0;
    if (waitpid(child, &status, 0) != child) return 228;
    if (!WIFSIGNALED(status) || WTERMSIG(status) != SIGSEGV) return 229;

    return dlclose(handle) == 0 ? 0 : 230;
}
"#,
        )
        .unwrap();
        let compile = Command::new("cc")
            .args(["-rdynamic", "-o"])
            .arg(&runner)
            .arg(&source)
            .arg("-ldl")
            .output()
            .unwrap();
        assert!(
            compile.status.success(),
            "{}",
            String::from_utf8_lossy(&compile.stderr)
        );

        for shared in [&mini, &gnu] {
            let slot = jump_slot_offset(shared, "host_function");
            let status = Command::new(&runner)
                .env_remove("LD_BIND_NOW")
                .arg(shared)
                .arg(format!("{slot:x}"))
                .status()
                .unwrap();
            assert!(
                status.success(),
                "-z now runtime returned {status} for {}",
                shared.display()
            );
        }
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn z_now_is_rejected_outside_shared_mode_before_input_io() {
    let dir = temp_dir("usage");
    let output = dir.join("must-not-exist");

    let result = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&output)
        .args(["-z", "now"])
        .arg(dir.join("missing.o"))
        .output()
        .unwrap();

    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(
        stderr.contains("-z now is only supported with --shared"),
        "{stderr}"
    );
    assert!(!output.exists());

    let _ = fs::remove_dir_all(dir);
}
