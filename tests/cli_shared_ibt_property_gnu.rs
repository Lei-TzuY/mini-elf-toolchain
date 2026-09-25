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
        && command_reports("objdump", "GNU objdump")
        && command_available("cc")
}

fn temp_dir(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after Unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "mini-elf-toolchain-shared-ibt-property-{label}-{}-{nonce}",
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

fn inspect_property(path: &Path) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-gnu-property"))
        .arg(path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn shared_z_ibt_matches_gnu_property_and_preserves_lazy_execution() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("runtime");
    let object = assemble(&dir);

    let mini = dir.join("libmini.so");
    let mini_link = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&mini)
        .args(["--shared", "-z", "ibt"])
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
        .args([
            "-shared",
            "--hash-style=sysv",
            "--no-relax",
            "-z",
            "ibt",
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
        let property = inspect_property(shared);
        assert!(
            property.contains("x86 feature_1_and=0x1 IBT"),
            "{}: {property}",
            shared.display()
        );

        let headers = Command::new("readelf")
            .args(["-lW"])
            .arg(shared)
            .output()
            .unwrap();
        assert!(headers.status.success());
        let headers = String::from_utf8_lossy(&headers.stdout);
        assert!(headers.contains("GNU_PROPERTY"), "{headers}");

        let disassembly = Command::new("objdump")
            .arg("-d")
            .arg(shared)
            .output()
            .unwrap();
        assert!(disassembly.status.success());
        let disassembly = String::from_utf8_lossy(&disassembly.stdout);
        assert!(disassembly.contains("host_function@plt"), "{disassembly}");
        assert!(disassembly.contains("endbr64"), "{disassembly}");
    }

    #[cfg(target_os = "linux")]
    {
        let source = dir.join("runner.c");
        let runner = dir.join("runner");
        fs::write(
            &source,
            r#"#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>

static uint64_t calls;

uint64_t host_function(void) {
    calls += 1;
    return UINT64_C(50) + calls;
}

int main(int argc, char **argv) {
    if (argc != 2) return 210;
    void *handle = dlopen(argv[1], RTLD_LAZY | RTLD_LOCAL);
    if (!handle) return 211;
    uint64_t (*call_host)(void) =
        (uint64_t (*)(void))dlsym(handle, "call_host_direct");
    if (!call_host) return 212;
    if (call_host() != UINT64_C(51)) return 213;
    if (call_host() != UINT64_C(52)) return 214;
    return dlclose(handle) == 0 ? 0 : 215;
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
            let status = Command::new(&runner)
                .env_remove("LD_BIND_NOW")
                .arg(shared)
                .status()
                .unwrap();
            assert!(
                status.success(),
                "-z ibt lazy runtime returned {status} for {}",
                shared.display()
            );
        }
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn ibtplt_alone_does_not_claim_ibt_property() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("ibtplt-only");
    let object = assemble(&dir);
    let mini = dir.join("libmini.so");
    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&mini)
        .args(["--shared", "-z", "ibtplt"])
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        inspect_property(&mini),
        "No PT_GNU_PROPERTY segments found.\n"
    );

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn z_ibt_is_rejected_outside_shared_mode_before_input_io() {
    let dir = temp_dir("usage");
    let output = dir.join("must-not-exist");

    let result = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&output)
        .args(["-z", "ibt"])
        .arg(dir.join("missing.o"))
        .output()
        .unwrap();

    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(
        stderr.contains("-z ibt is only supported with --shared"),
        "{stderr}"
    );
    assert!(!output.exists());

    let _ = fs::remove_dir_all(dir);
}
