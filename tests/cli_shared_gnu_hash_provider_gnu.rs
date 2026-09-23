use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const DT_NULL: i64 = 0;
const DT_HASH: i64 = 4;
const DT_GNU_HASH: i64 = 0x6fff_fef5;

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
        "mini-elf-toolchain-gnu-hash-provider-{label}-{}-{nonce}",
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

fn build_gnu_hash_provider(dir: &Path) -> PathBuf {
    let object = assemble(
        dir,
        "provider",
        r#".section .data
.globl provider_value
.type provider_value,@object
provider_value:
    .quad 0x1020304050607080
.size provider_value, .-provider_value

.section .text
.globl provider_function
.type provider_function,@function
provider_function:
    movabs $0x8877665544332211, %rax
    ret
.size provider_function, .-provider_function
"#,
    );
    let provider = dir.join("libgnuprovider.so");
    let output = Command::new("ld")
        .args([
            "-shared",
            "--hash-style=gnu",
            "-soname",
            "libgnuprovider.so",
            "-o",
        ])
        .arg(&provider)
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let dynamic = Command::new("readelf")
        .args(["-dW"])
        .arg(&provider)
        .output()
        .unwrap();
    assert!(dynamic.status.success());
    let dynamic = String::from_utf8_lossy(&dynamic.stdout);
    assert!(dynamic.contains("(GNU_HASH)"), "{dynamic}");
    assert!(!dynamic.contains("(HASH)"), "fixture must be GNU-hash-only: {dynamic}");

    provider
}

fn build_consumer(dir: &Path) -> PathBuf {
    assemble(
        dir,
        "consumer",
        r#".section .text
.globl call_provider
.type call_provider,@function
.extern provider_function
.type provider_function,@function
call_provider:
    call provider_function@PLT
    ret
.size call_provider, .-call_provider

.globl read_provider_value
.type read_provider_value,@function
.extern provider_value
.type provider_value,@object
read_provider_value:
    mov provider_value@GOTPCREL(%rip), %rax
    mov (%rax), %rax
    ret
.size read_provider_value, .-read_provider_value
"#,
    )
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

fn read_i64(bytes: &[u8], offset: usize) -> i64 {
    i64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn dynamic_gnu_hash_address(bytes: &[u8]) -> (usize, u64) {
    let phoff = read_u64(bytes, 32) as usize;
    let phentsize = read_u16(bytes, 54) as usize;
    let phnum = read_u16(bytes, 56) as usize;

    for index in 0..phnum {
        let ph = phoff + index * phentsize;
        if read_u32(bytes, ph) != PT_DYNAMIC {
            continue;
        }
        let offset = read_u64(bytes, ph + 8) as usize;
        let size = read_u64(bytes, ph + 32) as usize;
        for entry in (offset..offset + size).step_by(16) {
            let tag = read_i64(bytes, entry);
            if tag == DT_GNU_HASH {
                return (entry, read_u64(bytes, entry + 8));
            }
            if tag == DT_NULL {
                break;
            }
        }
    }
    panic!("provider has no DT_GNU_HASH");
}

fn map_virtual_address(bytes: &[u8], address: u64) -> usize {
    let phoff = read_u64(bytes, 32) as usize;
    let phentsize = read_u16(bytes, 54) as usize;
    let phnum = read_u16(bytes, 56) as usize;

    for index in 0..phnum {
        let ph = phoff + index * phentsize;
        if read_u32(bytes, ph) != PT_LOAD {
            continue;
        }
        let offset = read_u64(bytes, ph + 8);
        let virtual_address = read_u64(bytes, ph + 16);
        let file_size = read_u64(bytes, ph + 32);
        if address >= virtual_address && address < virtual_address + file_size {
            return (offset + (address - virtual_address)) as usize;
        }
    }
    panic!("address is not file-backed by PT_LOAD");
}

#[test]
fn needed_from_accepts_gnu_hash_only_provider_and_loads_it() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("needed-from");
    let provider = build_gnu_hash_provider(&dir);
    let consumer_object = build_consumer(&dir);
    let consumer = dir.join("libconsumer.so");

    let mini = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&consumer)
        .arg("--shared")
        .arg("--needed-from")
        .arg(&provider)
        .arg(&consumer_object)
        .output()
        .unwrap();
    assert!(
        mini.status.success(),
        "{}",
        String::from_utf8_lossy(&mini.stderr)
    );

    let dynamic = Command::new("readelf")
        .args(["-dW"])
        .arg(&consumer)
        .output()
        .unwrap();
    assert!(dynamic.status.success());
    let dynamic = String::from_utf8_lossy(&dynamic.stdout);
    assert!(
        dynamic.contains("Shared library: [libgnuprovider.so]"),
        "{dynamic}"
    );

    #[cfg(target_os = "linux")]
    {
        let source = dir.join("runner.c");
        let runner = dir.join("runner");
        fs::write(
            &source,
            r#"#include <dlfcn.h>
#include <stdint.h>

int main(int argc, char **argv) {
    if (argc != 2) return 70;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) return 71;
    uint64_t (*call_provider)(void) =
        (uint64_t (*)(void))dlsym(handle, "call_provider");
    uint64_t (*read_provider_value)(void) =
        (uint64_t (*)(void))dlsym(handle, "read_provider_value");
    if (!call_provider || !read_provider_value) return 72;
    if (call_provider() != UINT64_C(0x8877665544332211)) return 73;
    if (read_provider_value() != UINT64_C(0x1020304050607080)) return 74;
    return dlclose(handle) == 0 ? 0 : 75;
}
"#,
        )
        .unwrap();
        let compile = Command::new("cc")
            .args(["-o"])
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

        let status = Command::new(&runner)
            .arg(&consumer)
            .env("LD_LIBRARY_PATH", &dir)
            .status()
            .unwrap();
        assert!(status.success(), "GNU-hash provider consumer returned {status}");
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn shared_library_search_accepts_gnu_hash_only_provider() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("library-search");
    let _provider = build_gnu_hash_provider(&dir);
    let consumer_object = build_consumer(&dir);
    let consumer = dir.join("libconsumer.so");

    let mini = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&consumer)
        .arg("--shared")
        .arg("-L")
        .arg(&dir)
        .arg("-lgnuprovider")
        .arg(&consumer_object)
        .output()
        .unwrap();
    assert!(
        mini.status.success(),
        "{}",
        String::from_utf8_lossy(&mini.stderr)
    );

    let dynamic = Command::new("readelf")
        .args(["-dW"])
        .arg(&consumer)
        .output()
        .unwrap();
    assert!(dynamic.status.success());
    assert!(
        String::from_utf8_lossy(&dynamic.stdout)
            .contains("Shared library: [libgnuprovider.so]")
    );

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn malformed_gnu_hash_virtual_address_is_rejected_before_output() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("bad-address");
    let provider = build_gnu_hash_provider(&dir);
    let mut bytes = fs::read(&provider).unwrap();
    let (dynamic_entry, _) = dynamic_gnu_hash_address(&bytes);
    bytes[dynamic_entry + 8..dynamic_entry + 16].copy_from_slice(&u64::MAX.to_le_bytes());
    fs::write(&provider, bytes).unwrap();

    let consumer_object = build_consumer(&dir);
    let output = dir.join("must-not-exist.so");
    let mini = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&output)
        .arg("--shared")
        .arg("--needed-from")
        .arg(&provider)
        .arg(&consumer_object)
        .output()
        .unwrap();

    assert!(!mini.status.success());
    assert!(mini.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&mini.stderr);
    assert!(stderr.contains("DT_GNU_HASH"), "{stderr}");
    assert!(!output.exists());

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn malformed_gnu_hash_zero_bloom_size_is_rejected_before_output() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("zero-bloom");
    let provider = build_gnu_hash_provider(&dir);
    let mut bytes = fs::read(&provider).unwrap();
    let (_, address) = dynamic_gnu_hash_address(&bytes);
    let offset = map_virtual_address(&bytes, address);
    assert_ne!(read_u32(&bytes, offset + 8), 0);
    bytes[offset + 8..offset + 12].copy_from_slice(&0_u32.to_le_bytes());
    fs::write(&provider, bytes).unwrap();

    let consumer_object = build_consumer(&dir);
    let output = dir.join("must-not-exist.so");
    let mini = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&output)
        .arg("--shared")
        .arg("--needed-from")
        .arg(&provider)
        .arg(&consumer_object)
        .output()
        .unwrap();

    assert!(!mini.status.success());
    assert!(mini.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&mini.stderr);
    assert!(stderr.contains("bloom") || stderr.contains("GNU_HASH"), "{stderr}");
    assert!(!output.exists());

    let _ = fs::remove_dir_all(dir);
}
