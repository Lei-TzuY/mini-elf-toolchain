use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;

fn command_available(program: &str) -> bool {
    Command::new(program)
        .arg("--version")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn temp_dir(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after Unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "mini-elf-toolchain-shared-{label}-{}-{nonce}",
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

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn program_header_count(path: &Path, kind: u32) -> usize {
    let bytes = fs::read(path).unwrap();
    let phoff = read_u64(&bytes, 32) as usize;
    let phentsize = read_u16(&bytes, 54) as usize;
    let phnum = read_u16(&bytes, 56) as usize;
    (0..phnum)
        .filter(|index| read_u32(&bytes, phoff + index * phentsize) == kind)
        .count()
}

#[test]
fn emits_loader_consumable_shared_object_with_exported_function_and_data() {
    if !command_available("as") || !command_available("readelf") || !command_available("cc") {
        return;
    }

    let dir = temp_dir("dlopen");
    let object = assemble(
        &dir,
        "exports",
        r#".section .text
.globl answer
.type answer,@function
answer:
    mov $42, %eax
    ret
.size answer, .-answer

.section .data
.align 8
.globl exported_value
.type exported_value,@object
exported_value:
    .quad 0x1122334455667788
.size exported_value, .-exported_value
"#,
    );
    let shared = dir.join("libanswer.so");

    let relocs = Command::new("readelf")
        .args(["-rW"])
        .arg(&object)
        .output()
        .unwrap();
    assert!(relocs.status.success());
    assert!(
        String::from_utf8_lossy(&relocs.stdout).contains("There are no relocations")
            || String::from_utf8_lossy(&relocs.stdout).trim().is_empty()
    );

    let link = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&shared)
        .arg("--shared")
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        link.status.success(),
        "{}",
        String::from_utf8_lossy(&link.stderr)
    );
    assert!(String::from_utf8_lossy(&link.stdout).contains("linked shared ELF64 x86-64"));

    let header = Command::new("readelf")
        .args(["-hW"])
        .arg(&shared)
        .output()
        .unwrap();
    assert!(header.status.success());
    assert!(String::from_utf8_lossy(&header.stdout).contains("Type:                              DYN"));

    assert_eq!(program_header_count(&shared, PT_DYNAMIC), 1);
    assert_eq!(program_header_count(&shared, PT_INTERP), 0);

    let dynamic = Command::new("readelf")
        .args(["-dW"])
        .arg(&shared)
        .output()
        .unwrap();
    assert!(
        dynamic.status.success(),
        "{}",
        String::from_utf8_lossy(&dynamic.stderr)
    );
    let dynamic_text = String::from_utf8_lossy(&dynamic.stdout);
    for tag in ["HASH", "STRTAB", "SYMTAB", "STRSZ", "SYMENT"] {
        assert!(dynamic_text.contains(tag), "missing {tag}: {dynamic_text}");
    }
    assert!(!dynamic_text.contains("NEEDED"));

    let consumer_source = dir.join("consumer.c");
    let consumer = dir.join("consumer");
    fs::write(
        &consumer_source,
        r#"#include <dlfcn.h>
#include <stdint.h>
int main(int argc, char **argv) {
    if (argc != 2) return 20;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) return 21;
    int (*answer)(void) = (int (*)(void))dlsym(handle, "answer");
    uint64_t *value = (uint64_t *)dlsym(handle, "exported_value");
    if (!answer || !value) return 22;
    if (answer() != 42) return 23;
    if (*value != UINT64_C(0x1122334455667788)) return 24;
    if (dlsym(handle, "definitely_missing") != 0) return 25;
    return dlclose(handle) == 0 ? 0 : 26;
}
"#,
    )
    .unwrap();
    let compile = Command::new("cc")
        .arg("-O0")
        .arg("-o")
        .arg(&consumer)
        .arg(&consumer_source)
        .arg("-ldl")
        .output()
        .unwrap();
    assert!(
        compile.status.success(),
        "{}",
        String::from_utf8_lossy(&compile.stderr)
    );

    #[cfg(target_os = "linux")]
    {
        let status = Command::new(&consumer).arg(&shared).status().unwrap();
        assert!(status.success(), "dlopen consumer returned {status}");
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn shared_object_rejects_runtime_relocation_requirements_before_output() {
    if !command_available("as") || !command_available("readelf") {
        return;
    }

    let dir = temp_dir("relocation");
    let object = assemble(
        &dir,
        "needs-relocation",
        r#".section .text
.globl answer
.type answer,@function
.extern external_value
answer:
    mov external_value@GOTPCREL(%rip), %rax
    mov (%rax), %eax
    ret
.size answer, .-answer
"#,
    );
    let shared = dir.join("rejected.so");

    let relocs = Command::new("readelf")
        .args(["-rW"])
        .arg(&object)
        .output()
        .unwrap();
    assert!(relocs.status.success());
    assert!(String::from_utf8_lossy(&relocs.stdout).contains("GOTPCREL"));

    let link = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&shared)
        .arg("--shared")
        .arg(&object)
        .output()
        .unwrap();

    assert!(!link.status.success());
    assert!(link.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&link.stderr);
    assert!(
        stderr.contains("shared object") && stderr.contains("RELA"),
        "{stderr}"
    );
    assert!(!shared.exists());

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn shared_object_rejects_tls_before_output() {
    if !command_available("as") {
        return;
    }

    let dir = temp_dir("tls");
    let object = assemble(
        &dir,
        "tls",
        r#".section .tdata,"awT",@progbits
.globl tls_value
.type tls_value,@tls_object
tls_value:
    .quad 1
.size tls_value, .-tls_value

.section .text
.globl answer
.type answer,@function
answer:
    mov $42, %eax
    ret
.size answer, .-answer
"#,
    );
    let shared = dir.join("rejected-tls.so");

    let link = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&shared)
        .arg("--shared")
        .arg(&object)
        .output()
        .unwrap();

    assert!(!link.status.success());
    assert!(link.stdout.is_empty());
    assert!(String::from_utf8_lossy(&link.stderr).contains("TLS"));
    assert!(!shared.exists());

    let _ = fs::remove_dir_all(dir);
}
