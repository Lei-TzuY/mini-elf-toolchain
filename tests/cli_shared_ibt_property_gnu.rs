use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const PT_LOAD: u32 = 1;
const ENDBR64: [u8; 4] = [0xf3, 0x0f, 0x1e, 0xfa];

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

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn vaddr_to_file_offset(bytes: &[u8], address: u64) -> usize {
    let phoff = read_u64(bytes, 32) as usize;
    let phentsize = read_u16(bytes, 54) as usize;
    let phnum = read_u16(bytes, 56) as usize;

    for index in 0..phnum {
        let ph = phoff + index * phentsize;
        if read_u32(bytes, ph) != PT_LOAD {
            continue;
        }
        let offset = read_u64(bytes, ph + 8);
        let vaddr = read_u64(bytes, ph + 16);
        let filesz = read_u64(bytes, ph + 32);
        let Some(end) = vaddr.checked_add(filesz) else {
            continue;
        };
        if address >= vaddr && address < end {
            return usize::try_from(offset + (address - vaddr)).unwrap();
        }
    }
    panic!("virtual address {address:#x} is not file-backed by PT_LOAD");
}

fn dynamic_symbol_value(path: &Path, symbol: &str) -> u64 {
    let output = Command::new("readelf")
        .arg("-sDW")
        .arg(path)
        .output()
        .unwrap();
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);
    text.lines()
        .find(|line| line.split_whitespace().last() == Some(symbol))
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| u64::from_str_radix(value, 16).ok())
        .unwrap_or_else(|| panic!("missing dynamic symbol {symbol}: {text}"))
}

fn assert_mini_ibt_plt(path: &Path) {
    let bytes = fs::read(path).unwrap();
    let function = dynamic_symbol_value(path, "call_host_direct");
    let function_offset = vaddr_to_file_offset(&bytes, function);
    let body = &bytes[function_offset..function_offset + 32];
    let call_offset = body
        .iter()
        .position(|byte| *byte == 0xe8)
        .expect("call_host_direct should contain a direct CALL rel32");
    let displacement =
        i32::from_le_bytes(body[call_offset + 1..call_offset + 5].try_into().unwrap());
    let call_next = function + u64::try_from(call_offset + 5).unwrap();
    let secure_address = i128::from(call_next) + i128::from(displacement);
    let secure_address = u64::try_from(secure_address).unwrap();
    let secure_offset = vaddr_to_file_offset(&bytes, secure_address);
    let secure = &bytes[secure_offset..secure_offset + 16];

    assert_eq!(
        &secure[..4],
        &ENDBR64,
        "public PLT entry must begin ENDBR64"
    );
    assert_eq!(
        &secure[4..6],
        &[0xff, 0x25],
        "secure PLT must jump through GOT"
    );

    let got_disp = i32::from_le_bytes(secure[6..10].try_into().unwrap());
    let got_address =
        u64::try_from(i128::from(secure_address + 10) + i128::from(got_disp)).unwrap();
    let got_offset = vaddr_to_file_offset(&bytes, got_address);
    let lazy_address = read_u64(&bytes, got_offset);
    let lazy_offset = vaddr_to_file_offset(&bytes, lazy_address);
    let lazy = &bytes[lazy_offset..lazy_offset + 16];

    assert_eq!(
        &lazy[..4],
        &ENDBR64,
        "initial GOT indirect target must begin ENDBR64"
    );
    assert_eq!(lazy[4], 0x68, "lazy PLT entry must push relocation index");
    assert_eq!(lazy[9], 0xe9, "lazy PLT entry must jump directly to PLT0");
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
    }

    // Mini intentionally omits section headers, so objdump cannot discover its
    // code sections. Verify the actual direct-call target and lazy GOT target
    // through mapped ELF addresses instead of weakening the PLT evidence.
    assert_mini_ibt_plt(&mini);

    let gnu_disassembly = Command::new("objdump")
        .arg("-d")
        .arg(&gnu)
        .output()
        .unwrap();
    assert!(gnu_disassembly.status.success());
    let gnu_disassembly = String::from_utf8_lossy(&gnu_disassembly.stdout);
    assert!(
        gnu_disassembly.contains("host_function@plt"),
        "{gnu_disassembly}"
    );
    assert!(gnu_disassembly.contains("endbr64"), "{gnu_disassembly}");

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
fn z_ibt_is_rejected_outside_loader_image_modes_before_input_io() {
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
        stderr.contains("-z ibt is only supported with --shared or --dynamic-pie"),
        "{stderr}"
    );
    assert!(!output.exists());

    let _ = fs::remove_dir_all(dir);
}
