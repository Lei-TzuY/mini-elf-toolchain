use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_dir(label: &str) -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "mini-elf-toolchain-{label}-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&path).unwrap();
    path
}

fn tool_available(tool: &str) -> bool {
    Command::new(tool).arg("--version").output().is_ok()
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

fn build_dynamic_executable(dir: &std::path::Path) -> std::path::PathBuf {
    let dep_assembly = dir.join("dep.s");
    let dep_object = dir.join("dep.o");
    let dep_shared = dir.join("libdep.so");
    fs::write(
        &dep_assembly,
        ".text\n.globl dep_hook\n.type dep_hook,@function\ndep_hook:\n  ret\n",
    )
    .unwrap();
    let assembled = Command::new("as")
        .arg("-o")
        .arg(&dep_object)
        .arg(&dep_assembly)
        .output()
        .unwrap();
    assert!(
        assembled.status.success(),
        "{}",
        String::from_utf8_lossy(&assembled.stderr)
    );
    let linked = Command::new("ld")
        .arg("-shared")
        .arg("-o")
        .arg(&dep_shared)
        .arg(&dep_object)
        .output()
        .unwrap();
    assert!(
        linked.status.success(),
        "{}",
        String::from_utf8_lossy(&linked.stderr)
    );

    let main_assembly = dir.join("main.s");
    let main_object = dir.join("main.o");
    let executable = dir.join("sample");
    fs::write(
        &main_assembly,
        ".text\n.globl _start\n.type _start,@function\n_start:\n  call dep_hook\n  mov $60,%rax\n  xor %rdi,%rdi\n  syscall\n.globl preinit_hook\n.type preinit_hook,@function\npreinit_hook:\n  ret\n.section .preinit_array,\"aw\",@preinit_array\n.quad preinit_hook\n",
    )
    .unwrap();
    let assembled = Command::new("as")
        .arg("-o")
        .arg(&main_object)
        .arg(&main_assembly)
        .output()
        .unwrap();
    assert!(
        assembled.status.success(),
        "{}",
        String::from_utf8_lossy(&assembled.stderr)
    );
    let linked = Command::new("ld")
        .arg("-o")
        .arg(&executable)
        .arg(&main_object)
        .arg("-L")
        .arg(dir)
        .arg("-ldep")
        .arg("--dynamic-linker")
        .arg("/lib64/ld-linux-x86-64.so.2")
        .output()
        .unwrap();
    assert!(
        linked.status.success(),
        "{}",
        String::from_utf8_lossy(&linked.stderr)
    );
    executable
}

fn dynamic_program_header(bytes: &[u8]) -> usize {
    let phoff = read_u64(bytes, 32) as usize;
    let phentsize = read_u16(bytes, 54) as usize;
    let phnum = read_u16(bytes, 56) as usize;
    (0..phnum)
        .find_map(|index| {
            let offset = phoff + index * phentsize;
            (read_u32(bytes, offset) == 2).then_some(offset)
        })
        .expect("dynamic executable should contain PT_DYNAMIC")
}

fn dynamic_entry_offset(bytes: &[u8], wanted_tag: u64) -> usize {
    let dynamic = dynamic_program_header(bytes);
    let dynamic_offset = read_u64(bytes, dynamic + 8) as usize;
    let dynamic_size = read_u64(bytes, dynamic + 32) as usize;
    (dynamic_offset..dynamic_offset + dynamic_size)
        .step_by(16)
        .find(|offset| read_u64(bytes, *offset) == wanted_tag)
        .unwrap_or_else(|| panic!("missing dynamic tag {wanted_tag}"))
}

#[test]
fn preinit_array_matches_gnu_readelf_dynamic_tags() {
    if !tool_available("as") || !tool_available("ld") || !tool_available("readelf") {
        return;
    }
    let dir = temp_dir("dynpreinit-gnu");
    let executable = build_dynamic_executable(&dir);
    let gnu = Command::new("readelf")
        .arg("-dW")
        .arg(&executable)
        .output()
        .unwrap();
    assert!(gnu.status.success());
    let gnu = String::from_utf8_lossy(&gnu.stdout);
    for fact in ["PREINIT_ARRAY", "PREINIT_ARRAYSZ"] {
        assert!(gnu.contains(fact), "GNU missing {fact}: {gnu}");
    }

    let ours = Command::new(env!("CARGO_BIN_EXE_mini-elf-dyninit"))
        .arg(&executable)
        .output()
        .unwrap();
    assert!(
        ours.status.success(),
        "{}",
        String::from_utf8_lossy(&ours.stderr)
    );
    let ours = String::from_utf8_lossy(&ours.stdout);
    assert!(ours.contains("DT_PREINIT_ARRAY: address="), "{ours}");
    assert!(ours.contains("DT_PREINIT_ARRAY: address=") && ours.contains("entries=1"), "{ours}");
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn malformed_preinit_array_size_in_later_input_keeps_stdout_atomic() {
    if !tool_available("as") || !tool_available("ld") {
        return;
    }
    let dir = temp_dir("dynpreinit-size");
    let good = build_dynamic_executable(&dir);
    let bad = dir.join("bad");
    let mut bytes = fs::read(&good).unwrap();
    let size_entry = dynamic_entry_offset(&bytes, 33);
    bytes[size_entry + 8..size_entry + 16].copy_from_slice(&7u64.to_le_bytes());
    fs::write(&bad, bytes).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-dyninit"))
        .arg(&good)
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty(), "stdout must remain atomic");
    assert!(String::from_utf8_lossy(&output.stderr).contains("not a multiple of 8"));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn overflowing_preinit_array_virtual_range_is_rejected() {
    if !tool_available("as") || !tool_available("ld") {
        return;
    }
    let dir = temp_dir("dynpreinit-overflow");
    let executable = build_dynamic_executable(&dir);
    let bad = dir.join("overflow");
    let mut bytes = fs::read(&executable).unwrap();
    let address_entry = dynamic_entry_offset(&bytes, 32);
    bytes[address_entry + 8..address_entry + 16]
        .copy_from_slice(&(u64::MAX - 3).to_le_bytes());
    fs::write(&bad, bytes).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-dyninit"))
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("virtual range overflows u64"));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn missing_preinit_array_size_pair_is_rejected() {
    if !tool_available("as") || !tool_available("ld") {
        return;
    }
    let dir = temp_dir("dynpreinit-pair");
    let executable = build_dynamic_executable(&dir);
    let bad = dir.join("pair");
    let mut bytes = fs::read(&executable).unwrap();
    let size_entry = dynamic_entry_offset(&bytes, 33);
    bytes[size_entry..size_entry + 8].copy_from_slice(&0x6000_000du64.to_le_bytes());
    fs::write(&bad, bytes).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-dyninit"))
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("must provide DT_PREINIT_ARRAY and DT_PREINIT_ARRAYSZ together"));
    let _ = fs::remove_dir_all(dir);
}
