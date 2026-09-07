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

fn first_load_facts(output: &str) -> Vec<String> {
    output
        .lines()
        .find_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            (fields.first().copied() == Some("LOAD") && fields.len() >= 6).then(|| {
                fields[..6]
                    .iter()
                    .map(|field| (*field).to_owned())
                    .collect()
            })
        })
        .expect("expected a LOAD program header")
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn synthetic_executable_with_one_program_header() -> Vec<u8> {
    let mut bytes = vec![0u8; 120];
    bytes[0..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    put_u16(&mut bytes, 16, 2);
    put_u16(&mut bytes, 18, 62);
    put_u32(&mut bytes, 20, 1);
    put_u64(&mut bytes, 32, 64);
    put_u16(&mut bytes, 52, 64);
    put_u16(&mut bytes, 54, 56);
    put_u16(&mut bytes, 56, 1);
    bytes
}

#[test]
fn program_headers_match_gnu_readelf_first_load_facts() {
    if !tool_available("as") || !tool_available("ld") || !tool_available("readelf") {
        return;
    }

    let dir = temp_dir("readelf-program-headers");
    let assembly = dir.join("start.s");
    let object = dir.join("start.o");
    let executable = dir.join("sample");
    fs::write(
        &assembly,
        ".text\n.globl _start\n_start:\n  mov $60, %rax\n  xor %rdi, %rdi\n  syscall\n",
    )
    .unwrap();
    let assembled = Command::new("as")
        .arg("-o")
        .arg(&object)
        .arg(&assembly)
        .output()
        .unwrap();
    assert!(
        assembled.status.success(),
        "{}",
        String::from_utf8_lossy(&assembled.stderr)
    );
    let linked = Command::new("ld")
        .arg("-static")
        .arg("-e")
        .arg("_start")
        .arg("-o")
        .arg(&executable)
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        linked.status.success(),
        "{}",
        String::from_utf8_lossy(&linked.stderr)
    );

    let ours = Command::new(env!("CARGO_BIN_EXE_mini-elf-readelf"))
        .arg("--program-headers")
        .arg(&executable)
        .output()
        .unwrap();
    assert!(
        ours.status.success(),
        "{}",
        String::from_utf8_lossy(&ours.stderr)
    );
    let gnu = Command::new("readelf")
        .arg("-l")
        .arg(&executable)
        .output()
        .unwrap();
    assert!(gnu.status.success());

    let ours_stdout = String::from_utf8_lossy(&ours.stdout);
    let gnu_stdout = String::from_utf8_lossy(&gnu.stdout);
    assert_eq!(
        first_load_facts(&ours_stdout),
        first_load_facts(&gnu_stdout)
    );

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn malformed_later_program_header_table_keeps_stdout_atomic() {
    let dir = temp_dir("readelf-program-headers-atomic");
    let good = dir.join("good");
    let bad = dir.join("bad");
    fs::write(&good, synthetic_executable_with_one_program_header()).unwrap();

    let mut truncated = synthetic_executable_with_one_program_header();
    truncated.truncate(64);
    fs::write(&bad, truncated).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-readelf"))
        .arg("-l")
        .arg(&good)
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty(), "stdout must remain atomic");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("program-header table ends"), "{stderr}");

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn overflowing_program_segment_file_range_is_rejected() {
    let dir = temp_dir("readelf-program-headers-overflow");
    let bad = dir.join("overflow");
    let mut bytes = synthetic_executable_with_one_program_header();
    put_u32(&mut bytes, 64, 1);
    put_u32(&mut bytes, 68, 4);
    put_u64(&mut bytes, 72, u64::MAX);
    put_u64(&mut bytes, 96, 2);
    put_u64(&mut bytes, 104, 2);
    put_u64(&mut bytes, 112, 0x1000);
    fs::write(&bad, bytes).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-readelf"))
        .arg("--program-headers")
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("file range overflows u64"), "{stderr}");

    let _ = fs::remove_dir_all(dir);
}
