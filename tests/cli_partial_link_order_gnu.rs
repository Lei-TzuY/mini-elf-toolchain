use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const SHF_ALLOC: u64 = 0x2;
const SHF_LINK_ORDER: u64 = 0x80;
const SHF_GROUP: u64 = 0x200;

#[derive(Debug, Clone)]
struct SectionRecord {
    index: u16,
    name: String,
    section_type: u32,
    flags: u64,
    offset: u64,
    size: u64,
    link: u32,
    info: u32,
}

fn command_reports(program: &str, marker: &str) -> bool {
    let Ok(output) = Command::new(program).arg("--version").output() else {
        return false;
    };
    output.status.success()
        && (String::from_utf8_lossy(&output.stdout).contains(marker)
            || String::from_utf8_lossy(&output.stderr).contains(marker))
}

fn have_gnu_tools() -> bool {
    command_reports("as", "GNU assembler")
        && command_reports("ld", "GNU ld")
        && command_reports("readelf", "GNU readelf")
}

fn temp_dir(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after Unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "mini-elf-toolchain-link-order-{label}-{}-{nonce}",
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

fn partial(output: &Path, inputs: &[&Path]) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"));
    command.args(["partial", "-o"]).arg(output);
    for input in inputs {
        command.arg(input);
    }
    command.output().unwrap()
}

fn gnu_partial(output: &Path, inputs: &[&Path]) -> std::process::Output {
    let mut command = Command::new("ld");
    command.args(["-r", "-o"]).arg(output);
    for input in inputs {
        command.arg(input);
    }
    command.output().unwrap()
}

fn sections(path: &Path) -> Vec<SectionRecord> {
    let bytes = fs::read(path).unwrap();
    let shoff = read_u64(&bytes, 40) as usize;
    let shentsize = read_u16(&bytes, 58) as usize;
    let shnum = read_u16(&bytes, 60) as usize;
    let shstrndx = read_u16(&bytes, 62) as usize;
    assert_eq!(shentsize, 64);
    assert!(shstrndx < shnum);

    let shstr = shoff + shstrndx * shentsize;
    let names_offset = read_u64(&bytes, shstr + 24) as usize;
    let names_size = read_u64(&bytes, shstr + 32) as usize;
    let names = &bytes[names_offset..names_offset + names_size];

    (0..shnum)
        .map(|index| {
            let header = shoff + index * shentsize;
            let name_offset = read_u32(&bytes, header) as usize;
            let tail = &names[name_offset..];
            let end = tail.iter().position(|byte| *byte == 0).unwrap();
            SectionRecord {
                index: index as u16,
                name: String::from_utf8_lossy(&tail[..end]).into_owned(),
                section_type: read_u32(&bytes, header + 4),
                flags: read_u64(&bytes, header + 8),
                offset: read_u64(&bytes, header + 24),
                size: read_u64(&bytes, header + 32),
                link: read_u32(&bytes, header + 40),
                info: read_u32(&bytes, header + 44),
            }
        })
        .collect()
}

fn section<'a>(records: &'a [SectionRecord], name: &str) -> &'a SectionRecord {
    records
        .iter()
        .find(|record| record.name == name)
        .unwrap_or_else(|| panic!("missing section {name}: {records:?}"))
}

fn section_bytes(path: &Path, record: &SectionRecord) -> Vec<u8> {
    let bytes = fs::read(path).unwrap();
    let start = record.offset as usize;
    let end = start + record.size as usize;
    bytes[start..end].to_vec()
}

fn set_section_info(path: &Path, name: &str, info: u32) {
    let mut bytes = fs::read(path).unwrap();
    let records = sections(path);
    let record = section(&records, name);
    let shoff = read_u64(&bytes, 40) as usize;
    let shentsize = read_u16(&bytes, 58) as usize;
    let header = shoff + usize::from(record.index) * shentsize;
    bytes[header + 44..header + 48].copy_from_slice(&info.to_le_bytes());
    fs::write(path, bytes).unwrap();
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

#[test]
fn preserves_forward_link_order_target_and_final_link_interoperability() {
    if !have_gnu_tools() {
        return;
    }

    let dir = temp_dir("forward");
    let input = assemble(
        &dir,
        "forward",
        r#".section .meta.target,"ao",@progbits,.text.target
.quad 0x1122334455667788

.section .text.target,"ax",@progbits
.globl target
.type target,@function
target:
    ret
.size target, .-target

.text
.globl _start
.type _start,@function
_start:
    mov $60, %rax
    xor %rdi, %rdi
    syscall
.size _start, .-_start

.section .note.GNU-stack,"",@progbits
"#,
    );

    let ours = dir.join("ours.o");
    let linked = partial(&ours, &[&input]);
    assert!(
        linked.status.success(),
        "{}",
        String::from_utf8_lossy(&linked.stderr)
    );

    let records = sections(&ours);
    let target = section(&records, ".text.target");
    let metadata = section(&records, ".meta.target");
    assert_ne!(target.index, 0);
    assert_eq!(
        metadata.flags & (SHF_ALLOC | SHF_LINK_ORDER),
        SHF_ALLOC | SHF_LINK_ORDER
    );
    assert_eq!(metadata.link, u32::from(target.index));
    assert_eq!(metadata.info, 0);

    let gnu = dir.join("gnu.o");
    let reference = gnu_partial(&gnu, &[&input]);
    assert!(
        reference.status.success(),
        "{}",
        String::from_utf8_lossy(&reference.stderr)
    );
    let gnu_records = sections(&gnu);
    let gnu_target = section(&gnu_records, ".text.target");
    let gnu_metadata = section(&gnu_records, ".meta.target");
    assert_eq!(gnu_metadata.link, u32::from(gnu_target.index));
    assert_eq!(
        metadata.flags & (SHF_ALLOC | SHF_LINK_ORDER),
        gnu_metadata.flags & (SHF_ALLOC | SHF_LINK_ORDER)
    );

    let mini_exe = dir.join("mini-final");
    let mini = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&mini_exe)
        .arg(&ours)
        .output()
        .unwrap();
    assert!(
        mini.status.success(),
        "{}",
        String::from_utf8_lossy(&mini.stderr)
    );

    let gnu_exe = dir.join("gnu-final");
    let gnu_final = Command::new("ld")
        .args(["-static", "-o"])
        .arg(&gnu_exe)
        .arg(&ours)
        .output()
        .unwrap();
    assert!(
        gnu_final.status.success(),
        "{}",
        String::from_utf8_lossy(&gnu_final.stderr)
    );

    #[cfg(target_os = "linux")]
    for executable in [&mini_exe, &gnu_exe] {
        let status = Command::new(executable).status().unwrap();
        assert!(
            status.success(),
            "{} returned {status}",
            executable.display()
        );
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn coalesces_link_order_sections_only_when_their_output_target_matches() {
    if !have_gnu_tools() {
        return;
    }

    let dir = temp_dir("coalesce");
    let first = assemble(
        &dir,
        "first",
        r#".text
.globl _start
.type _start,@function
_start:
    mov $60, %rax
    xor %rdi, %rdi
    syscall
.size _start, .-_start

.section .meta,"ao",@progbits,.text
.quad 1

.section .note.GNU-stack,"",@progbits
"#,
    );
    let second = assemble(
        &dir,
        "second",
        r#".text
.globl helper
.type helper,@function
helper:
    ret
.size helper, .-helper

.section .meta,"ao",@progbits,.text
.quad 2

.section .note.GNU-stack,"",@progbits
"#,
    );

    let ours = dir.join("ours.o");
    let gnu = dir.join("gnu.o");
    let linked = partial(&ours, &[&first, &second]);
    assert!(
        linked.status.success(),
        "{}",
        String::from_utf8_lossy(&linked.stderr)
    );
    let reference = gnu_partial(&gnu, &[&first, &second]);
    assert!(
        reference.status.success(),
        "{}",
        String::from_utf8_lossy(&reference.stderr)
    );

    for path in [&ours, &gnu] {
        let records = sections(path);
        assert_eq!(
            records
                .iter()
                .filter(|record| record.name == ".meta")
                .count(),
            1
        );
        let text = section(&records, ".text");
        let metadata = section(&records, ".meta");
        assert_eq!(metadata.link, u32::from(text.index));
        assert_eq!(metadata.flags & SHF_LINK_ORDER, SHF_LINK_ORDER);
        assert_eq!(
            section_bytes(path, metadata),
            [
                1_u64.to_le_bytes().as_slice(),
                2_u64.to_le_bytes().as_slice()
            ]
            .concat()
        );
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn rejects_link_order_targets_outside_the_bounded_allocatable_model() {
    if !have_gnu_tools() {
        return;
    }

    let dir = temp_dir("reject-targets");
    let nonalloc = assemble(
        &dir,
        "nonalloc",
        r#".section .debug.target,"",@progbits
.byte 0

.section .meta.bad,"ao",@progbits,.debug.target
.quad 1
"#,
    );
    let output = dir.join("nonalloc-partial.o");
    let result = partial(&output, &[&nonalloc]);
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&result.stderr).contains("SHF_LINK_ORDER"),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(!output.exists());

    let grouped = assemble(
        &dir,
        "grouped",
        r#".section .text.pick,"axG",@progbits,pick,comdat
.globl pick
.type pick,@function
pick:
    ret
.size pick, .-pick

.section .meta.pick,"ao",@progbits,.text.pick
.quad 1
"#,
    );
    let grouped_output = dir.join("grouped-partial.o");
    let grouped_result = partial(&grouped_output, &[&grouped]);
    assert!(!grouped_result.status.success());
    assert!(grouped_result.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&grouped_result.stderr).contains("SHF_LINK_ORDER"),
        "{}",
        String::from_utf8_lossy(&grouped_result.stderr)
    );
    assert!(!grouped_output.exists());

    let chained = assemble(
        &dir,
        "chained",
        r#".text
.globl _start
_start:
    ret

.section .meta.first,"ao",@progbits,.text
.quad 1
.section .meta.second,"ao",@progbits,.meta.first
.quad 2
"#,
    );
    let chained_output = dir.join("chained-partial.o");
    let chained_result = partial(&chained_output, &[&chained]);
    assert!(!chained_result.status.success());
    assert!(chained_result.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&chained_result.stderr).contains("SHF_LINK_ORDER"),
        "{}",
        String::from_utf8_lossy(&chained_result.stderr)
    );
    assert!(!chained_output.exists());

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn rejects_nonzero_link_order_info_without_creating_output() {
    if !have_gnu_tools() {
        return;
    }

    let dir = temp_dir("nonzero-info");
    let input = assemble(
        &dir,
        "info",
        r#".text
.globl _start
_start:
    ret

.section .meta,"ao",@progbits,.text
.quad 1
"#,
    );
    set_section_info(&input, ".meta", 1);

    let output = dir.join("partial.o");
    let result = partial(&output, &[&input]);
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&result.stderr).contains("SHF_LINK_ORDER"),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(!output.exists());

    let records = sections(&input);
    let metadata = section(&records, ".meta");
    assert_eq!(metadata.info, 1);
    assert_eq!(metadata.flags & SHF_LINK_ORDER, SHF_LINK_ORDER);
    assert_eq!(metadata.section_type, 1);

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn link_order_fixture_flags_are_gnu_assembler_backed() {
    if !have_gnu_tools() {
        return;
    }

    let dir = temp_dir("fixture-flags");
    let input = assemble(
        &dir,
        "fixture",
        r#".text
.globl _start
_start:
    ret

.section .meta,"ao",@progbits,.text
.quad 1
"#,
    );
    let records = sections(&input);
    let text = section(&records, ".text");
    let metadata = section(&records, ".meta");
    assert_ne!(metadata.flags & SHF_ALLOC, 0);
    assert_ne!(metadata.flags & SHF_LINK_ORDER, 0);
    assert_eq!(metadata.flags & SHF_GROUP, 0);
    assert_eq!(metadata.link, u32::from(text.index));

    let _ = fs::remove_dir_all(dir);
}
