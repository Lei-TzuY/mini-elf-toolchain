use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const SHT_PROGBITS: u32 = 1;
const SHF_ALLOC: u64 = 0x2;
const SHF_MERGE: u64 = 0x10;
const SHF_STRINGS: u64 = 0x20;

#[derive(Debug, Clone)]
struct SectionRecord {
    index: u16,
    name: String,
    section_type: u32,
    flags: u64,
    offset: u64,
    size: u64,
    entry_size: u64,
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
        && command_reports("nm", "GNU nm")
}

fn temp_dir(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after Unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "mini-elf-toolchain-partial-merge-strings-{label}-{}-{nonce}",
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

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
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
                entry_size: read_u64(&bytes, header + 56),
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

fn section_bytes(path: &Path, section: &SectionRecord) -> Vec<u8> {
    let bytes = fs::read(path).unwrap();
    let start = section.offset as usize;
    bytes[start..start + section.size as usize].to_vec()
}

fn nm_output(path: &Path) -> String {
    let output = Command::new("nm")
        .args(["-n", "--defined-only"])
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

fn relocation_output(path: &Path) -> String {
    let output = Command::new("readelf")
        .args(["-rW"])
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
fn coalesces_merge_string_contributions_and_rebases_symbols_and_relocations() {
    if !have_gnu_tools() {
        return;
    }

    let dir = temp_dir("coalesce");
    let first = assemble(
        &dir,
        "first",
        r#".section .rodata.str1.1,"aMS",@progbits,1
.globl sa
.type sa,@object
sa:
    .asciz "hello"
.size sa, .-sa

.text
.globl _start
.type _start,@function
.extern sb
_start:
    lea sa(%rip), %rax
    cmpb $'h', (%rax)
    jne .Lfail
    lea sb(%rip), %rax
    cmpb $'w', (%rax)
    jne .Lfail
    mov $60, %rax
    xor %rdi, %rdi
    syscall
.Lfail:
    mov $60, %rax
    mov $1, %rdi
    syscall
.size _start, .-_start

.section .note.GNU-stack,"",@progbits
"#,
    );
    let second = assemble(
        &dir,
        "second",
        r#".section .rodata.str1.1,"aMS",@progbits,1
.globl sb
.type sb,@object
sb:
    .asciz "world"
.size sb, .-sb

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
                .filter(|record| record.name == ".rodata.str1.1")
                .count(),
            1,
            "{records:?}"
        );
        let strings = section(&records, ".rodata.str1.1");
        assert_ne!(strings.index, 0);
        assert_eq!(strings.section_type, SHT_PROGBITS);
        assert_eq!(
            strings.flags & (SHF_ALLOC | SHF_MERGE | SHF_STRINGS),
            SHF_ALLOC | SHF_MERGE | SHF_STRINGS
        );
        assert_eq!(strings.entry_size, 1);
        assert_eq!(section_bytes(path, strings), b"hello\0world\0");

        let symbols = nm_output(path);
        assert!(
            symbols.lines().any(|line| line.starts_with("0000000000000000 ") && line.ends_with(" sa")),
            "{symbols}"
        );
        assert!(
            symbols.lines().any(|line| line.starts_with("0000000000000006 ") && line.ends_with(" sb")),
            "{symbols}"
        );

        let relocations = relocation_output(path);
        assert!(relocations.contains("R_X86_64_PC32"), "{relocations}");
        assert!(relocations.contains(" sa "), "{relocations}");
        assert!(relocations.contains(" sb "), "{relocations}");
    }

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
fn partial_link_does_not_deduplicate_merge_string_contents() {
    if !have_gnu_tools() {
        return;
    }

    let dir = temp_dir("duplicates");
    let first = assemble(
        &dir,
        "first",
        r#".section .rodata.str1.1,"aMS",@progbits,1
.globl first_string
first_string:
    .asciz "same"
"#,
    );
    let second = assemble(
        &dir,
        "second",
        r#".section .rodata.str1.1,"aMS",@progbits,1
.globl second_string
second_string:
    .asciz "same"
"#,
    );

    let ours = dir.join("ours.o");
    let gnu = dir.join("gnu.o");
    assert!(partial(&ours, &[&first, &second]).status.success());
    assert!(gnu_partial(&gnu, &[&first, &second]).status.success());

    for path in [&ours, &gnu] {
        let records = sections(path);
        let strings = section(&records, ".rodata.str1.1");
        assert_eq!(section_bytes(path, strings), b"same\0same\0");

        let symbols = nm_output(path);
        assert!(
            symbols.lines().any(|line| line.starts_with("0000000000000000 ") && line.ends_with(" first_string")),
            "{symbols}"
        );
        assert!(
            symbols.lines().any(|line| line.starts_with("0000000000000005 ") && line.ends_with(" second_string")),
            "{symbols}"
        );
    }

    let _ = fs::remove_dir_all(dir);
}
