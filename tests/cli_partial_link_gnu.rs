use std::collections::{BTreeMap, BTreeSet};
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

fn have_gnu_toolchain() -> bool {
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
        "mini-elf-toolchain-partial-{label}-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&path).unwrap();
    path
}

fn assemble(dir: &Path, stem: &str, source: &str) -> PathBuf {
    let asm = dir.join(format!("{stem}.s"));
    let object = dir.join(format!("{stem}.o"));
    fs::write(&asm, source).unwrap();
    let status = Command::new("as")
        .args(["--64", "-o"])
        .arg(&object)
        .arg(&asm)
        .status()
        .unwrap();
    assert!(status.success(), "GNU as failed for {stem}");
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

fn rewrite_first_defined_global_symbol_to_shn_xindex(path: &Path) {
    let mut bytes = fs::read(path).unwrap();
    let shoff = read_u64(&bytes, 40) as usize;
    let shentsize = read_u16(&bytes, 58) as usize;
    let shnum = read_u16(&bytes, 60) as usize;
    let mut rewritten = false;

    for section_index in 0..shnum {
        let section = shoff + section_index * shentsize;
        if read_u32(&bytes, section + 4) != 2 {
            continue;
        }
        let offset = read_u64(&bytes, section + 24) as usize;
        let size = read_u64(&bytes, section + 32) as usize;
        let entry_size = read_u64(&bytes, section + 56) as usize;
        assert!(entry_size >= 24);

        for symbol in (offset..offset + size).step_by(entry_size) {
            let info = bytes[symbol + 4];
            let binding = info >> 4;
            let section_index = read_u16(&bytes, symbol + 6);
            if binding == 1 && section_index != 0 && section_index < 0xff00 {
                bytes[symbol + 6..symbol + 8].copy_from_slice(&0xffff_u16.to_le_bytes());
                rewritten = true;
                break;
            }
        }
        if rewritten {
            break;
        }
    }

    assert!(rewritten, "fixture did not contain a defined global symbol");
    fs::write(path, bytes).unwrap();
}

fn global_defined_names(path: &Path) -> BTreeSet<String> {
    let output = Command::new("nm")
        .args(["-g", "--defined-only"])
        .arg(path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.split_whitespace().last())
        .map(ToOwned::to_owned)
        .collect()
}

fn global_defined_values(path: &Path) -> BTreeMap<String, u64> {
    let output = Command::new("nm")
        .args(["-g", "--defined-only", "-n"])
        .arg(path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            if fields.len() < 3 {
                return None;
            }
            let value = u64::from_str_radix(fields[0], 16).ok()?;
            Some((fields[2].to_owned(), value))
        })
        .collect()
}

fn named_section_count(path: &Path, wanted: &str) -> usize {
    let output = Command::new("readelf")
        .args(["-SW"])
        .arg(path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| line.split_whitespace().any(|field| field == wanted))
        .count()
}

fn relocation_offsets(path: &Path, relocation_name: &str) -> BTreeSet<u64> {
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
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| line.contains(relocation_name))
        .filter_map(|line| line.split_whitespace().next())
        .filter_map(|offset| u64::from_str_radix(offset, 16).ok())
        .collect()
}

fn global_nm_records(path: &Path) -> Vec<(String, char, Option<u64>)> {
    let output = Command::new("nm").arg("-g").arg(path).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut records = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            match fields.as_slice() {
                [kind, name] => Some((
                    (*name).to_owned(),
                    kind.chars().next()?,
                    None,
                )),
                [value, kind, name, ..] => Some((
                    (*name).to_owned(),
                    kind.chars().next()?,
                    u64::from_str_radix(value, 16).ok(),
                )),
                _ => None,
            }
        })
        .collect::<Vec<_>>();
    records.sort();
    records
}

fn readelf_symbol_record(path: &Path, wanted: &str) -> Vec<String> {
    let output = Command::new("readelf")
        .args(["-sW"])
        .arg(path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            if fields.last().copied() != Some(wanted) || fields.len() < 8 {
                return None;
            }
            Some(fields[1..].join(" "))
        })
        .collect()
}

fn build_inputs(dir: &Path) -> (PathBuf, PathBuf) {
    let start = assemble(
        dir,
        "start",
        r#".section .text
.globl _start
.type _start,@function
_start:
    mov $60, %rax
    xor %rdi, %rdi
    syscall
    .quad helper
.size _start, .-_start
"#,
    );
    let helper = assemble(
        dir,
        "helper",
        r#".section .text
.globl helper
.type helper,@function
helper:
    ret
.size helper, .-helper

.section .rodata
.globl helper_marker
.type helper_marker,@object
helper_marker:
    .quad 0x1122334455667788
.size helper_marker, .-helper_marker

.section .bss
.align 16
.globl helper_scratch
.type helper_scratch,@object
helper_scratch:
    .zero 16
.size helper_scratch, .-helper_scratch
"#,
    );
    (start, helper)
}

#[test]
fn partial_output_is_consumable_by_mini_and_gnu_linkers() {
    if !have_gnu_toolchain() {
        return;
    }

    let dir = temp_dir("interop");
    let (start, helper) = build_inputs(&dir);
    let ours_partial = dir.join("ours-partial.o");
    let gnu_partial = dir.join("gnu-partial.o");

    let partial = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["partial", "-o"])
        .arg(&ours_partial)
        .arg(&start)
        .arg(&helper)
        .output()
        .unwrap();
    assert!(
        partial.status.success(),
        "{}",
        String::from_utf8_lossy(&partial.stderr)
    );
    assert!(String::from_utf8_lossy(&partial.stdout).contains("partial ELF64 x86-64"));

    let validate = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .arg("validate-rel")
        .arg(&ours_partial)
        .output()
        .unwrap();
    assert!(
        validate.status.success(),
        "{}",
        String::from_utf8_lossy(&validate.stderr)
    );

    let header = Command::new("readelf")
        .args(["-hW"])
        .arg(&ours_partial)
        .output()
        .unwrap();
    assert!(header.status.success());
    assert!(
        String::from_utf8_lossy(&header.stdout).contains("Type:                              REL")
    );

    let relocations = Command::new("readelf")
        .args(["-rW"])
        .arg(&ours_partial)
        .output()
        .unwrap();
    assert!(relocations.status.success());
    let reloc_text = String::from_utf8_lossy(&relocations.stdout);
    assert!(reloc_text.contains("R_X86_64_64"));
    assert!(reloc_text.contains("helper"));

    let gnu_partial_status = Command::new("ld")
        .args(["-r", "-o"])
        .arg(&gnu_partial)
        .arg(&start)
        .arg(&helper)
        .status()
        .unwrap();
    assert!(gnu_partial_status.success());
    assert_eq!(
        global_defined_names(&ours_partial),
        global_defined_names(&gnu_partial)
    );

    let mini_exe = dir.join("mini-final");
    let mini = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&mini_exe)
        .arg(&ours_partial)
        .output()
        .unwrap();
    assert!(
        mini.status.success(),
        "{}",
        String::from_utf8_lossy(&mini.stderr)
    );

    let gnu_exe = dir.join("gnu-final");
    let gnu = Command::new("ld")
        .args(["-static", "-o"])
        .arg(&gnu_exe)
        .arg(&ours_partial)
        .output()
        .unwrap();
    assert!(
        gnu.status.success(),
        "{}",
        String::from_utf8_lossy(&gnu.stderr)
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
fn partial_output_is_deterministic_for_identical_inputs() {
    if !command_reports("as", "GNU assembler") {
        return;
    }

    let dir = temp_dir("deterministic");
    let (start, helper) = build_inputs(&dir);
    let first = dir.join("first.o");
    let second = dir.join("second.o");

    for output in [&first, &second] {
        let result = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
            .args(["partial", "-o"])
            .arg(output)
            .arg(&start)
            .arg(&helper)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }

    assert_eq!(fs::read(&first).unwrap(), fs::read(&second).unwrap());
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn malformed_later_input_fails_without_writing_partial_output() {
    if !command_reports("as", "GNU assembler") {
        return;
    }

    let dir = temp_dir("malformed");
    let valid = assemble(&dir, "valid", ".text\n.globl valid\nvalid:\n  ret\n");
    let invalid = dir.join("invalid.o");
    fs::write(&invalid, b"not an ELF object").unwrap();
    let output = dir.join("partial.o");

    let result = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["partial", "-o"])
        .arg(&output)
        .arg(&valid)
        .arg(&invalid)
        .output()
        .unwrap();

    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert!(String::from_utf8_lossy(&result.stderr).contains("invalid.o"));
    assert!(!output.exists());

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn grouped_alloc_section_is_rejected_without_output() {
    if !command_reports("as", "GNU assembler") {
        return;
    }

    let dir = temp_dir("comdat");
    let source = dir.join("comdat.s");
    let object = dir.join("comdat.o");
    let output = dir.join("partial.o");

    fs::write(
        &source,
        r#".section .text.comdat_fn,"axG",@progbits,comdat_fn,comdat
.globl comdat_fn
.type comdat_fn,@function
comdat_fn:
    ret
.size comdat_fn, .-comdat_fn
"#,
    )
    .unwrap();

    assert!(Command::new("as")
        .args(["--64", "-o"])
        .arg(&object)
        .arg(&source)
        .status()
        .unwrap()
        .success());

    let sections = Command::new("readelf")
        .args(["-SW"])
        .arg(&object)
        .output()
        .unwrap();
    assert!(sections.status.success());
    assert!(
        String::from_utf8_lossy(&sections.stdout).contains(".group"),
        "GNU fixture must carry SHT_GROUP metadata"
    );

    let result = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["partial", "-o"])
        .arg(&output)
        .arg(&object)
        .output()
        .unwrap();

    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&result.stderr).contains("SHF_GROUP/COMDAT"),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(!output.exists());

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn shn_xindex_symbol_is_rejected_without_output() {
    if !command_reports("as", "GNU assembler") {
        return;
    }

    let dir = temp_dir("shn-xindex");
    let object = assemble(
        &dir,
        "xindex",
        ".text\n.globl xindex_target\n.type xindex_target,@function\nxindex_target:\n  ret\n.size xindex_target, .-xindex_target\n",
    );
    let output = dir.join("partial.o");

    rewrite_first_defined_global_symbol_to_shn_xindex(&object);

    let result = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["partial", "-o"])
        .arg(&output)
        .arg(&object)
        .output()
        .unwrap();

    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&result.stderr).contains("SHN_XINDEX"),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(!output.exists());

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn compatible_text_sections_are_coalesced_with_gnu_ld_r_offsets() {
    if !have_gnu_toolchain() {
        return;
    }

    let dir = temp_dir("coalesce-text");
    let start = assemble(
        &dir,
        "coalesce-start",
        r#".section .text
.globl _start
.type _start,@function
_start:
    mov $60, %rax
    xor %rdi, %rdi
    syscall
    .quad helper
.size _start, .-_start
"#,
    );
    let helper = assemble(
        &dir,
        "coalesce-helper",
        r#".section .text,"ax",@progbits
.p2align 4
.globl helper
.type helper,@function
helper:
    ret
    .quad _start
.size helper, .-helper
"#,
    );
    let ours_partial = dir.join("ours-coalesced.o");
    let gnu_partial = dir.join("gnu-coalesced.o");

    let ours = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["partial", "-o"])
        .arg(&ours_partial)
        .arg(&start)
        .arg(&helper)
        .output()
        .unwrap();
    assert!(
        ours.status.success(),
        "{}",
        String::from_utf8_lossy(&ours.stderr)
    );

    let gnu = Command::new("ld")
        .args(["-r", "-o"])
        .arg(&gnu_partial)
        .arg(&start)
        .arg(&helper)
        .output()
        .unwrap();
    assert!(
        gnu.status.success(),
        "{}",
        String::from_utf8_lossy(&gnu.stderr)
    );

    assert_eq!(named_section_count(&ours_partial, ".text"), 1);
    assert_eq!(named_section_count(&gnu_partial, ".text"), 1);
    assert_eq!(
        global_defined_values(&ours_partial),
        global_defined_values(&gnu_partial)
    );
    assert_eq!(
        relocation_offsets(&ours_partial, "R_X86_64_64"),
        relocation_offsets(&gnu_partial, "R_X86_64_64")
    );

    let helper_value = global_defined_values(&ours_partial)
        .get("helper")
        .copied()
        .unwrap();
    assert_eq!(
        helper_value % 16,
        0,
        "helper contribution lost 16-byte alignment"
    );

    let mini_exe = dir.join("mini-coalesced");
    let mini = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&mini_exe)
        .arg(&ours_partial)
        .output()
        .unwrap();
    assert!(
        mini.status.success(),
        "{}",
        String::from_utf8_lossy(&mini.stderr)
    );

    let gnu_exe = dir.join("gnu-coalesced");
    let gnu_final = Command::new("ld")
        .args(["-static", "-o"])
        .arg(&gnu_exe)
        .arg(&ours_partial)
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
fn global_and_weak_symbols_are_canonicalized_like_gnu_ld_r() {
    if !have_gnu_toolchain() {
        return;
    }

    let dir = temp_dir("resolve-global-weak");
    let start = assemble(
        &dir,
        "resolve-start",
        r#".section .text
.globl _start
.type _start,@function
_start:
    mov $60, %rax
    xor %rdi, %rdi
    syscall
    .quad choice
.size _start, .-_start
"#,
    );
    let weak = assemble(
        &dir,
        "resolve-weak",
        r#".section .text
.weak choice
.type choice,@function
choice:
    ret
.size choice, .-choice
"#,
    );
    let strong = assemble(
        &dir,
        "resolve-strong",
        r#".section .text
.globl choice
.type choice,@function
choice:
    ret
.size choice, .-choice
"#,
    );
    let ours_partial = dir.join("ours-resolved.o");
    let gnu_partial = dir.join("gnu-resolved.o");

    let ours = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["partial", "-o"])
        .arg(&ours_partial)
        .arg(&start)
        .arg(&weak)
        .arg(&strong)
        .output()
        .unwrap();
    assert!(
        ours.status.success(),
        "{}",
        String::from_utf8_lossy(&ours.stderr)
    );

    let gnu = Command::new("ld")
        .args(["-r", "-o"])
        .arg(&gnu_partial)
        .arg(&start)
        .arg(&weak)
        .arg(&strong)
        .output()
        .unwrap();
    assert!(
        gnu.status.success(),
        "{}",
        String::from_utf8_lossy(&gnu.stderr)
    );

    assert_eq!(global_nm_records(&ours_partial), global_nm_records(&gnu_partial));
    assert_eq!(
        global_nm_records(&ours_partial)
            .iter()
            .filter(|(name, _, _)| name == "choice")
            .count(),
        1
    );
    assert!(
        !global_nm_records(&ours_partial)
            .iter()
            .any(|(name, kind, _)| name == "choice" && *kind == 'U')
    );

    let mini_exe = dir.join("mini-resolved");
    let mini = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&mini_exe)
        .arg(&ours_partial)
        .output()
        .unwrap();
    assert!(
        mini.status.success(),
        "{}",
        String::from_utf8_lossy(&mini.stderr)
    );

    let gnu_exe = dir.join("gnu-resolved");
    let gnu_final = Command::new("ld")
        .args(["-static", "-o"])
        .arg(&gnu_exe)
        .arg(&ours_partial)
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
fn common_symbols_are_merged_like_gnu_ld_r() {
    if !have_gnu_toolchain() {
        return;
    }

    let dir = temp_dir("resolve-common");
    let small = assemble(&dir, "common-small", ".comm common_sym,8,8\n");
    let large = assemble(&dir, "common-large", ".comm common_sym,16,16\n");
    let ours_partial = dir.join("ours-common.o");
    let gnu_partial = dir.join("gnu-common.o");

    let ours = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["partial", "-o"])
        .arg(&ours_partial)
        .arg(&small)
        .arg(&large)
        .output()
        .unwrap();
    assert!(
        ours.status.success(),
        "{}",
        String::from_utf8_lossy(&ours.stderr)
    );

    let gnu = Command::new("ld")
        .args(["-r", "-o"])
        .arg(&gnu_partial)
        .arg(&small)
        .arg(&large)
        .output()
        .unwrap();
    assert!(
        gnu.status.success(),
        "{}",
        String::from_utf8_lossy(&gnu.stderr)
    );

    assert_eq!(
        readelf_symbol_record(&ours_partial, "common_sym"),
        readelf_symbol_record(&gnu_partial, "common_sym")
    );
    assert_eq!(readelf_symbol_record(&ours_partial, "common_sym").len(), 1);

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn multiple_strong_definitions_fail_before_partial_output() {
    if !have_gnu_toolchain() {
        return;
    }

    let dir = temp_dir("resolve-duplicate-strong");
    let first = assemble(
        &dir,
        "strong-first",
        ".text\n.globl duplicate_symbol\n.type duplicate_symbol,@function\nduplicate_symbol:\n  ret\n.size duplicate_symbol, .-duplicate_symbol\n",
    );
    let second = assemble(
        &dir,
        "strong-second",
        ".text\n.globl duplicate_symbol\n.type duplicate_symbol,@function\nduplicate_symbol:\n  nop\n  ret\n.size duplicate_symbol, .-duplicate_symbol\n",
    );
    let ours_partial = dir.join("ours-duplicate.o");
    let gnu_partial = dir.join("gnu-duplicate.o");

    let gnu = Command::new("ld")
        .args(["-r", "-o"])
        .arg(&gnu_partial)
        .arg(&first)
        .arg(&second)
        .output()
        .unwrap();
    assert!(!gnu.status.success(), "GNU ld -r unexpectedly accepted duplicate strong definitions");

    let ours = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["partial", "-o"])
        .arg(&ours_partial)
        .arg(&first)
        .arg(&second)
        .output()
        .unwrap();

    assert!(!ours.status.success());
    assert!(ours.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&ours.stderr).contains("multiple strong definitions"),
        "{}",
        String::from_utf8_lossy(&ours.stderr)
    );
    assert!(!ours_partial.exists());

    let _ = fs::remove_dir_all(dir);
}
