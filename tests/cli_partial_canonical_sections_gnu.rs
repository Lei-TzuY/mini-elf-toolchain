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
        "mini-elf-toolchain-partial-canonical-sections-{label}-{}-{nonce}",
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

fn named_section_count(path: &Path, wanted: &str) -> usize {
    let output = Command::new("readelf")
        .args(["-SW"])
        .arg(path)
        .output()
        .unwrap();
    assert!(output.status.success());
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| line.split_whitespace().any(|field| field == wanted))
        .count()
}

fn section_line(path: &Path, wanted: &str) -> String {
    let output = Command::new("readelf")
        .args(["-SW"])
        .arg(path)
        .output()
        .unwrap();
    assert!(output.status.success());
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find(|line| line.split_whitespace().any(|field| field == wanted))
        .unwrap_or_else(|| panic!("missing section {wanted}"))
        .to_owned()
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

#[test]
fn canonical_rodata_data_and_bss_sections_match_gnu_ld_r() {
    if !have_gnu_toolchain() {
        return;
    }

    let dir = temp_dir("merge");
    let first = assemble(
        &dir,
        "first",
        r#".section .text,"ax",@progbits
.globl _start
.type _start,@function
_start:
    mov $60, %rax
    xor %rdi, %rdi
    syscall
.size _start, .-_start

.section .rodata,"a",@progbits
.p2align 3
.globl ro_first
.type ro_first,@object
ro_first:
    .quad data_first
.size ro_first, .-ro_first

.section .data,"aw",@progbits
.p2align 3
.globl data_first
.type data_first,@object
data_first:
    .quad ro_first
.size data_first, .-data_first

.section .bss,"aw",@nobits
.p2align 4
.globl bss_first
.type bss_first,@object
bss_first:
    .zero 16
.size bss_first, .-bss_first
"#,
    );
    let second = assemble(
        &dir,
        "second",
        r#".section .text,"ax",@progbits
.p2align 4
.globl helper
.type helper,@function
helper:
    ret
.size helper, .-helper

.section .rodata,"a",@progbits
.p2align 5
.globl ro_second
.type ro_second,@object
ro_second:
    .long data_second
.size ro_second, .-ro_second

.section .data,"aw",@progbits
.p2align 4
.globl data_second
.type data_second,@object
data_second:
    .quad ro_second
.size data_second, .-data_second

.section .bss,"aw",@nobits
.p2align 5
.globl bss_second
.type bss_second,@object
bss_second:
    .zero 32
.size bss_second, .-bss_second
"#,
    );

    let ours = dir.join("ours.o");
    let gnu = dir.join("gnu.o");

    let ours_output = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["partial", "-o"])
        .arg(&ours)
        .arg(&first)
        .arg(&second)
        .output()
        .unwrap();
    assert!(
        ours_output.status.success(),
        "{}",
        String::from_utf8_lossy(&ours_output.stderr)
    );

    let gnu_output = Command::new("ld")
        .args(["-r", "-o"])
        .arg(&gnu)
        .arg(&first)
        .arg(&second)
        .output()
        .unwrap();
    assert!(
        gnu_output.status.success(),
        "{}",
        String::from_utf8_lossy(&gnu_output.stderr)
    );

    for name in [
        ".text",
        ".rodata",
        ".data",
        ".bss",
        ".rela.rodata",
        ".rela.data",
    ] {
        assert_eq!(
            named_section_count(&ours, name),
            named_section_count(&gnu, name),
            "section count differs for {name}"
        );
        assert_eq!(
            named_section_count(&ours, name),
            1,
            "canonical output should contain one {name}"
        );
    }

    assert!(
        section_line(&ours, ".bss").contains("NOBITS"),
        "merged .bss must remain SHT_NOBITS"
    );
    assert_eq!(global_defined_values(&ours), global_defined_values(&gnu));
    assert_eq!(
        relocation_offsets(&ours, "R_X86_64_64"),
        relocation_offsets(&gnu, "R_X86_64_64")
    );
    assert_eq!(
        relocation_offsets(&ours, "R_X86_64_32"),
        relocation_offsets(&gnu, "R_X86_64_32")
    );

    let values = global_defined_values(&ours);
    assert_eq!(values["ro_second"] % 32, 0);
    assert_eq!(values["data_second"] % 16, 0);
    assert_eq!(values["bss_second"] % 32, 0);

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
fn noncanonical_alloc_sections_remain_independent() {
    if !have_gnu_toolchain() {
        return;
    }

    let dir = temp_dir("noncanonical");
    let first = assemble(
        &dir,
        "first",
        r#".section .custom.alloc,"a",@progbits
.globl custom_first
custom_first:
    .quad 1
"#,
    );
    let second = assemble(
        &dir,
        "second",
        r#".section .custom.alloc,"a",@progbits
.globl custom_second
custom_second:
    .quad 2
"#,
    );
    let ours = dir.join("ours.o");

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["partial", "-o"])
        .arg(&ours)
        .arg(&first)
        .arg(&second)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(named_section_count(&ours, ".custom.alloc"), 2);

    let _ = fs::remove_dir_all(dir);
}
