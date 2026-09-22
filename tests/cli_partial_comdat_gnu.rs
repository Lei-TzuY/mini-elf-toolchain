use std::collections::BTreeSet;
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
        "mini-elf-toolchain-partial-comdat-{label}-{}-{nonce}",
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

fn remove_last_member_from_first_group(path: &Path) {
    let mut bytes = fs::read(path).unwrap();
    let shoff = read_u64(&bytes, 40) as usize;
    let shentsize = read_u16(&bytes, 58) as usize;
    let shnum = read_u16(&bytes, 60) as usize;
    let mut changed = false;

    for section_index in 0..shnum {
        let section = shoff + section_index * shentsize;
        if read_u32(&bytes, section + 4) != 17 {
            continue;
        }
        let size = read_u64(&bytes, section + 32);
        assert!(
            size >= 12,
            "fixture group must contain at least two members"
        );
        bytes[section + 32..section + 40].copy_from_slice(&(size - 4).to_le_bytes());
        changed = true;
        break;
    }

    assert!(changed, "fixture did not contain SHT_GROUP");
    fs::write(path, bytes).unwrap();
}

fn section_groups(path: &Path) -> String {
    let output = Command::new("readelf")
        .arg("--section-groups")
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

fn global_records(path: &Path) -> BTreeSet<String> {
    let output = Command::new("nm").arg("-g").arg(path).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

#[test]
fn preserves_single_gnu_comdat_group_through_partial_link() {
    if !have_gnu_toolchain() {
        return;
    }

    let dir = temp_dir("preserve");
    let start = assemble(
        &dir,
        "start",
        r#".section .text
.globl _start
.type _start,@function
.extern comdat_fn
_start:
    mov $60, %rax
    xor %rdi, %rdi
    syscall
    .quad comdat_fn
.size _start, .-_start
"#,
    );
    let grouped = assemble(
        &dir,
        "grouped",
        r#".section .text.comdat_fn,"axG",@progbits,comdat_fn,comdat
.globl comdat_fn
.type comdat_fn,@function
comdat_fn:
    ret
.size comdat_fn, .-comdat_fn
"#,
    );

    let input_groups = section_groups(&grouped);
    assert!(input_groups.contains("COMDAT group section"));
    assert!(input_groups.contains("comdat_fn"));
    assert!(input_groups.contains(".text.comdat_fn"));

    let ours = dir.join("ours.o");
    let gnu = dir.join("gnu.o");

    let partial = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["partial", "-o"])
        .arg(&ours)
        .arg(&start)
        .arg(&grouped)
        .output()
        .unwrap();
    assert!(
        partial.status.success(),
        "{}",
        String::from_utf8_lossy(&partial.stderr)
    );

    let gnu_partial = Command::new("ld")
        .args(["-r", "-o"])
        .arg(&gnu)
        .arg(&start)
        .arg(&grouped)
        .output()
        .unwrap();
    assert!(
        gnu_partial.status.success(),
        "{}",
        String::from_utf8_lossy(&gnu_partial.stderr)
    );

    let ours_groups = section_groups(&ours);
    let gnu_groups = section_groups(&gnu);
    for output in [&ours_groups, &gnu_groups] {
        assert!(output.contains("COMDAT group section"));
        assert!(output.contains("comdat_fn"));
        assert!(output.contains(".text.comdat_fn"));
    }
    assert_eq!(global_records(&ours), global_records(&gnu));

    let validate = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .arg("validate-rel")
        .arg(&ours)
        .output()
        .unwrap();
    assert!(
        validate.status.success(),
        "{}",
        String::from_utf8_lossy(&validate.stderr)
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
fn preserves_grouped_rela_member_through_partial_link() {
    if !have_gnu_toolchain() {
        return;
    }

    let dir = temp_dir("rela-member");
    let start_object = assemble(
        &dir,
        "start-rela",
        r#".section .text
.globl _start
.type _start,@function
.extern grouped_rela
_start:
    mov $60, %rax
    xor %rdi, %rdi
    syscall
    .quad grouped_rela
.size _start, .-_start
"#,
    );
    let grouped = assemble(
        &dir,
        "grouped-rela",
        r#".section .text.grouped_rela,"axG",@progbits,grouped_rela,comdat
.globl grouped_rela
.type grouped_rela,@function
.extern external_target
grouped_rela:
    .quad external_target
    ret
.size grouped_rela, .-grouped_rela
"#,
    );
    let target = assemble(
        &dir,
        "target",
        r#".section .data
.globl external_target
.type external_target,@object
external_target:
    .quad 0x1122334455667788
.size external_target, .-external_target
"#,
    );

    let input_groups = section_groups(&grouped);
    assert!(input_groups.contains(".text.grouped_rela"));
    assert!(
        input_groups.contains(".rela.text.grouped_rela"),
        "GNU fixture must put the relocation section in the COMDAT group: {input_groups}"
    );

    let ours = dir.join("ours-rela.o");
    let gnu = dir.join("gnu-rela.o");

    let partial = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["partial", "-o"])
        .arg(&ours)
        .arg(&start_object)
        .arg(&grouped)
        .arg(&target)
        .output()
        .unwrap();
    assert!(
        partial.status.success(),
        "{}",
        String::from_utf8_lossy(&partial.stderr)
    );

    let gnu_partial = Command::new("ld")
        .args(["-r", "-o"])
        .arg(&gnu)
        .arg(&start_object)
        .arg(&grouped)
        .arg(&target)
        .output()
        .unwrap();
    assert!(
        gnu_partial.status.success(),
        "{}",
        String::from_utf8_lossy(&gnu_partial.stderr)
    );

    let ours_groups = section_groups(&ours);
    let gnu_groups = section_groups(&gnu);
    for output in [&ours_groups, &gnu_groups] {
        assert!(output.contains("grouped_rela"));
        assert!(output.contains(".text.grouped_rela"));
        assert!(output.contains(".rela.text.grouped_rela"));
    }
    assert_eq!(global_records(&ours), global_records(&gnu));

    let ours_relocations = Command::new("readelf")
        .args(["-rW"])
        .arg(&ours)
        .output()
        .unwrap();
    assert!(ours_relocations.status.success());
    let ours_relocations = String::from_utf8_lossy(&ours_relocations.stdout);
    assert!(ours_relocations.contains(".rela.text.grouped_rela"));
    assert!(ours_relocations.contains("external_target"));

    let validate = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .arg("validate-rel")
        .arg(&ours)
        .output()
        .unwrap();
    assert!(
        validate.status.success(),
        "{}",
        String::from_utf8_lossy(&validate.stderr)
    );

    let mini_exe = dir.join("mini-rela-final");
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

    let gnu_exe = dir.join("gnu-rela-final");
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
fn orphan_grouped_rela_section_is_rejected_without_output() {
    if !have_gnu_toolchain() {
        return;
    }

    let dir = temp_dir("orphan-rela");
    let grouped = assemble(
        &dir,
        "orphan-grouped-rela",
        r#".section .text.orphan_grouped,"axG",@progbits,orphan_grouped,comdat
.globl orphan_grouped
.type orphan_grouped,@function
.extern external_target
orphan_grouped:
    .quad external_target
    ret
.size orphan_grouped, .-orphan_grouped
"#,
    );
    let groups = section_groups(&grouped);
    assert!(groups.contains(".text.orphan_grouped"));
    assert!(groups.contains(".rela.text.orphan_grouped"));

    remove_last_member_from_first_group(&grouped);

    let output = dir.join("partial.o");
    let result = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["partial", "-o"])
        .arg(&output)
        .arg(&grouped)
        .output()
        .unwrap();

    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&result.stderr)
            .contains("SHF_GROUP without membership in a supported SHT_GROUP"),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(!output.exists());

    let _ = fs::remove_dir_all(dir);
}
