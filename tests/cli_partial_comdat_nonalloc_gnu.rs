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
}

fn temp_dir(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after Unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "mini-elf-toolchain-partial-comdat-nonalloc-{label}-{}-{nonce}",
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

fn section_hex(path: &Path, section: &str) -> String {
    let output = Command::new("readelf")
        .args(["-x", section])
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

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn poison_grouped_nonalloc_sh_link(path: &Path) {
    let mut bytes = fs::read(path).unwrap();
    let shoff = read_u64(&bytes, 40) as usize;
    let shentsize = read_u16(&bytes, 58) as usize;
    let shnum = read_u16(&bytes, 60) as usize;
    let mut changed = false;

    for section_index in 0..shnum {
        let section = shoff + section_index * shentsize;
        let section_type = read_u32(&bytes, section + 4);
        let flags = read_u64(&bytes, section + 8);
        const SHT_PROGBITS: u32 = 1;
        const SHF_ALLOC: u64 = 0x2;
        const SHF_GROUP: u64 = 0x200;
        if section_type == SHT_PROGBITS && flags & SHF_GROUP != 0 && flags & SHF_ALLOC == 0 {
            bytes[section + 40..section + 44].copy_from_slice(&1_u32.to_le_bytes());
            changed = true;
            break;
        }
    }

    assert!(
        changed,
        "fixture did not contain grouped non-alloc SHT_PROGBITS"
    );
    fs::write(path, bytes).unwrap();
}

fn grouped_source(payload: u64) -> String {
    format!(
        r#".section .text.debug_group,"axG",@progbits,debug_group,comdat
.globl debug_group
.type debug_group,@function
debug_group:
    ret
.size debug_group, .-debug_group

.section .debug.debug_group,"G",@progbits,debug_group,comdat
.quad 0x{payload:016x}
.byte 0x44, 0x42, 0x47, 0x21
"#
    )
}

#[test]
fn preserves_grouped_nonalloc_progbits_and_comdat_first_wins() {
    if !have_gnu_toolchain() {
        return;
    }

    let dir = temp_dir("preserve");
    let first = assemble(&dir, "first", &grouped_source(0x1111_2222_3333_4444));
    let second = assemble(&dir, "second", &grouped_source(0xaaaa_bbbb_cccc_dddd));

    let first_groups = section_groups(&first);
    assert!(first_groups.contains(".text.debug_group"));
    assert!(
        first_groups.contains(".debug.debug_group"),
        "GNU fixture must place the non-alloc debug section in the COMDAT group: {first_groups}"
    );

    let ours = dir.join("ours.o");
    let gnu = dir.join("gnu.o");

    let partial = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["partial", "-o"])
        .arg(&ours)
        .arg(&first)
        .arg(&second)
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
        .arg(&first)
        .arg(&second)
        .output()
        .unwrap();
    assert!(
        gnu_partial.status.success(),
        "{}",
        String::from_utf8_lossy(&gnu_partial.stderr)
    );

    for output in [&ours, &gnu] {
        let groups = section_groups(output);
        assert!(groups.contains("debug_group"), "{groups}");
        assert!(groups.contains(".text.debug_group"), "{groups}");
        assert!(groups.contains(".debug.debug_group"), "{groups}");

        let debug = section_hex(output, ".debug.debug_group");
        assert!(
            debug.contains("44443333 22221111"),
            "first COMDAT payload must survive: {debug}"
        );
        assert!(
            !debug.contains("ddddcccc bbbbaaaa"),
            "discarded duplicate COMDAT payload leaked into output: {debug}"
        );
    }

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

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn grouped_nonalloc_metadata_outside_bounded_contract_is_rejected() {
    if !have_gnu_toolchain() {
        return;
    }

    let dir = temp_dir("metadata");
    let object = assemble(&dir, "bad", &grouped_source(0x0102_0304_0506_0708));
    poison_grouped_nonalloc_sh_link(&object);

    let output = dir.join("bad-partial.o");
    let partial = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["partial", "-o"])
        .arg(&output)
        .arg(&object)
        .output()
        .unwrap();

    assert!(!partial.status.success());
    assert!(!output.exists());
    let stderr = String::from_utf8_lossy(&partial.stderr);
    assert!(
        stderr.contains("grouped non-allocatable section")
            && stderr.contains("unsupported sh_link=1"),
        "{stderr}"
    );

    let _ = fs::remove_dir_all(dir);
}


#[test]
fn preserves_grouped_rela_targeting_nonalloc_member() {
    if !have_gnu_toolchain() {
        return;
    }

    let dir = temp_dir("rela");
    let grouped = assemble(
        &dir,
        "grouped-rela",
        r#".section .text.debug_rela,"axG",@progbits,debug_rela,comdat
.globl debug_rela
.type debug_rela,@function
debug_rela:
    ret
.size debug_rela, .-debug_rela

.section .debug.debug_rela,"G",@progbits,debug_rela,comdat
.extern external_debug_target
.quad external_debug_target
"#,
    );
    let target = assemble(
        &dir,
        "target",
        r#".section .data
.globl external_debug_target
.type external_debug_target,@object
external_debug_target:
    .quad 0x8877665544332211
.size external_debug_target, .-external_debug_target
"#,
    );

    let input_groups = section_groups(&grouped);
    assert!(input_groups.contains(".debug.debug_rela"), "{input_groups}");
    assert!(
        input_groups.contains(".rela.debug.debug_rela"),
        "GNU fixture must group the relocation section with its non-alloc target: {input_groups}"
    );

    let ours = dir.join("ours-rela.o");
    let gnu = dir.join("gnu-rela.o");

    let partial = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["partial", "-o"])
        .arg(&ours)
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
        .arg(&grouped)
        .arg(&target)
        .output()
        .unwrap();
    assert!(
        gnu_partial.status.success(),
        "{}",
        String::from_utf8_lossy(&gnu_partial.stderr)
    );

    for output in [&ours, &gnu] {
        let groups = section_groups(output);
        assert!(groups.contains(".debug.debug_rela"), "{groups}");
        assert!(groups.contains(".rela.debug.debug_rela"), "{groups}");

        let relocations = Command::new("readelf")
            .args(["-rW"])
            .arg(output)
            .output()
            .unwrap();
        assert!(relocations.status.success());
        let relocations = String::from_utf8_lossy(&relocations.stdout);
        assert!(relocations.contains(".rela.debug.debug_rela"), "{relocations}");
        assert!(relocations.contains("external_debug_target"), "{relocations}");
    }

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

    let _ = fs::remove_dir_all(dir);
}
