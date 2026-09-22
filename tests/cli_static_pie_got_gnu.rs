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
        "mini-elf-toolchain-static-pie-got-{label}-{}-{nonce}",
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

fn rewrite_symbol_as_absolute(path: &Path, target_name: &[u8], value: u64) {
    const SHT_SYMTAB: u32 = 2;
    const SHN_ABS: u16 = 0xfff1;

    let mut bytes = fs::read(path).unwrap();
    let shoff = read_u64(&bytes, 40) as usize;
    let shentsize = read_u16(&bytes, 58) as usize;
    let shnum = read_u16(&bytes, 60) as usize;
    let mut rewritten = false;

    for section_index in 0..shnum {
        let section = shoff + section_index * shentsize;
        if read_u32(&bytes, section + 4) != SHT_SYMTAB {
            continue;
        }

        let symtab_offset = read_u64(&bytes, section + 24) as usize;
        let symtab_size = read_u64(&bytes, section + 32) as usize;
        let string_table_index = read_u32(&bytes, section + 40) as usize;
        let entry_size = read_u64(&bytes, section + 56) as usize;
        assert!(entry_size >= 24);
        assert!(string_table_index < shnum);

        let string_section = shoff + string_table_index * shentsize;
        let string_offset = read_u64(&bytes, string_section + 24) as usize;
        let string_size = read_u64(&bytes, string_section + 32) as usize;
        let string_end = string_offset + string_size;

        for symbol in (symtab_offset..symtab_offset + symtab_size).step_by(entry_size) {
            let name_offset = read_u32(&bytes, symbol) as usize;
            assert!(name_offset < string_size);
            let name_start = string_offset + name_offset;
            let name_tail = &bytes[name_start..string_end];
            let name_end = name_tail
                .iter()
                .position(|byte| *byte == 0)
                .expect("symbol name must be NUL terminated");
            if &name_tail[..name_end] != target_name {
                continue;
            }

            bytes[symbol + 6..symbol + 8].copy_from_slice(&SHN_ABS.to_le_bytes());
            bytes[symbol + 8..symbol + 16].copy_from_slice(&value.to_le_bytes());
            rewritten = true;
            break;
        }

        if rewritten {
            break;
        }
    }

    assert!(
        rewritten,
        "fixture did not contain symbol {}",
        String::from_utf8_lossy(target_name)
    );
    fs::write(path, bytes).unwrap();
}

fn dynamic_relative_count(path: &Path) -> usize {
    let output = Command::new("readelf")
        .args(["-rW", "--use-dynamic"])
        .arg(path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout)
        .matches("R_X86_64_RELATIVE")
        .count()
}

#[test]
fn pie_gotpcrel_uses_one_runtime_relative_got_slot_and_executes() {
    if !have_gnu_tools() {
        return;
    }

    let dir = temp_dir("relative");
    let object = assemble(
        &dir,
        "got",
        r#".section .data
.align 8
.globl target_value
.type target_value,@object
target_value:
    .quad 0x1122334455667788
.size target_value, .-target_value

.section .text
.globl _start
.type _start,@function
_start:
    mov target_value@GOTPCREL(%rip), %rax
    mov (%rax), %rcx
    movabs $0x1122334455667788, %rdx
    cmp %rdx, %rcx
    jne .Lfail

    mov target_value@GOTPCREL(%rip), %rax
    cmp %rdx, (%rax)
    jne .Lfail

    mov $60, %rax
    xor %rdi, %rdi
    syscall
.Lfail:
    mov $60, %rax
    mov $1, %rdi
    syscall
.size _start, .-_start
"#,
    );

    let input_relocations = Command::new("readelf")
        .args(["-rW"])
        .arg(&object)
        .output()
        .unwrap();
    assert!(input_relocations.status.success());
    let input_relocations = String::from_utf8_lossy(&input_relocations.stdout);
    assert!(
        input_relocations.matches("GOTPCREL").count() >= 2,
        "fixture must contain two GOTPCREL-family relocations: {input_relocations}"
    );

    let ours = dir.join("ours-pie");
    let mini = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&ours)
        .arg("--pie")
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        mini.status.success(),
        "{}",
        String::from_utf8_lossy(&mini.stderr)
    );

    let headers = Command::new("readelf")
        .args(["-lW"])
        .arg(&ours)
        .output()
        .unwrap();
    assert!(headers.status.success());
    let headers = String::from_utf8_lossy(&headers.stdout);
    assert!(headers.contains("DYNAMIC"));
    assert!(!headers.contains("INTERP"));
    assert_eq!(
        dynamic_relative_count(&ours),
        1,
        "deduplicated GOT symbol must require exactly one runtime relocation"
    );

    let gnu = dir.join("gnu-pie");
    let gnu_link = Command::new("ld")
        .args(["-pie", "--no-dynamic-linker", "--no-relax", "-o"])
        .arg(&gnu)
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        gnu_link.status.success(),
        "{}",
        String::from_utf8_lossy(&gnu_link.stderr)
    );
    assert!(
        dynamic_relative_count(&gnu) >= 1,
        "GNU reference should runtime-relocate its GOT entry"
    );

    #[cfg(target_os = "linux")]
    {
        let status = Command::new(&ours).status().unwrap();
        assert!(status.success(), "{} returned {status}", ours.display());
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn pie_gotpcrel_absolute_symbol_keeps_fixed_got_value_without_dynamic_plane() {
    if !have_gnu_tools() {
        return;
    }

    let dir = temp_dir("absolute");
    let object = assemble(
        &dir,
        "absolute-got",
        r#".section .data
.align 8
.globl absolute_target
.type absolute_target,@object
absolute_target:
    .quad 0
.size absolute_target, .-absolute_target

.section .text
.globl _start
.type _start,@function
_start:
    mov absolute_target@GOTPCREL(%rip), %rax
    cmp $0x4321, %rax
    jne .Lfail
    mov $60, %rax
    xor %rdi, %rdi
    syscall
.Lfail:
    mov $60, %rax
    mov $1, %rdi
    syscall
.size _start, .-_start
"#,
    );

    rewrite_symbol_as_absolute(&object, b"absolute_target", 0x4321);

    let input_relocations = Command::new("readelf")
        .args(["-rW"])
        .arg(&object)
        .output()
        .unwrap();
    assert!(input_relocations.status.success());
    assert!(
        String::from_utf8_lossy(&input_relocations.stdout).contains("GOTPCREL"),
        "fixture must contain a GOTPCREL-family relocation"
    );

    let ours = dir.join("absolute-pie");
    let mini = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&ours)
        .arg("--pie")
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        mini.status.success(),
        "{}",
        String::from_utf8_lossy(&mini.stderr)
    );

    let headers = Command::new("readelf")
        .args(["-lW"])
        .arg(&ours)
        .output()
        .unwrap();
    assert!(headers.status.success());
    assert!(
        !String::from_utf8_lossy(&headers.stdout).contains("DYNAMIC"),
        "absolute-only GOT value needs no load-bias runtime relocation"
    );

    #[cfg(target_os = "linux")]
    {
        let status = Command::new(&ours).status().unwrap();
        assert!(status.success(), "{} returned {status}", ours.display());
    }

    let _ = fs::remove_dir_all(dir);
}
