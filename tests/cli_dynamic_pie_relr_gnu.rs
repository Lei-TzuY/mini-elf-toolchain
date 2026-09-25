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

fn gnu_ld_supports_pack_relative_relocs() -> bool {
    Command::new("ld")
        .arg("--help")
        .output()
        .is_ok_and(|output| {
            output.status.success()
                && String::from_utf8_lossy(&output.stdout).contains("pack-relative-relocs")
        })
}

fn dynamic_linker() -> Option<PathBuf> {
    [
        PathBuf::from("/lib64/ld-linux-x86-64.so.2"),
        PathBuf::from("/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"),
    ]
    .into_iter()
    .find(|path| path.is_file())
}

fn temp_dir(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after Unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "mini-elf-toolchain-dynamic-pie-relr-{label}-{}-{nonce}",
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

fn readelf(path: &Path, args: &[&str]) -> String {
    let output = Command::new("readelf")
        .args(args)
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

fn build_provider(dir: &Path) -> PathBuf {
    let object = assemble(
        dir,
        "provider",
        r#".data
.globl provider_data
.type provider_data,@object
.size provider_data,8
provider_data:
    .quad 77

.section .note.GNU-stack,"",@progbits
"#,
    );
    let provider = dir.join("libprovider.so");
    let linked = Command::new("ld")
        .args(["-shared", "-soname", "libprovider.so", "-o"])
        .arg(&provider)
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        linked.status.success(),
        "{}",
        String::from_utf8_lossy(&linked.stderr)
    );
    provider
}

fn build_consumer(dir: &Path) -> PathBuf {
    assemble(
        dir,
        "consumer",
        r#".data
.align 8
.type local_value,@object
local_value:
    .quad 0x1122334455667788
.size local_value,8

.align 8
.type local_ptr0,@object
local_ptr0:
    .quad local_value
.type local_ptr1,@object
local_ptr1:
    .quad local_value
.type local_ptr2,@object
local_ptr2:
    .quad local_value

.globl provider_data
.type provider_data,@object

.text
.globl _start
.type _start,@function
_start:
    lea local_value(%rip), %rbx

    mov local_ptr0(%rip), %rax
    cmp %rbx, %rax
    jne .Lrelative_fail
    mov local_ptr1(%rip), %rax
    cmp %rbx, %rax
    jne .Lrelative_fail
    mov local_ptr2(%rip), %rax
    cmp %rbx, %rax
    jne .Lrelative_fail

    mov provider_data@GOTPCREL(%rip), %rax
    mov (%rax), %rax
    cmp $77, %rax
    jne .Lprovider_fail

    mov $60, %eax
    xor %edi, %edi
    syscall

.Lrelative_fail:
    mov $60, %eax
    mov $41, %edi
    syscall

.Lprovider_fail:
    mov $60, %eax
    mov $42, %edi
    syscall
.size _start, .-_start

.section .note.GNU-stack,"",@progbits
"#,
    )
}

fn link_mini(output: &Path, interpreter: &Path, provider: &Path, consumer: &Path, packed: bool) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"));
    command
        .args(["link", "-o"])
        .arg(output)
        .arg("--dynamic-pie")
        .arg("--dynamic-linker")
        .arg(interpreter)
        .arg("--needed-from")
        .arg(provider)
        .arg("--runpath")
        .arg("$ORIGIN");
    if packed {
        command.args(["-z", "pack-relative-relocs"]);
    }
    let linked = command.arg(consumer).output().unwrap();
    assert!(
        linked.status.success(),
        "{}",
        String::from_utf8_lossy(&linked.stderr)
    );
}

#[test]
#[cfg(target_os = "linux")]
fn dynamic_pie_pack_relative_relocs_splits_relr_from_remaining_rela_and_executes() {
    if !have_gnu_tools() {
        return;
    }
    let Some(interpreter) = dynamic_linker() else {
        return;
    };

    let dir = temp_dir("packed");
    let provider = build_provider(&dir);
    let consumer = build_consumer(&dir);
    let ours = dir.join("mini-packed");
    link_mini(&ours, &interpreter, &provider, &consumer, true);

    let dynamic = readelf(&ours, &["-dW"]);
    for tag in ["RELR", "RELRSZ", "RELRENT", "RELA", "RELASZ", "RELAENT"] {
        assert!(dynamic.contains(tag), "missing {tag}:\n{dynamic}");
    }
    assert!(
        !dynamic.contains("RELACOUNT"),
        "packed RELATIVE relocations must not remain in the RELA prefix:\n{dynamic}"
    );

    let relr = Command::new(env!("CARGO_BIN_EXE_mini-elf-dynrelr"))
        .arg(&ours)
        .output()
        .unwrap();
    assert!(
        relr.status.success(),
        "{}",
        String::from_utf8_lossy(&relr.stderr)
    );
    let relr = String::from_utf8_lossy(&relr.stdout);
    assert!(
        relr.contains("DT_RELR contains 2 encoded entries, 3 relocations"),
        "three contiguous pointer fixups should use one direct entry plus one bitmap:\n{relr}"
    );

    let rela = Command::new(env!("CARGO_BIN_EXE_mini-elf-dynrela"))
        .arg(&ours)
        .output()
        .unwrap();
    assert!(
        rela.status.success(),
        "{}",
        String::from_utf8_lossy(&rela.stderr)
    );
    let rela = String::from_utf8_lossy(&rela.stdout);
    assert!(rela.contains("R_X86_64_GLOB_DAT"), "{rela}");
    assert!(rela.contains("provider_data"), "{rela}");
    assert!(
        !rela.contains("R_X86_64_RELATIVE"),
        "packed relatives must not be duplicated in DT_RELA:\n{rela}"
    );

    let status = Command::new(&ours).status().unwrap();
    assert_eq!(
        status.code(),
        Some(0),
        "{} must execute with both RELR internal pointers and RELA provider binding; status={status}",
        ours.display()
    );

    assert!(
        gnu_ld_supports_pack_relative_relocs(),
        "GNU ld fixture must support -z pack-relative-relocs"
    );
    let gnu = dir.join("gnu-packed");
    let linked = Command::new("ld")
        .arg("-pie")
        .arg("--dynamic-linker")
        .arg(&interpreter)
        .args(["-z", "pack-relative-relocs", "-rpath", "$ORIGIN", "-o"])
        .arg(&gnu)
        .arg(&consumer)
        .arg("-L")
        .arg(&dir)
        .arg("-lprovider")
        .output()
        .unwrap();
    assert!(
        linked.status.success(),
        "{}",
        String::from_utf8_lossy(&linked.stderr)
    );
    let gnu_dynamic = readelf(&gnu, &["-dW"]);
    assert!(gnu_dynamic.contains("RELR"), "{gnu_dynamic}");
    let status = Command::new(&gnu).status().unwrap();
    assert_eq!(status.code(), Some(0), "GNU reference status={status}");

    let _ = fs::remove_dir_all(dir);
}

#[test]
#[cfg(target_os = "linux")]
fn dynamic_pie_default_policy_remains_rela_only() {
    if !have_gnu_tools() {
        return;
    }
    let Some(interpreter) = dynamic_linker() else {
        return;
    };

    let dir = temp_dir("default");
    let provider = build_provider(&dir);
    let consumer = build_consumer(&dir);
    let ours = dir.join("mini-default");
    link_mini(&ours, &interpreter, &provider, &consumer, false);

    let dynamic = readelf(&ours, &["-dW"]);
    assert!(!dynamic.contains("(RELR)"), "{dynamic}");
    assert!(!dynamic.contains("(RELRSZ)"), "{dynamic}");
    assert!(!dynamic.contains("(RELRENT)"), "{dynamic}");
    assert!(dynamic.contains("RELACOUNT"), "{dynamic}");

    let rela = Command::new(env!("CARGO_BIN_EXE_mini-elf-dynrela"))
        .arg(&ours)
        .output()
        .unwrap();
    assert!(rela.status.success());
    let rela = String::from_utf8_lossy(&rela.stdout);
    assert!(rela.contains("R_X86_64_RELATIVE"), "{rela}");
    assert!(rela.contains("R_X86_64_GLOB_DAT"), "{rela}");

    let status = Command::new(&ours).status().unwrap();
    assert_eq!(status.code(), Some(0), "default RELA path status={status}");

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn pack_relative_relocs_rejects_unsupported_modes_and_duplicates_before_io() {
    let binary = env!("CARGO_BIN_EXE_mini-elf-toolchain");

    for mode in [None] {
        let output = PathBuf::from("/tmp/mini-elf-toolchain-relr-should-not-exist");
        let mut command = Command::new(binary);
        command.args(["link", "-o"]).arg(&output);
        if let Some(mode) = mode {
            command.arg(mode);
        }
        let result = command
            .args(["-z", "pack-relative-relocs", "definitely-missing-input.o"])
            .output()
            .unwrap();
        assert_eq!(result.status.code(), Some(2));
        assert!(result.stdout.is_empty());
        let stderr = String::from_utf8_lossy(&result.stderr);
        assert!(
            stderr.contains(
                "-z pack-relative-relocs is only supported with --pie, --shared or --dynamic-pie"
            ),
            "{stderr}"
        );
        assert!(!output.exists());
    }

    let duplicate = Command::new(binary)
        .args(["link", "-o", "unused-output", "--dynamic-pie"])
        .args(["--dynamic-linker", "/definitely/not/opened"])
        .args(["-z", "pack-relative-relocs", "-z", "pack-relative-relocs"])
        .arg("definitely-missing-input.o")
        .output()
        .unwrap();
    assert_eq!(duplicate.status.code(), Some(2));
    assert!(duplicate.stdout.is_empty());
    assert!(String::from_utf8_lossy(&duplicate.stderr)
        .contains("duplicate -z pack-relative-relocs option"));
}
