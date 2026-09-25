use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const PT_GNU_RELRO: u32 = 0x6474_e552;

fn command_reports(program: &str, marker: &str) -> bool {
    let Ok(output) = Command::new(program).arg("--version").output() else {
        return false;
    };
    output.status.success()
        && (String::from_utf8_lossy(&output.stdout).contains(marker)
            || String::from_utf8_lossy(&output.stderr).contains(marker))
}

fn have_tools() -> bool {
    command_reports("as", "GNU assembler")
        && command_reports("ld", "GNU ld")
        && command_reports("readelf", "GNU readelf")
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
        "mini-elf-toolchain-dynamic-pie-bind-now-{label}-{}-{nonce}",
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

fn provider(dir: &Path) -> PathBuf {
    let object = assemble(
        dir,
        "provider",
        r#".text
.globl provider_func
.type provider_func,@function
provider_func:
    mov $7, %eax
    ret
.size provider_func, .-provider_func

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

fn consumer_source() -> &'static str {
    r#".text
.globl provider_func
.type provider_func,@function

.globl _start
.type _start,@function
_start:
    # Decode the ordinary x86-64 PLT entry before the first call. A lazy
    # JUMP_SLOT still points at PLT+6; -z now must have replaced it already.
    lea provider_func@PLT(%rip), %r12
    cmpw $0x25ff, (%r12)
    jne .Lbad_plt
    movslq 2(%r12), %rax
    lea 6(%r12,%rax), %r13
    mov (%r13), %r14
    lea 6(%r12), %r15
    cmp %r15, %r14
    je .Lnot_eager

    call provider_func@PLT
    cmp $7, %eax
    jne .Lcall_fail

    # Full RELRO must make the eagerly-resolved GOTPLT slot read-only.
    movq $0, (%r13)

    mov $60, %eax
    mov $99, %edi
    syscall

.Lnot_eager:
    mov $60, %eax
    mov $88, %edi
    syscall

.Lbad_plt:
    mov $60, %eax
    mov $89, %edi
    syscall

.Lcall_fail:
    mov $60, %eax
    mov $77, %edi
    syscall
.size _start, .-_start

.section .note.GNU-stack,"",@progbits
"#
}

fn link_mini(
    dir: &Path,
    object: &Path,
    provider: &Path,
    interpreter: &Path,
) -> PathBuf {
    let output = dir.join("mini-pie");
    let linked = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&output)
        .arg("--dynamic-pie")
        .arg("--dynamic-linker")
        .arg(interpreter)
        .args(["-z", "now"])
        .arg("--needed-from")
        .arg(provider)
        .arg("--runpath")
        .arg("$ORIGIN")
        .arg(object)
        .output()
        .unwrap();
    assert!(
        linked.status.success(),
        "{}",
        String::from_utf8_lossy(&linked.stderr)
    );
    output
}

fn link_gnu(dir: &Path, object: &Path, interpreter: &Path) -> PathBuf {
    let output = dir.join("gnu-pie");
    let linked = Command::new("ld")
        .arg("-pie")
        .arg("--dynamic-linker")
        .arg(interpreter)
        .args(["-z", "relro", "-z", "now", "-rpath", "$ORIGIN", "-o"])
        .arg(&output)
        .arg(object)
        .arg("-L")
        .arg(dir)
        .arg("-lprovider")
        .output()
        .unwrap();
    assert!(
        linked.status.success(),
        "{}",
        String::from_utf8_lossy(&linked.stderr)
    );
    output
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

fn gnu_relro_contains(path: &Path, address: u64) -> bool {
    let bytes = fs::read(path).unwrap();
    let phoff = read_u64(&bytes, 32) as usize;
    let phentsize = read_u16(&bytes, 54) as usize;
    let phnum = read_u16(&bytes, 56) as usize;

    (0..phnum).any(|index| {
        let ph = phoff + index * phentsize;
        if read_u32(&bytes, ph) != PT_GNU_RELRO {
            return false;
        }
        let start = read_u64(&bytes, ph + 16);
        let size = read_u64(&bytes, ph + 40);
        start
            .checked_add(size)
            .is_some_and(|end| address >= start && address < end)
    })
}

fn jump_slot_offset(path: &Path, symbol: &str) -> u64 {
    let output = Command::new("readelf")
        .args(["-rW", "--use-dynamic"])
        .arg(path)
        .output()
        .unwrap();
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);
    text.lines()
        .find(|line| line.contains("R_X86_64_JUMP_SLOT") && line.contains(symbol))
        .and_then(|line| line.split_whitespace().next())
        .and_then(|value| u64::from_str_radix(value, 16).ok())
        .unwrap_or_else(|| panic!("missing JUMP_SLOT for {symbol}: {text}"))
}

fn assert_bind_now_metadata(path: &Path) {
    let dynamic = Command::new("readelf")
        .args(["-dW"])
        .arg(path)
        .output()
        .unwrap();
    assert!(dynamic.status.success());
    let dynamic = String::from_utf8_lossy(&dynamic.stdout);
    assert!(
        dynamic.contains("BIND_NOW")
            || dynamic
                .lines()
                .any(|line| line.contains("FLAGS_1") && line.contains(" NOW ")),
        "missing eager-binding policy: {dynamic}"
    );

    let headers = Command::new("readelf")
        .args(["-lW"])
        .arg(path)
        .output()
        .unwrap();
    assert!(headers.status.success());
    assert!(
        String::from_utf8_lossy(&headers.stdout).contains("GNU_RELRO"),
        "{}",
        String::from_utf8_lossy(&headers.stdout)
    );

    let slot = jump_slot_offset(path, "provider_func");
    assert!(
        gnu_relro_contains(path, slot),
        "{} JUMP_SLOT at {slot:#x} must be covered by PT_GNU_RELRO",
        path.display()
    );
}

#[test]
fn dynamic_pie_z_now_eagerly_binds_and_relro_protects_jump_slot() {
    if !have_tools() {
        return;
    }
    let Some(interpreter) = dynamic_linker() else {
        return;
    };

    let dir = temp_dir("runtime");
    let provider = provider(&dir);
    let object = assemble(&dir, "consumer", consumer_source());

    let mini = link_mini(&dir, &object, &provider, &interpreter);
    let gnu = link_gnu(&dir, &object, &interpreter);

    for pie in [&mini, &gnu] {
        assert_bind_now_metadata(pie);
    }

    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::ExitStatusExt;

        for pie in [&mini, &gnu] {
            let status = Command::new(pie)
                .env_remove("LD_BIND_NOW")
                .status()
                .unwrap();
            assert_eq!(
                status.signal(),
                Some(11),
                "{} must eagerly resolve the JUMP_SLOT before the first call and then fault when user code writes the full-RELRO GOTPLT slot; status={status}",
                pie.display()
            );
        }
    }

    let _ = fs::remove_dir_all(dir);
}
