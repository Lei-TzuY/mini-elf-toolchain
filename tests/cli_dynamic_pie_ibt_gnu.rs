use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const PT_LOAD: u32 = 1;
const ENDBR64: [u8; 4] = [0xf3, 0x0f, 0x1e, 0xfa];

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
        "mini-elf-toolchain-dynamic-pie-ibt-{label}-{}-{nonce}",
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

fn build_provider(dir: &Path) -> PathBuf {
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
    sub $8, %rsp
    call provider_func@PLT
    add $8, %rsp
    cmp $7, %eax
    jne .Lfail
    mov $60, %eax
    xor %edi, %edi
    syscall
.Lfail:
    mov $60, %eax
    mov $41, %edi
    syscall
.size _start, .-_start

.section .note.GNU-stack,"",@progbits
"#
}

fn link_mini(
    dir: &Path,
    stem: &str,
    mode: &str,
    object: &Path,
    provider: &Path,
    interpreter: &Path,
) -> PathBuf {
    let output = dir.join(stem);
    let linked = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&output)
        .arg("--dynamic-pie")
        .arg("--dynamic-linker")
        .arg(interpreter)
        .args(["-z", mode])
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

fn link_gnu(dir: &Path, stem: &str, mode: &str, object: &Path, interpreter: &Path) -> PathBuf {
    let output = dir.join(stem);
    let linked = Command::new("ld")
        .arg("-pie")
        .arg("--dynamic-linker")
        .arg(interpreter)
        .args(["--no-relax", "-z", mode, "-rpath", "$ORIGIN", "-o"])
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

fn vaddr_to_file_offset(bytes: &[u8], address: u64) -> usize {
    let phoff = read_u64(bytes, 32) as usize;
    let phentsize = read_u16(bytes, 54) as usize;
    let phnum = read_u16(bytes, 56) as usize;

    for index in 0..phnum {
        let ph = phoff + index * phentsize;
        if read_u32(bytes, ph) != PT_LOAD {
            continue;
        }
        let offset = read_u64(bytes, ph + 8);
        let vaddr = read_u64(bytes, ph + 16);
        let filesz = read_u64(bytes, ph + 32);
        let Some(end) = vaddr.checked_add(filesz) else {
            continue;
        };
        if address >= vaddr && address < end {
            return usize::try_from(offset + (address - vaddr)).unwrap();
        }
    }
    panic!("virtual address {address:#x} is not file-backed by PT_LOAD");
}

fn assert_ibt_plt(path: &Path) {
    let bytes = fs::read(path).unwrap();
    let entry = read_u64(&bytes, 24);
    let entry_offset = vaddr_to_file_offset(&bytes, entry);
    let body = &bytes[entry_offset..entry_offset + 32];
    let call_offset = body
        .iter()
        .position(|byte| *byte == 0xe8)
        .expect("_start should contain a direct CALL rel32");
    let displacement =
        i32::from_le_bytes(body[call_offset + 1..call_offset + 5].try_into().unwrap());
    let call_next = entry + u64::try_from(call_offset + 5).unwrap();
    let plt_address = u64::try_from(i128::from(call_next) + i128::from(displacement)).unwrap();
    let plt_offset = vaddr_to_file_offset(&bytes, plt_address);
    let plt = &bytes[plt_offset..plt_offset + 16];

    assert_eq!(&plt[..4], &ENDBR64, "public PLT entry must begin ENDBR64");
    assert_eq!(&plt[4..6], &[0xff, 0x25], "IBT PLT must jump through GOT");

    let got_disp = i32::from_le_bytes(plt[6..10].try_into().unwrap());
    let got_address = u64::try_from(i128::from(plt_address + 10) + i128::from(got_disp)).unwrap();
    let got_offset = vaddr_to_file_offset(&bytes, got_address);
    let lazy_address = read_u64(&bytes, got_offset);
    let lazy_offset = vaddr_to_file_offset(&bytes, lazy_address);
    let lazy = &bytes[lazy_offset..lazy_offset + 16];

    assert_eq!(
        &lazy[..4],
        &ENDBR64,
        "initial lazy GOT target must begin ENDBR64"
    );
    assert_eq!(lazy[4], 0x68, "lazy landing must push relocation index");
    assert_eq!(lazy[9], 0xe9, "lazy landing must jump directly to PLT0");
}

fn inspect_property(path: &Path) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-gnu-property"))
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

fn assert_runs(path: &Path) {
    #[cfg(target_os = "linux")]
    {
        let status = Command::new(path)
            .env_remove("LD_BIND_NOW")
            .status()
            .unwrap();
        assert!(
            status.success(),
            "dynamic PIE IBT runtime returned {status} for {}",
            path.display()
        );
    }
}

#[test]
fn dynamic_pie_ibtplt_matches_gnu_without_claiming_ibt_property() {
    if !have_tools() {
        return;
    }
    let Some(interpreter) = dynamic_linker() else {
        return;
    };

    let dir = temp_dir("ibtplt");
    let provider = build_provider(&dir);
    let object = assemble(&dir, "consumer", consumer_source());

    let mini = link_mini(
        &dir,
        "mini-ibtplt",
        "ibtplt",
        &object,
        &provider,
        &interpreter,
    );
    let gnu = link_gnu(&dir, "gnu-ibtplt", "ibtplt", &object, &interpreter);

    assert_ibt_plt(&mini);
    assert_ibt_plt(&gnu);
    assert_eq!(
        inspect_property(&mini),
        "No PT_GNU_PROPERTY segments found.\n"
    );
    assert_eq!(
        inspect_property(&gnu),
        "No PT_GNU_PROPERTY segments found.\n"
    );

    assert_runs(&mini);
    assert_runs(&gnu);

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn dynamic_pie_z_ibt_emits_property_and_executes_ibt_safe_plt() {
    if !have_tools() {
        return;
    }
    let Some(interpreter) = dynamic_linker() else {
        return;
    };

    let dir = temp_dir("property");
    let provider = build_provider(&dir);
    let object = assemble(&dir, "consumer", consumer_source());

    let mini = link_mini(&dir, "mini-ibt", "ibt", &object, &provider, &interpreter);
    let gnu = link_gnu(&dir, "gnu-ibt", "ibt", &object, &interpreter);

    for pie in [&mini, &gnu] {
        assert_ibt_plt(pie);
        let property = inspect_property(pie);
        assert!(
            property.contains("x86 feature_1_and=0x1 IBT"),
            "{}: {property}",
            pie.display()
        );

        let headers = Command::new("readelf")
            .args(["-lW"])
            .arg(pie)
            .output()
            .unwrap();
        assert!(headers.status.success());
        let headers = String::from_utf8_lossy(&headers.stdout);
        assert!(headers.contains("INTERP"), "{headers}");
        assert!(headers.contains("GNU_PROPERTY"), "{headers}");

        assert_runs(pie);
    }

    let _ = fs::remove_dir_all(dir);
}
