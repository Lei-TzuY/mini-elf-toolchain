use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PF_X: u32 = 1;
const DT_NULL: i64 = 0;
const DT_HASH: i64 = 4;
const DT_SYMTAB: i64 = 6;
const DT_RELA: i64 = 7;
const R_X86_64_SIZE64: u32 = 33;

fn temp(label: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "mini-elf-size64-{label}-{}-{stamp}",
        std::process::id()
    ));
    fs::create_dir_all(&path).unwrap();
    path
}

fn fixture(dir: &Path) -> PathBuf {
    let source = dir.join("fixture.s");
    let object = dir.join("fixture.o");
    let image = dir.join("fixture.so");
    fs::write(
        &source,
        ".text\n.globl dummy\ndummy:\nret\n.data\n.globl slot\nslot:\n.quad external@SIZE\n",
    )
    .unwrap();
    assert!(Command::new("as")
        .args(["--64", "-o", object.to_str().unwrap(), source.to_str().unwrap()])
        .status()
        .unwrap()
        .success());
    assert!(Command::new("ld")
        .args([
            "-shared",
            "--hash-style=sysv",
            "-o",
            image.to_str().unwrap(),
            object.to_str().unwrap(),
        ])
        .status()
        .unwrap()
        .success());
    image
}

fn run(inputs: &[&Path]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_mini-elf-dynrela-size64"));
    for input in inputs {
        command.arg(input);
    }
    command.output().unwrap()
}
fn u16at(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes(b[o..o + 2].try_into().unwrap())
}
fn u32at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
fn u64at(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}
fn i64at(b: &[u8], o: usize) -> i64 {
    i64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}
fn phdrs(b: &[u8]) -> Vec<(u32, u32, u64, u64, u64, u64)> {
    let o = u64at(b, 32) as usize;
    let s = usize::from(u16at(b, 54));
    let n = usize::from(u16at(b, 56));
    (0..n)
        .map(|i| {
            let p = o + i * s;
            (
                u32at(b, p),
                u32at(b, p + 4),
                u64at(b, p + 8),
                u64at(b, p + 16),
                u64at(b, p + 32),
                u64at(b, p + 40),
            )
        })
        .collect()
}
fn map_vaddr(b: &[u8], a: u64) -> usize {
    for h in phdrs(b) {
        if h.0 == PT_LOAD && a >= h.3 && a < h.3 + h.4 {
            return (h.2 + a - h.3) as usize;
        }
    }
    panic!("address not file-backed")
}
fn dynamic_tag(b: &[u8], wanted: i64) -> u64 {
    let h = phdrs(b).into_iter().find(|h| h.0 == PT_DYNAMIC).unwrap();
    let (mut o, end) = (h.2 as usize, (h.2 + h.4) as usize);
    while o + 16 <= end {
        let t = i64at(b, o);
        let v = u64at(b, o + 8);
        if t == wanted {
            return v;
        }
        if t == DT_NULL {
            break;
        }
        o += 16;
    }
    panic!("missing dynamic tag")
}
fn rela_offset(b: &[u8]) -> usize {
    let mut o = map_vaddr(b, dynamic_tag(b, DT_RELA));
    loop {
        if u64at(b, o + 8) as u32 == R_X86_64_SIZE64 {
            return o;
        }
        o += 24;
    }
}
fn symbol_count(b: &[u8]) -> u64 {
    let h = map_vaddr(b, dynamic_tag(b, DT_HASH));
    u64::from(u32at(b, h + 4))
}
fn executable_address(b: &[u8]) -> u64 {
    phdrs(b)
        .into_iter()
        .find(|h| h.0 == PT_LOAD && h.1 & PF_X != 0 && h.4 >= 8)
        .map(|h| h.3)
        .unwrap_or_else(|| {
            phdrs(b)
                .into_iter()
                .find(|h| h.0 == PT_LOAD && h.1 & PF_X != 0)
                .unwrap()
                .3
        })
}
fn make_same_image(b: &mut [u8], r: usize, size: u64, addend: i64) {
    let info = u64at(b, r + 8);
    let si = info >> 32;
    let st = map_vaddr(b, dynamic_tag(b, DT_SYMTAB));
    let s = st + usize::try_from(si).unwrap() * 24;
    b[s + 6..s + 8].copy_from_slice(&1u16.to_le_bytes());
    b[s + 16..s + 24].copy_from_slice(&size.to_le_bytes());
    b[r + 16..r + 24].copy_from_slice(&addend.to_le_bytes());
}

#[test]
fn validates_gnu_size64_external_relocation() {
    let d = temp("good");
    let image = fixture(&d);
    let re = Command::new("readelf")
        .args(["-rW", image.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(re.status.success());
    assert!(String::from_utf8_lossy(&re.stdout).contains("R_X86_64_SIZE64"));
    let o = run(&[&image]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert!(String::from_utf8_lossy(&o.stdout).contains("binding=external"));
    fs::remove_dir_all(d).unwrap();
}

#[test]
fn validates_same_image_symbol_size_with_negative_addend() {
    let d = temp("same-image");
    let image = fixture(&d);
    let mut b = fs::read(&image).unwrap();
    let r = rela_offset(&b);
    make_same_image(&mut b, r, 7, -2);
    let p = d.join("same.so");
    fs::write(&p, b).unwrap();
    let o = run(&[&p]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert!(String::from_utf8_lossy(&o.stdout).contains("size=7 addend=-2 result=5"));
    fs::remove_dir_all(d).unwrap();
}

#[test]
fn rejects_invalid_symbol_index() {
    let d = temp("index");
    let image = fixture(&d);
    let mut b = fs::read(&image).unwrap();
    let r = rela_offset(&b);
    let n = symbol_count(&b);
    b[r + 8..r + 16]
        .copy_from_slice(&((n << 32) | u64::from(R_X86_64_SIZE64)).to_le_bytes());
    let p = d.join("bad.so");
    fs::write(&p, b).unwrap();
    let o = run(&[&p]);
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("invalid symbol index"));
    fs::remove_dir_all(d).unwrap();
}

#[test]
fn rejects_nonwritable_target() {
    let d = temp("target");
    let image = fixture(&d);
    let mut b = fs::read(&image).unwrap();
    let r = rela_offset(&b);
    let a = executable_address(&b);
    b[r..r + 8].copy_from_slice(&a.to_le_bytes());
    let p = d.join("bad.so");
    fs::write(&p, b).unwrap();
    let o = run(&[&p]);
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("SIZE64 target"));
    fs::remove_dir_all(d).unwrap();
}

#[test]
fn rejects_size_plus_addend_outside_unsigned_64_bits() {
    let d = temp("overflow");
    let image = fixture(&d);
    let mut b = fs::read(&image).unwrap();
    let r = rela_offset(&b);
    make_same_image(&mut b, r, u64::MAX, 1);
    let p = d.join("overflow.so");
    fs::write(&p, b).unwrap();
    let o = run(&[&p]);
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("does not fit u64"));
    fs::remove_dir_all(d).unwrap();
}

#[test]
fn rejects_negative_size_result() {
    let d = temp("underflow");
    let image = fixture(&d);
    let mut b = fs::read(&image).unwrap();
    let r = rela_offset(&b);
    make_same_image(&mut b, r, 0, -1);
    let p = d.join("underflow.so");
    fs::write(&p, b).unwrap();
    let o = run(&[&p]);
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("does not fit u64"));
    fs::remove_dir_all(d).unwrap();
}

#[test]
fn malformed_later_input_keeps_stdout_atomic() {
    let d = temp("atomic");
    let good = fixture(&d);
    let mut b = fs::read(&good).unwrap();
    let r = rela_offset(&b);
    let n = symbol_count(&b);
    b[r + 8..r + 16]
        .copy_from_slice(&((n << 32) | u64::from(R_X86_64_SIZE64)).to_le_bytes());
    let bad = d.join("bad.so");
    fs::write(&bad, b).unwrap();
    let o = run(&[&good, &bad]);
    assert!(!o.status.success());
    assert!(o.stdout.is_empty());
    fs::remove_dir_all(d).unwrap();
}
