use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PF_X: u32 = 1;
const DT_NULL: i64 = 0;
const DT_HASH: i64 = 4;
const DT_SYMTAB: i64 = 6;
const DT_RELA: i64 = 7;
const R_X86_64_COPY: u32 = 5;
const ET_DYN: u16 = 3;

fn temp(label: &str) -> PathBuf {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let p = std::env::temp_dir().join(format!(
        "mini-elf-toolchain-{label}-{}-{n}",
        std::process::id()
    ));
    fs::create_dir_all(&p).unwrap();
    p
}

fn fixture(dir: &Path) -> PathBuf {
    let dep_s = dir.join("dep.s");
    let dep_o = dir.join("dep.o");
    let dep_so = dir.join("libdep.so");
    let main_s = dir.join("main.s");
    let main_o = dir.join("main.o");
    let exe = dir.join("copy-image");
    fs::write(&dep_s, ".data\n.globl target\n.type target,@object\n.size target,16\ntarget:\n.quad 0x1122334455667788\n.quad 0x99aabbccddeeff00\n").unwrap();
    fs::write(
        &main_s,
        ".text\n.globl _start\n.type _start,@function\n_start:\nmov target(%rip), %rax\nret\n",
    )
    .unwrap();
    assert!(Command::new("as")
        .args(["-o", dep_o.to_str().unwrap(), dep_s.to_str().unwrap()])
        .status()
        .unwrap()
        .success());
    assert!(Command::new("ld")
        .args([
            "-shared",
            "--hash-style=sysv",
            "-o",
            dep_so.to_str().unwrap(),
            dep_o.to_str().unwrap()
        ])
        .status()
        .unwrap()
        .success());
    assert!(Command::new("as")
        .args(["-o", main_o.to_str().unwrap(), main_s.to_str().unwrap()])
        .status()
        .unwrap()
        .success());
    assert!(Command::new("ld")
        .args([
            "--hash-style=sysv",
            "-dynamic-linker",
            "/lib64/ld-linux-x86-64.so.2",
            "-e",
            "_start",
            "-o",
            exe.to_str().unwrap(),
            main_o.to_str().unwrap(),
            dep_so.to_str().unwrap()
        ])
        .status()
        .unwrap()
        .success());
    let mut b = fs::read(&exe).unwrap();
    b[16..18].copy_from_slice(&ET_DYN.to_le_bytes());
    fs::write(&exe, b).unwrap();
    exe
}

fn run(paths: &[&Path], bias: &str) -> Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_mini-elf-dynrela-copy"));
    c.arg("--load-bias").arg(bias);
    for p in paths {
        c.arg(p);
    }
    c.output().unwrap()
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
fn ph(b: &[u8]) -> Vec<(u32, u32, u64, u64, u64, u64)> {
    let p = u64at(b, 32) as usize;
    let e = u16at(b, 54) as usize;
    let n = u16at(b, 56) as usize;
    (0..n)
        .map(|i| {
            let x = p + i * e;
            (
                u32at(b, x),
                u32at(b, x + 4),
                u64at(b, x + 8),
                u64at(b, x + 16),
                u64at(b, x + 32),
                u64at(b, x + 40),
            )
        })
        .collect()
}
fn map(b: &[u8], a: u64) -> usize {
    for (k, _, o, v, f, _) in ph(b) {
        if k == PT_LOAD && a >= v && a < v + f {
            return (o + a - v) as usize;
        }
    }
    panic!("unmapped")
}
fn tag(b: &[u8], want: i64) -> u64 {
    let d = ph(b).into_iter().find(|x| x.0 == PT_DYNAMIC).unwrap();
    let mut c = d.2 as usize;
    let end = (d.2 + d.4) as usize;
    while c + 16 <= end {
        let t = i64at(b, c);
        let v = u64at(b, c + 8);
        if t == want {
            return v;
        }
        if t == DT_NULL {
            break;
        }
        c += 16;
    }
    panic!("missing tag")
}
fn rela(b: &[u8]) -> usize {
    let mut c = map(b, tag(b, DT_RELA));
    loop {
        if u64at(b, c + 8) as u32 == R_X86_64_COPY {
            return c;
        }
        c += 24;
    }
}
fn count(b: &[u8]) -> u64 {
    u32at(b, map(b, tag(b, DT_HASH)) + 4) as u64
}
fn symoff(b: &[u8], si: u64) -> usize {
    map(b, tag(b, DT_SYMTAB)) + si as usize * 24
}
fn exec_addr(b: &[u8]) -> u64 {
    ph(b)
        .into_iter()
        .find(|x| x.0 == PT_LOAD && x.1 & PF_X != 0 && x.4 > 0)
        .unwrap()
        .3
}

#[test]
fn validates_gnu_copy_relocation() {
    let d = temp("copy-good");
    let image = fixture(&d);
    let g = Command::new("readelf")
        .args(["-rW", image.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(g.status.success());
    let gt = String::from_utf8_lossy(&g.stdout);
    assert!(gt.contains("R_X86_64_COPY"), "{gt}");
    let o = run(&[&image], "0x70000000");
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let s = String::from_utf8_lossy(&o.stdout);
    assert!(s.contains("Validated R_X86_64_COPY"));
    assert!(s.contains("size=16"));
    assert!(s.contains("source=external-definition-required"));
    fs::remove_dir_all(d).unwrap();
}

#[test]
fn rejects_bad_symbol_index() {
    let d = temp("copy-index");
    let image = fixture(&d);
    let mut b = fs::read(&image).unwrap();
    let r = rela(&b);
    let n = count(&b);
    b[r + 8..r + 16].copy_from_slice(&((n << 32) | R_X86_64_COPY as u64).to_le_bytes());
    let bad = d.join("bad");
    fs::write(&bad, b).unwrap();
    let o = run(&[&bad], "0");
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("invalid dynamic symbol index"));
    fs::remove_dir_all(d).unwrap();
}

#[test]
fn rejects_zero_size_destination() {
    let d = temp("copy-size");
    let image = fixture(&d);
    let mut b = fs::read(&image).unwrap();
    let r = rela(&b);
    let si = u64at(&b, r + 8) >> 32;
    let s = symoff(&b, si);
    b[s + 16..s + 24].copy_from_slice(&0u64.to_le_bytes());
    let bad = d.join("bad");
    fs::write(&bad, b).unwrap();
    let o = run(&[&bad], "0");
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("zero size"));
    fs::remove_dir_all(d).unwrap();
}

#[test]
fn rejects_nonwritable_target() {
    let d = temp("copy-target");
    let image = fixture(&d);
    let mut b = fs::read(&image).unwrap();
    let r = rela(&b);
    let si = u64at(&b, r + 8) >> 32;
    let s = symoff(&b, si);
    let a = exec_addr(&b);
    b[r..r + 8].copy_from_slice(&a.to_le_bytes());
    b[s + 8..s + 16].copy_from_slice(&a.to_le_bytes());
    let bad = d.join("bad");
    fs::write(&bad, b).unwrap();
    let o = run(&[&bad], "0");
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("writable PT_LOAD"));
    fs::remove_dir_all(d).unwrap();
}

#[test]
fn rejects_runtime_range_overflow() {
    let d = temp("copy-overflow");
    let image = fixture(&d);
    let o = run(&[&image], "0xffffffffffffffff");
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("runtime target overflows u64"));
    fs::remove_dir_all(d).unwrap();
}

#[test]
fn malformed_later_input_keeps_stdout_atomic() {
    let d = temp("copy-atomic");
    let image = fixture(&d);
    let bad = d.join("bad");
    fs::write(&bad, b"not an elf").unwrap();
    let o = run(&[&image, &bad], "0");
    assert!(!o.status.success());
    assert!(o.stdout.is_empty());
    fs::remove_dir_all(d).unwrap();
}
