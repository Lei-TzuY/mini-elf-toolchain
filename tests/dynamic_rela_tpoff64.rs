use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PF_X: u32 = 1;
const DT_NULL: i64 = 0;
const DT_HASH: i64 = 4;
const DT_RELA: i64 = 7;
const R_X86_64_TPOFF64: u32 = 18;

fn temp(label: &str) -> PathBuf {
    let n = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let p = std::env::temp_dir().join(format!("mini-elf-toolchain-{label}-{}-{n}", std::process::id()));
    fs::create_dir_all(&p).unwrap();
    p
}

fn fixture(dir: &Path) -> PathBuf {
    let s = dir.join("f.s");
    let o = dir.join("f.o");
    let so = dir.join("f.so");
    fs::write(
        &s,
        ".section .tdata,\"awT\",@progbits\n.globl tlsvar\n.type tlsvar,@tls_object\n.size tlsvar,8\ntlsvar:\n.quad 0\n.text\n.globl probe\n.type probe,@function\nprobe:\nmovq tlsvar@gottpoff(%rip), %rax\nret\n",
    )
    .unwrap();
    assert!(Command::new("as").args(["-o", o.to_str().unwrap(), s.to_str().unwrap()]).status().unwrap().success());
    assert!(Command::new("ld")
        .args(["-shared", "--hash-style=sysv", "-o", so.to_str().unwrap(), o.to_str().unwrap()])
        .status().unwrap().success());
    so
}

fn run(paths: &[&Path], bias: &str, tls_offset: &str) -> Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_mini-elf-dynrela-tpoff64"));
    c.arg("--load-bias").arg(bias).arg("--tls-block-offset").arg(tls_offset);
    for p in paths { c.arg(p); }
    c.output().unwrap()
}

fn u16at(b: &[u8], o: usize) -> u16 { u16::from_le_bytes(b[o..o + 2].try_into().unwrap()) }
fn u32at(b: &[u8], o: usize) -> u32 { u32::from_le_bytes(b[o..o + 4].try_into().unwrap()) }
fn u64at(b: &[u8], o: usize) -> u64 { u64::from_le_bytes(b[o..o + 8].try_into().unwrap()) }
fn i64at(b: &[u8], o: usize) -> i64 { i64::from_le_bytes(b[o..o + 8].try_into().unwrap()) }

fn ph(b: &[u8]) -> Vec<(u32, u32, u64, u64, u64, u64)> {
    let p = u64at(b, 32) as usize;
    let e = u16at(b, 54) as usize;
    let n = u16at(b, 56) as usize;
    (0..n).map(|i| {
        let x = p + i * e;
        (u32at(b, x), u32at(b, x + 4), u64at(b, x + 8), u64at(b, x + 16), u64at(b, x + 32), u64at(b, x + 40))
    }).collect()
}

fn map(b: &[u8], a: u64) -> usize {
    for (k, _, o, v, f, _) in ph(b) {
        if k == PT_LOAD && a >= v && a < v + f { return (o + a - v) as usize; }
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
        if t == want { return v; }
        if t == DT_NULL { break; }
        c += 16;
    }
    panic!("missing tag")
}

fn rela(b: &[u8]) -> usize {
    let mut c = map(b, tag(b, DT_RELA));
    loop {
        if u64at(b, c + 8) as u32 == R_X86_64_TPOFF64 { return c; }
        c += 24;
    }
}

fn count(b: &[u8]) -> u64 { u32at(b, map(b, tag(b, DT_HASH)) + 4) as u64 }
fn exec_addr(b: &[u8]) -> u64 {
    ph(b).into_iter().find(|x| x.0 == PT_LOAD && x.1 & PF_X != 0 && x.4 > 0).unwrap().3
}

#[test]
fn validates_gnu_tpoff64() {
    let d = temp("tpoff-good");
    let so = fixture(&d);
    let g = Command::new("readelf").args(["-rW", so.to_str().unwrap()]).output().unwrap();
    assert!(g.status.success());
    let gt = String::from_utf8_lossy(&g.stdout);
    assert!(gt.contains("R_X86_64_TPOFF64"), "{gt}");
    let o = run(&[&so], "0x70000000", "-0x1000");
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let s = String::from_utf8_lossy(&o.stdout);
    assert!(s.contains("Validated R_X86_64_TPOFF64"));
    assert!(s.contains("result-tpoff="));
    fs::remove_dir_all(d).unwrap();
}

#[test]
fn rejects_bad_symbol_index() {
    let d = temp("tpoff-index");
    let so = fixture(&d);
    let mut b = fs::read(&so).unwrap();
    let r = rela(&b);
    let n = count(&b);
    b[r + 8..r + 16].copy_from_slice(&((n << 32) | R_X86_64_TPOFF64 as u64).to_le_bytes());
    let bad = d.join("bad.so"); fs::write(&bad, b).unwrap();
    let o = run(&[&bad], "0", "-4096");
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("invalid dynamic symbol index"));
    fs::remove_dir_all(d).unwrap();
}

#[test]
fn rejects_nonwritable_target() {
    let d = temp("tpoff-target");
    let so = fixture(&d);
    let mut b = fs::read(&so).unwrap();
    let r = rela(&b);
    let a = exec_addr(&b);
    b[r..r + 8].copy_from_slice(&a.to_le_bytes());
    let bad = d.join("bad.so"); fs::write(&bad, b).unwrap();
    let o = run(&[&bad], "0", "-4096");
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("target"));
    fs::remove_dir_all(d).unwrap();
}

#[test]
fn rejects_signed_result_overflow() {
    let d = temp("tpoff-overflow");
    let so = fixture(&d);
    let mut b = fs::read(&so).unwrap();
    let r = rela(&b);
    let info = u64at(&b, r + 8);
    let si = (info >> 32) as usize;
    let symtab = tag(&b, 6);
    let s = map(&b, symtab) + si * 24;
    b[s + 8..s + 16].copy_from_slice(&u64::MAX.to_le_bytes());
    let bad = d.join("bad.so"); fs::write(&bad, b).unwrap();
    let o = run(&[&bad], "0", "9223372036854775807");
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("does not fit signed 64-bit"));
    fs::remove_dir_all(d).unwrap();
}

#[test]
fn rejects_runtime_target_overflow() {
    let d = temp("tpoff-runtime-overflow");
    let so = fixture(&d);
    let o = run(&[&so], "0xffffffffffffffff", "-4096");
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("runtime target overflows u64"));
    fs::remove_dir_all(d).unwrap();
}

#[test]
fn malformed_later_input_keeps_stdout_atomic() {
    let d = temp("tpoff-atomic");
    let so = fixture(&d);
    let bad = d.join("bad.so");
    fs::write(&bad, b"not an elf").unwrap();
    let o = run(&[&so, &bad], "0", "-4096");
    assert!(!o.status.success());
    assert!(o.stdout.is_empty(), "stdout was {}", String::from_utf8_lossy(&o.stdout));
    fs::remove_dir_all(d).unwrap();
}
