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
const DT_RELA: i64 = 7;
const DT_GNU_HASH: i64 = 0x6fff_fef5;
const R_X86_64_PC32: u32 = 2;

fn temp(label: &str) -> PathBuf {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let p = std::env::temp_dir().join(format!("mini-elf-pc32-{label}-{}-{n}", std::process::id()));
    fs::create_dir_all(&p).unwrap();
    p
}
fn fixture(d: &Path) -> PathBuf {
    let s = d.join("f.s");
    let o = d.join("f.o");
    let so = d.join("f.so");
    fs::write(
        &s,
        ".text\n.globl dummy\ndummy:\nret\n.data\n.globl slot\nslot:\n.long external - .\n",
    )
    .unwrap();
    assert!(Command::new("as")
        .args(["-o", o.to_str().unwrap(), s.to_str().unwrap()])
        .status()
        .unwrap()
        .success());
    assert!(Command::new("ld")
        .args([
            "-shared",
            "--hash-style=sysv",
            "-o",
            so.to_str().unwrap(),
            o.to_str().unwrap()
        ])
        .status()
        .unwrap()
        .success());
    so
}

fn gnu_hash_fixture(d: &Path) -> PathBuf {
    let s = d.join("gnu.s");
    let o = d.join("gnu.o");
    let so = d.join("gnu.so");
    fs::write(
        &s,
        ".text\n.globl dummy\ndummy:\nret\n.data\n.globl slot\nslot:\n.long external - .\n",
    )
    .unwrap();
    assert!(Command::new("as")
        .args(["-o", o.to_str().unwrap(), s.to_str().unwrap()])
        .status()
        .unwrap()
        .success());
    assert!(Command::new("ld")
        .args([
            "-shared",
            "--hash-style=gnu",
            "-o",
            so.to_str().unwrap(),
            o.to_str().unwrap(),
        ])
        .status()
        .unwrap()
        .success());
    so
}

fn run(ps: &[&Path]) -> Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_mini-elf-dynrela-pc32"));
    for p in ps {
        c.arg(p);
    }
    c.output().unwrap()
}
fn u16a(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes(b[o..o + 2].try_into().unwrap())
}
fn u32a(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
fn u64a(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}
fn i64a(b: &[u8], o: usize) -> i64 {
    i64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}
fn ph(b: &[u8]) -> Vec<(u32, u32, u64, u64, u64, u64)> {
    let po = u64a(b, 32) as usize;
    let pe = usize::from(u16a(b, 54));
    let pn = usize::from(u16a(b, 56));
    (0..pn)
        .map(|i| {
            let o = po + i * pe;
            (
                u32a(b, o),
                u32a(b, o + 4),
                u64a(b, o + 8),
                u64a(b, o + 16),
                u64a(b, o + 32),
                u64a(b, o + 40),
            )
        })
        .collect()
}
fn map(b: &[u8], va: u64) -> usize {
    for h in ph(b) {
        if h.0 == PT_LOAD && va >= h.3 && va < h.3 + h.4 {
            return (h.2 + va - h.3) as usize;
        }
    }
    panic!("unmapped")
}
fn tag(b: &[u8], want: i64) -> u64 {
    let h = ph(b).into_iter().find(|h| h.0 == PT_DYNAMIC).unwrap();
    let mut o = h.2 as usize;
    let e = (h.2 + h.4) as usize;
    while o + 16 <= e {
        let t = i64a(b, o);
        let v = u64a(b, o + 8);
        if t == want {
            return v;
        }
        if t == DT_NULL {
            break;
        }
        o += 16
    }
    panic!("missing tag")
}
fn rela_off(b: &[u8]) -> usize {
    let mut o = map(b, tag(b, DT_RELA));
    loop {
        if u64a(b, o + 8) as u32 == R_X86_64_PC32 {
            return o;
        }
        o += 24
    }
}
fn sym_count(b: &[u8]) -> u64 {
    u64::from(u32a(b, map(b, tag(b, DT_HASH)) + 4))
}
fn exec_va(b: &[u8]) -> u64 {
    ph(b)
        .into_iter()
        .find(|h| h.0 == PT_LOAD && h.1 & PF_X != 0 && h.4 >= 1)
        .unwrap()
        .3
}

#[test]
fn validates_gnu_pc32() {
    let d = temp("good");
    let so = fixture(&d);
    let r = Command::new("readelf")
        .args(["-rW", so.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(r.status.success());
    assert!(String::from_utf8_lossy(&r.stdout).contains("R_X86_64_PC32"));
    let o = run(&[&so]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let s = String::from_utf8_lossy(&o.stdout);
    assert!(s.contains("symbol=1:external"), "{s}");
    assert!(s.contains("binding=external"), "{s}");
    fs::remove_dir_all(d).unwrap();
}

#[test]
fn validates_gnu_hash_only_pc32() {
    let d = temp("gnu-hash");
    let so = gnu_hash_fixture(&d);
    let dyns = Command::new("readelf")
        .args(["-dW", so.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(dyns.status.success());
    let dyntext = String::from_utf8_lossy(&dyns.stdout);
    assert!(dyntext.contains("(GNU_HASH)"), "{dyntext}");
    assert!(!dyntext.contains(" (HASH)"), "{dyntext}");
    let rels = Command::new("readelf")
        .args(["-rW", so.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(rels.status.success());
    assert!(String::from_utf8_lossy(&rels.stdout).contains("R_X86_64_PC32"));
    let out = run(&[&so]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("binding=external"));
    fs::remove_dir_all(d).unwrap();
}

#[test]
fn rejects_malformed_gnu_hash_bloom_count() {
    let d = temp("gnu-hash-bloom");
    let so = gnu_hash_fixture(&d);
    let mut b = fs::read(&so).unwrap();
    let hash = tag(&b, DT_GNU_HASH);
    let o = map(&b, hash);
    b[o + 8..o + 12].copy_from_slice(&0u32.to_le_bytes());
    let bad = d.join("bad.so");
    fs::write(&bad, b).unwrap();
    let out = run(&[&bad]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("bloom count"));
    fs::remove_dir_all(d).unwrap();
}

#[test]
fn rejects_bad_symbol_index() {
    let d = temp("index");
    let so = fixture(&d);
    let mut b = fs::read(&so).unwrap();
    let o = rela_off(&b);
    let n = sym_count(&b);
    b[o + 8..o + 16].copy_from_slice(&((n << 32) | u64::from(R_X86_64_PC32)).to_le_bytes());
    let bad = d.join("bad.so");
    fs::write(&bad, b).unwrap();
    let r = run(&[&bad]);
    assert!(!r.status.success());
    assert!(String::from_utf8_lossy(&r.stderr).contains("invalid symbol index"));
    fs::remove_dir_all(d).unwrap();
}
#[test]
fn rejects_nonwritable_target() {
    let d = temp("target");
    let so = fixture(&d);
    let mut b = fs::read(&so).unwrap();
    let o = rela_off(&b);
    let x = exec_va(&b);
    b[o..o + 8].copy_from_slice(&x.to_le_bytes());
    let bad = d.join("bad.so");
    fs::write(&bad, b).unwrap();
    let r = run(&[&bad]);
    assert!(!r.status.success());
    assert!(String::from_utf8_lossy(&r.stderr).contains("PC32 target"));
    fs::remove_dir_all(d).unwrap();
}
#[test]
fn malformed_later_input_keeps_stdout_atomic() {
    let d = temp("atomic");
    let good = fixture(&d);
    let mut b = fs::read(&good).unwrap();
    let o = rela_off(&b);
    let n = sym_count(&b);
    b[o + 8..o + 16].copy_from_slice(&((n << 32) | u64::from(R_X86_64_PC32)).to_le_bytes());
    let bad = d.join("bad.so");
    fs::write(&bad, b).unwrap();
    let r = run(&[&good, &bad]);
    assert!(!r.status.success());
    assert!(r.stdout.is_empty());
    fs::remove_dir_all(d).unwrap();
}
