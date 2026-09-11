use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const DT_NULL: i64 = 0;
const DT_GNU_HASH: i64 = 0x6fff_fef5;
const ET_DYN: u16 = 3;

fn temp(label: &str) -> PathBuf {
    let n = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let p = std::env::temp_dir().join(format!("mini-elf-toolchain-{label}-{}-{n}", std::process::id()));
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
    fs::write(&dep_s, ".data\n.globl target\n.type target,@object\n.size target,16\ntarget:\n.quad 1\n.quad 2\n").unwrap();
    fs::write(&main_s, ".text\n.globl _start\n.type _start,@function\n_start:\nmov target(%rip), %rax\nret\n").unwrap();
    assert!(Command::new("as").args(["-o", dep_o.to_str().unwrap(), dep_s.to_str().unwrap()]).status().unwrap().success());
    assert!(Command::new("ld").args(["-shared", "--hash-style=gnu", "-o", dep_so.to_str().unwrap(), dep_o.to_str().unwrap()]).status().unwrap().success());
    assert!(Command::new("as").args(["-o", main_o.to_str().unwrap(), main_s.to_str().unwrap()]).status().unwrap().success());
    assert!(Command::new("ld").args(["--hash-style=gnu", "-dynamic-linker", "/lib64/ld-linux-x86-64.so.2", "-e", "_start", "-o", exe.to_str().unwrap(), main_o.to_str().unwrap(), dep_so.to_str().unwrap()]).status().unwrap().success());
    let mut b = fs::read(&exe).unwrap();
    b[16..18].copy_from_slice(&ET_DYN.to_le_bytes());
    fs::write(&exe, b).unwrap();
    exe
}

fn run(path: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_mini-elf-dynrela-copy")).args(["--load-bias", "0x70000000"]).arg(path).output().unwrap()
}
fn u16at(b: &[u8], o: usize) -> u16 { u16::from_le_bytes(b[o..o + 2].try_into().unwrap()) }
fn u32at(b: &[u8], o: usize) -> u32 { u32::from_le_bytes(b[o..o + 4].try_into().unwrap()) }
fn u64at(b: &[u8], o: usize) -> u64 { u64::from_le_bytes(b[o..o + 8].try_into().unwrap()) }
fn i64at(b: &[u8], o: usize) -> i64 { i64::from_le_bytes(b[o..o + 8].try_into().unwrap()) }
fn ph(b: &[u8]) -> Vec<(u32, u64, u64, u64)> {
    let p = u64at(b, 32) as usize;
    let e = u16at(b, 54) as usize;
    let n = u16at(b, 56) as usize;
    (0..n).map(|i| { let x = p + i * e; (u32at(b, x), u64at(b, x + 8), u64at(b, x + 16), u64at(b, x + 32)) }).collect()
}
fn map(b: &[u8], a: u64) -> usize {
    for (k, o, v, f) in ph(b) {
        if k == PT_LOAD && a >= v && a < v + f { return (o + a - v) as usize; }
    }
    panic!("unmapped")
}
fn tag(b: &[u8], want: i64) -> u64 {
    let d = ph(b).into_iter().find(|x| x.0 == PT_DYNAMIC).unwrap();
    let mut c = d.1 as usize;
    let end = (d.1 + d.3) as usize;
    while c + 16 <= end {
        let t = i64at(b, c);
        let v = u64at(b, c + 8);
        if t == want { return v; }
        if t == DT_NULL { break; }
        c += 16;
    }
    panic!("missing tag")
}

#[test]
fn validates_gnu_hash_only_copy_relocation() {
    let d = temp("copy-gnu-hash");
    let image = fixture(&d);
    let dyns = Command::new("readelf").args(["-dW", image.to_str().unwrap()]).output().unwrap();
    assert!(dyns.status.success());
    let dt = String::from_utf8_lossy(&dyns.stdout);
    assert!(dt.contains("GNU_HASH"), "{dt}");
    assert!(!dt.lines().any(|line| line.contains("(HASH)")), "{dt}");
    let rel = Command::new("readelf").args(["-rW", image.to_str().unwrap()]).output().unwrap();
    assert!(rel.status.success());
    assert!(String::from_utf8_lossy(&rel.stdout).contains("R_X86_64_COPY"));
    let o = run(&image);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert!(String::from_utf8_lossy(&o.stdout).contains("Validated R_X86_64_COPY"));
    fs::remove_dir_all(d).unwrap();
}

#[test]
fn rejects_malformed_gnu_hash_bloom_count() {
    let d = temp("copy-gnu-hash-bloom");
    let image = fixture(&d);
    let mut b = fs::read(&image).unwrap();
    let hash = map(&b, tag(&b, DT_GNU_HASH));
    b[hash + 8..hash + 12].copy_from_slice(&3u32.to_le_bytes());
    let bad = d.join("bad");
    fs::write(&bad, b).unwrap();
    let o = run(&bad);
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("non-zero power of two"));
    fs::remove_dir_all(d).unwrap();
}
