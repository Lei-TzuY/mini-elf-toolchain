use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn have_tools() -> bool {
    ["as", "ld", "readelf"].into_iter().all(|p| Command::new(p).arg("--version").output().is_ok_and(|o| o.status.success()))
}
fn dynamic_linker() -> Option<PathBuf> {
    ["/lib64/ld-linux-x86-64.so.2", "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"].into_iter().map(PathBuf::from).find(|p| p.is_file())
}
fn temp_dir() -> PathBuf {
    let n=SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let p=std::env::temp_dir().join(format!("mini-elf-dyn-pie-gotpcrel64-{}-{n}",std::process::id()));
    fs::create_dir_all(&p).unwrap(); p
}
fn assemble(dir:&Path, stem:&str, src:&str)->PathBuf {
    let s=dir.join(format!("{stem}.s")); let o=dir.join(format!("{stem}.o")); fs::write(&s,src).unwrap();
    let r=Command::new("as").args(["--64","-o"]).arg(&o).arg(&s).output().unwrap();
    assert!(r.status.success(),"{}",String::from_utf8_lossy(&r.stderr)); o
}
fn readelf(path:&Path,args:&[&str])->String {
    let o=Command::new("readelf").args(args).arg(path).output().unwrap();
    assert!(o.status.success()); String::from_utf8(o.stdout).unwrap()
}

#[test]
#[cfg(target_os="linux")]
fn dynamic_pie_binds_gotpcrel64_through_loader_got() {
    if !have_tools() { return; }
    let Some(interp)=dynamic_linker() else { return; };
    let dir=temp_dir();
    let provider_o=assemble(&dir,"provider",r#".data
.globl provider_value
.type provider_value,@object
.size provider_value,8
provider_value: .quad 42
.section .note.GNU-stack,"",@progbits
"#);
    let provider=dir.join("libprovider.so");
    let r=Command::new("ld").args(["-shared","-soname","libprovider.so","-o"]).arg(&provider).arg(&provider_o).output().unwrap();
    assert!(r.status.success(),"{}",String::from_utf8_lossy(&r.stderr));

    let consumer=assemble(&dir,"consumer",r#".globl provider_value
.type provider_value,@object
.text
.globl _start
.type _start,@function
_start:
    lea got_disp(%rip), %rax
    add got_disp(%rip), %rax
    mov (%rax), %rax
    mov (%rax), %rdi
    mov $60, %eax
    syscall
.size _start,.-_start
.section .rodata
.align 8
got_disp: .quad provider_value@GOTPCREL
.section .note.GNU-stack,"",@progbits
"#);
    let input_relocs=readelf(&consumer,&["-rW"]);
    assert!(input_relocs.contains("R_X86_64_GOTPCREL64"),"{input_relocs}");

    let mini=dir.join("mini");
    let r=Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain")).args(["link","-o"]).arg(&mini)
        .arg("--dynamic-pie").arg("--dynamic-linker").arg(&interp).arg("--needed-from").arg(&provider)
        .arg("--runpath").arg("$ORIGIN").arg(&consumer).output().unwrap();
    assert!(r.status.success(),"{}",String::from_utf8_lossy(&r.stderr));
    let relocs=readelf(&mini,&["-rW"]);
    assert!(relocs.lines().any(|l| l.contains("R_X86_64_GLOB_DAT") && l.contains("provider_value")),"{relocs}");
    let status=Command::new(&mini).status().unwrap();
    assert_eq!(status.code(),Some(42));

    let gnu=dir.join("gnu");
    let r=Command::new("ld").arg("-pie").arg("--dynamic-linker").arg(&interp).args(["-rpath","$ORIGIN","-o"]).arg(&gnu)
        .arg(&consumer).arg("-L").arg(&dir).arg("-lprovider").output().unwrap();
    assert!(r.status.success(),"{}",String::from_utf8_lossy(&r.stderr));
    assert_eq!(Command::new(&gnu).status().unwrap().code(),Some(42));
    let _=fs::remove_dir_all(dir);
}
