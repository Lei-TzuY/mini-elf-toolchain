use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_dir(label: &str) -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "mini-elf-toolchain-{label}-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&path).unwrap();
    path
}

fn tool_available(tool: &str) -> bool {
    Command::new(tool).arg("--version").output().is_ok()
}

#[test]
fn rejects_truncated_elf_before_symbol_walk() {
    let dir = temp_dir("nm-malformed");
    let input = dir.join("bad.o");
    fs::write(&input, b"\x7fELF").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-nm"))
        .arg(&input)
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("ELF64 header is truncated"), "{stderr}");

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn reports_gnu_symbol_facts_for_real_et_rel() {
    if !tool_available("as") || !tool_available("readelf") || !tool_available("nm") {
        return;
    }

    let dir = temp_dir("nm-gnu");
    let assembly = dir.join("sample.s");
    let object = dir.join("sample.o");
    fs::write(
        &assembly,
        ".text\n.globl exported\n.type exported,@function\nexported:\n  ret\n.size exported, .-exported\n.data\n.weak weak_obj\n.type weak_obj,@object\n.size weak_obj,8\nweak_obj:\n  .quad 42\n",
    )
    .unwrap();

    let assembled = Command::new("as")
        .arg("-o")
        .arg(&object)
        .arg(&assembly)
        .output()
        .unwrap();
    assert!(
        assembled.status.success(),
        "{}",
        String::from_utf8_lossy(&assembled.stderr)
    );

    let mini = Command::new(env!("CARGO_BIN_EXE_mini-elf-nm"))
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        mini.status.success(),
        "{}",
        String::from_utf8_lossy(&mini.stderr)
    );
    let mini_stdout = String::from_utf8_lossy(&mini.stdout);
    assert!(mini_stdout.contains("VALUE             SIZE BIND   TYPE    SHNDX NAME"));
    assert!(mini_stdout.contains("GLOBAL FUNC"), "{mini_stdout}");
    assert!(mini_stdout.contains("exported"), "{mini_stdout}");
    assert!(mini_stdout.contains("WEAK   OBJECT"), "{mini_stdout}");
    assert!(mini_stdout.contains("weak_obj"), "{mini_stdout}");

    let readelf = Command::new("readelf")
        .args(["-Ws"])
        .arg(&object)
        .output()
        .unwrap();
    assert!(readelf.status.success());
    let readelf_stdout = String::from_utf8_lossy(&readelf.stdout);
    assert!(readelf_stdout.contains("GLOBAL") && readelf_stdout.contains("FUNC"));
    assert!(readelf_stdout.contains("exported"));
    assert!(readelf_stdout.contains("WEAK") && readelf_stdout.contains("OBJECT"));
    assert!(readelf_stdout.contains("weak_obj"));

    let nm = Command::new("nm").arg(&object).output().unwrap();
    assert!(nm.status.success());
    let nm_stdout = String::from_utf8_lossy(&nm.stdout);
    assert!(nm_stdout.contains("exported"));
    assert!(nm_stdout.contains("weak_obj"));

    let _ = fs::remove_dir_all(dir);
}
