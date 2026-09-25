use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn command_available(program: &str) -> bool {
    Command::new(program)
        .arg("--version")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn have_tools() -> bool {
    command_available("cc") && command_available("readelf")
}

fn dynamic_linker() -> Option<PathBuf> {
    [
        PathBuf::from("/lib64/ld-linux-x86-64.so.2"),
        PathBuf::from("/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"),
    ]
    .into_iter()
    .find(|path| path.is_file())
}

fn libc_path() -> Option<PathBuf> {
    let output = Command::new("cc")
        .arg("-print-file-name=libc.so.6")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let path = PathBuf::from(String::from_utf8(output.stdout).ok()?.trim());
    path.is_file().then_some(path)
}

fn temp_dir() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after Unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "mini-elf-toolchain-dynamic-pie-compiler-gotpcrelx-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&path).unwrap();
    path
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

#[test]
#[cfg(target_os = "linux")]
fn compiler_generated_relaxable_gotpcrel_binds_external_data() {
    if !have_tools() {
        return;
    }
    let Some(interpreter) = dynamic_linker() else {
        return;
    };
    let Some(libc) = libc_path() else {
        return;
    };

    let dir = temp_dir();

    let provider_source = dir.join("provider.c");
    let provider = dir.join("libprovider.so");
    fs::write(
        &provider_source,
        r#"int provider_value = 42;
"#,
    )
    .unwrap();
    let provider_build = Command::new("cc")
        .args(["-shared", "-fPIC"])
        .arg(&provider_source)
        .arg("-Wl,-soname,libprovider.so")
        .arg("-o")
        .arg(&provider)
        .output()
        .unwrap();
    assert!(
        provider_build.status.success(),
        "{}",
        String::from_utf8_lossy(&provider_build.stderr)
    );

    let consumer_source = dir.join("consumer.c");
    let consumer = dir.join("consumer.o");
    fs::write(
        &consumer_source,
        r#"extern int provider_value;

int main(void) {
    return provider_value;
}
"#,
    )
    .unwrap();
    let consumer_build = Command::new("cc")
        .args(["-O0", "-fPIC", "-fno-stack-protector", "-c"])
        .arg(&consumer_source)
        .arg("-o")
        .arg(&consumer)
        .output()
        .unwrap();
    assert!(
        consumer_build.status.success(),
        "{}",
        String::from_utf8_lossy(&consumer_build.stderr)
    );

    let input_symbols = readelf(&consumer, &["-sW"]);
    assert!(
        input_symbols.lines().any(|line| {
            line.contains("OBJECT")
                && line.contains("GLOBAL")
                && line.contains("UND")
                && line.ends_with(" provider_value")
        }),
        "compiler fixture must expose provider_value as an undefined GLOBAL OBJECT:\n{input_symbols}"
    );

    let input_relocations = readelf(&consumer, &["-rW"]);
    assert!(
        input_relocations.lines().any(|line| {
            (line.contains("R_X86_64_REX_GOTPCRELX") || line.contains("R_X86_64_GOTPCRELX"))
                && line.contains("provider_value")
        }),
        "compiler fixture must exercise a relaxable GOTPCREL relocation:\n{input_relocations}"
    );

    let mini = dir.join("mini-pie");
    let linked = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
        .args(["link", "-o"])
        .arg(&mini)
        .arg("--dynamic-pie")
        .arg("--crt-startup")
        .arg("--dynamic-linker")
        .arg(&interpreter)
        .arg("--needed-from")
        .arg(&provider)
        .arg("--needed-from")
        .arg(&libc)
        .arg("--runpath")
        .arg("$ORIGIN")
        .arg(&consumer)
        .output()
        .unwrap();
    assert!(
        linked.status.success(),
        "{}",
        String::from_utf8_lossy(&linked.stderr)
    );

    let dynamic_relocations = readelf(&mini, &["-rW", "--use-dynamic"]);
    assert!(
        dynamic_relocations.lines().any(|line| {
            line.contains("R_X86_64_GLOB_DAT") && line.contains("provider_value")
        }),
        "relaxable compiler GOT reference must retain loader-owned GLOB_DAT binding:\n{dynamic_relocations}"
    );

    let mini_status = Command::new(&mini).status().unwrap();
    assert_eq!(
        mini_status.code(),
        Some(42),
        "mini-linked compiler PIE must read provider data through the loader-filled GOT: {mini_status}"
    );

    let gnu = dir.join("gnu-pie");
    let gnu_link = Command::new("cc")
        .arg("-pie")
        .arg(&consumer)
        .arg("-L")
        .arg(&dir)
        .arg("-lprovider")
        .arg("-Wl,-rpath,$ORIGIN")
        .arg("-o")
        .arg(&gnu)
        .output()
        .unwrap();
    assert!(
        gnu_link.status.success(),
        "{}",
        String::from_utf8_lossy(&gnu_link.stderr)
    );
    let gnu_status = Command::new(&gnu).status().unwrap();
    assert_eq!(
        gnu_status.code(),
        Some(42),
        "GNU reference must execute the same compiler object: {gnu_status}"
    );

    let _ = fs::remove_dir_all(dir);
}
