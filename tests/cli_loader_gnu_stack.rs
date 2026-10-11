use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const PT_INTERP: u32 = 3;
const PT_GNU_STACK: u32 = 0x6474_e551;
const PT_GNU_RELRO: u32 = 0x6474_e552;
const PT_GNU_PROPERTY: u32 = 0x6474_e553;

fn headers(path: &Path) -> Vec<(u32, u32)> {
    let bytes = fs::read(path).unwrap();
    let phoff = u64::from_le_bytes(bytes[32..40].try_into().unwrap()) as usize;
    let phentsize = u16::from_le_bytes(bytes[54..56].try_into().unwrap()) as usize;
    let phnum = u16::from_le_bytes(bytes[56..58].try_into().unwrap()) as usize;
    assert_eq!(phentsize, 56);
    (0..phnum)
        .map(|index| {
            let start = phoff + index * phentsize;
            (
                u32::from_le_bytes(bytes[start..start + 4].try_into().unwrap()),
                u32::from_le_bytes(bytes[start + 4..start + 8].try_into().unwrap()),
            )
        })
        .collect()
}

fn assemble(dir: &Path, name: &str, note: Option<&str>) -> PathBuf {
    let source = dir.join(format!("{name}.s"));
    let object = dir.join(format!("{name}.o"));
    let note = note.map_or_else(String::new, |flags| {
        format!(".section .note.GNU-stack,\"{flags}\",@progbits\n")
    });
    fs::write(
        &source,
        format!("{note}.text\n.globl _start\n.type _start,@function\n_start:\nmov $60,%eax\nmov $42,%edi\nsyscall\n.size _start,.-_start\n"),
    )
    .unwrap();
    let result = Command::new("as")
        .args(["--64", "-o"])
        .arg(&object)
        .arg(&source)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    object
}

#[test]
fn loader_images_preserve_stack_notes_with_interp_relro_and_property() {
    let available = Command::new("as")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success());
    if !available {
        eprintln!("SKIP: missing assembler");
        return;
    }
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "mini-elf-loader-stack-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).unwrap();
    for (name, note, expected) in [
        ("rw", Some(""), Some(6)),
        ("rwe", Some("x"), Some(7)),
        ("unspecified", None, Some(6)),
    ] {
        let object = assemble(&dir, name, note);
        for mode in ["--shared", "--dynamic-pie"] {
            for (layout, options) in [
                ("lazy", vec![]),
                ("now", vec!["-z", "now"]),
                ("ibt-now", vec!["-z", "ibt", "-z", "now"]),
            ] {
                let output = dir.join(format!("{name}-{mode}-{layout}"));
                let linked = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
                    .args(["link", "-o"])
                    .arg(&output)
                    .arg(mode)
                    .args(options)
                    .arg(&object)
                    .output()
                    .unwrap();
                assert!(
                    linked.status.success(),
                    "{}",
                    String::from_utf8_lossy(&linked.stderr)
                );
                let all = headers(&output);
                let stacks = all
                    .iter()
                    .filter(|(kind, _)| *kind == PT_GNU_STACK)
                    .map(|(_, flags)| *flags)
                    .collect::<Vec<_>>();
                assert_eq!(
                    stacks,
                    expected.into_iter().collect::<Vec<_>>(),
                    "{name}/{mode}/{layout}: {all:?}"
                );
                assert_eq!(
                    all.iter().any(|(kind, _)| *kind == PT_INTERP),
                    mode == "--dynamic-pie"
                );
                assert_eq!(
                    all.iter().any(|(kind, _)| *kind == PT_GNU_PROPERTY),
                    layout == "ibt-now"
                );
                if layout != "lazy" {
                    assert!(all.iter().any(|(kind, _)| *kind == PT_GNU_RELRO));
                }
            }
        }
    }
    // A single explicitly executable note must remain executable even when
    // another participating input declares a non-executable stack.
    let rw = assemble(&dir, "mixed-rw", Some(""));
    let source = dir.join("mixed-rwe.s");
    let rwe = dir.join("mixed-rwe.o");
    fs::write(&source, ".section .note.GNU-stack,\"x\",@progbits\n.text\n.globl extra\n.type extra,@function\nextra:\nret\n").unwrap();
    assert!(Command::new("as")
        .args(["--64", "-o"])
        .arg(&rwe)
        .arg(&source)
        .status()
        .unwrap()
        .success());
    for mode in ["--shared", "--dynamic-pie"] {
        let output = dir.join(format!("mixed-{mode}"));
        let linked = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"))
            .args(["link", "-o"])
            .arg(&output)
            .args([mode, "-z", "ibt", "-z", "now"])
            .args([&rw, &rwe])
            .output()
            .unwrap();
        assert!(
            linked.status.success(),
            "{}",
            String::from_utf8_lossy(&linked.stderr)
        );
        assert_eq!(
            headers(&output)
                .iter()
                .filter(|(kind, _)| *kind == PT_GNU_STACK)
                .map(|(_, flags)| *flags)
                .collect::<Vec<_>>(),
            vec![7]
        );
    }
    fs::remove_dir_all(dir).unwrap();
}
