use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

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

fn temp_dir(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after Unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "mini-elf-toolchain-gnu-stack-producer-{label}-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&path).unwrap();
    path
}

fn assemble(
    dir: &Path,
    stem: &str,
    symbol: &str,
    stack_flags: Option<&str>,
) -> PathBuf {
    let source = dir.join(format!("{stem}.s"));
    let object = dir.join(format!("{stem}.o"));
    let note = stack_flags
        .map(|flags| format!("\n.section .note.GNU-stack,\"{flags}\",@progbits\n"))
        .unwrap_or_default();
    fs::write(
        &source,
        format!(
            ".text\n.globl {symbol}\n.type {symbol},@function\n{symbol}:\n  ret\n.size {symbol}, .-{symbol}\n{note}"
        ),
    )
    .unwrap();
    let output = Command::new("as")
        .args(["--64", "-o"])
        .arg(&object)
        .arg(&source)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    object
}

fn stack_flags(path: &Path) -> Option<String> {
    let output = Command::new("readelf")
        .args(["-lW"])
        .arg(path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8_lossy(&output.stdout);
    text.lines()
        .find(|line| line.contains("GNU_STACK"))
        .and_then(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            fields.get(fields.len().checked_sub(2)?).map(|value| (*value).to_owned())
        })
}

fn link_mini(dir: &Path, label: &str, pie: bool, objects: &[&Path]) -> PathBuf {
    let output = dir.join(format!("mini-{label}{}", if pie { ".pie" } else { "" }));
    let mut command = Command::new(env!("CARGO_BIN_EXE_mini-elf-toolchain"));
    command.args(["link", "-o"]).arg(&output);
    if pie {
        command.arg("--pie");
    }
    for object in objects {
        command.arg(object);
    }
    let linked = command.output().unwrap();
    assert!(
        linked.status.success(),
        "{}",
        String::from_utf8_lossy(&linked.stderr)
    );
    output
}

fn link_gnu(dir: &Path, label: &str, pie: bool, objects: &[&Path]) -> PathBuf {
    let output = dir.join(format!("gnu-{label}{}", if pie { ".pie" } else { "" }));
    let mut command = Command::new("ld");
    if pie {
        command.args(["-pie", "--no-dynamic-linker"]);
    }
    command.args(["-o"]).arg(&output);
    for object in objects {
        command.arg(object);
    }
    let linked = command.output().unwrap();
    assert!(
        linked.status.success(),
        "{}",
        String::from_utf8_lossy(&linked.stderr)
    );
    output
}

#[test]
fn static_outputs_match_gnu_stack_policy_for_nonexec_and_exec_notes() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("notes");
    for (label, flags, expected) in [("noexec", "", "RW"), ("exec", "x", "RWE")] {
        let object = assemble(&dir, label, "_start", Some(flags));
        for pie in [false, true] {
            let mini = link_mini(&dir, label, pie, &[&object]);
            let gnu = link_gnu(&dir, label, pie, &[&object]);
            assert_eq!(stack_flags(&mini).as_deref(), Some(expected));
            assert_eq!(stack_flags(&gnu).as_deref(), Some(expected));

            let inspected = Command::new(env!("CARGO_BIN_EXE_mini-elf-gnu-stack"))
                .arg(&mini)
                .output()
                .unwrap();
            assert!(inspected.status.success());
            let inspected = String::from_utf8_lossy(&inspected.stdout);
            assert!(inspected.contains("PT_GNU_STACK"), "{inspected}");
            assert!(
                inspected.contains(if expected == "RWE" {
                    "executable=yes"
                } else {
                    "executable=no"
                }),
                "{inspected}"
            );
        }
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn executable_stack_requirement_is_aggregated_across_inputs() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("aggregate");
    let start = assemble(&dir, "start", "_start", Some(""));
    let helper = assemble(&dir, "helper", "helper", Some("x"));

    for pie in [false, true] {
        let mini = link_mini(&dir, "aggregate", pie, &[&start, &helper]);
        let gnu = link_gnu(&dir, "aggregate", pie, &[&start, &helper]);
        assert_eq!(stack_flags(&mini).as_deref(), Some("RWE"));
        assert_eq!(stack_flags(&gnu).as_deref(), Some("RWE"));
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn inputs_without_gnu_stack_notes_do_not_synthesize_a_policy_header() {
    if !have_tools() {
        return;
    }

    let dir = temp_dir("absent");
    let object = assemble(&dir, "absent", "_start", None);

    for pie in [false, true] {
        let mini = link_mini(&dir, "absent", pie, &[&object]);
        assert_eq!(stack_flags(&mini), None);
    }

    let _ = fs::remove_dir_all(dir);
}
