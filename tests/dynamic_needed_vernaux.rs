use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const DT_NULL: i64 = 0;
const DT_VERNEED: i64 = 0x6fff_fffe;

fn temp_dir(label: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "mini-elf-needed-vernaux-{label}-{}-{stamp}",
        std::process::id()
    ));
    fs::create_dir_all(&path).unwrap();
    path
}

fn command_ok(command: &mut Command) {
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "command failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn build_fixture(dir: &Path) -> PathBuf {
    let dep_s = dir.join("dep.s");
    let dep_o = dir.join("dep.o");
    let dep_map = dir.join("dep.map");
    let dep_so = dir.join("libdep.so");
    fs::write(
        &dep_s,
        ".text\n.globl dep\n.type dep,@function\ndep:\n  ret\n.size dep, .-dep\n",
    )
    .unwrap();
    fs::write(&dep_map, "VERS_DEP { global: dep; };\n").unwrap();
    command_ok(
        Command::new("as")
            .arg("--64")
            .arg("-o")
            .arg(&dep_o)
            .arg(&dep_s),
    );
    command_ok(
        Command::new("ld")
            .arg("-shared")
            .arg("--version-script")
            .arg(&dep_map)
            .arg("-soname")
            .arg("libdep.so")
            .arg("-o")
            .arg(&dep_so)
            .arg(&dep_o),
    );

    let use_s = dir.join("use.s");
    let use_o = dir.join("use.o");
    let use_so = dir.join("consumer.so");
    fs::write(
        &use_s,
        ".text\n.globl exported\n.type exported,@function\nexported:\n  call dep@PLT\n  ret\n.size exported, .-exported\n",
    )
    .unwrap();
    command_ok(
        Command::new("as")
            .arg("--64")
            .arg("-o")
            .arg(&use_o)
            .arg(&use_s),
    );
    command_ok(
        Command::new("ld")
            .arg("-shared")
            .arg("-o")
            .arg(&use_so)
            .arg(&use_o)
            .arg("-L")
            .arg(dir)
            .arg("-ldep"),
    );
    use_so
}

#[test]
fn rejects_vernaux_chain_ending_before_vn_cnt_atomically() {
    let dir = temp_dir("early-end");
    let good = build_fixture(&dir);
    let bad = dir.join("early-end.so");
    let mut bytes = fs::read(&good).unwrap();
    let verneed = dynamic_value(&bytes, DT_VERNEED).unwrap();
    let verneed_offset = virtual_to_file(&bytes, verneed, 16).unwrap();
    bytes[verneed_offset + 2..verneed_offset + 4].copy_from_slice(&2u16.to_le_bytes());
    fs::write(&bad, bytes).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-needed-check"))
        .arg(&good)
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Vernaux chain ends before vn_cnt 2"),
        "{stderr}"
    );
    assert!(output.stdout.is_empty());
}

#[test]
fn rejects_nonzero_final_vernaux_next() {
    let dir = temp_dir("final-next");
    let good = build_fixture(&dir);
    let bad = dir.join("final-next.so");
    let mut bytes = fs::read(&good).unwrap();
    let verneed = dynamic_value(&bytes, DT_VERNEED).unwrap();
    let verneed_offset = virtual_to_file(&bytes, verneed, 16).unwrap();
    let aux_relative = read_u32(&bytes, verneed_offset + 8) as u64;
    let aux_offset = virtual_to_file(&bytes, verneed + aux_relative, 16).unwrap();
    bytes[aux_offset + 12..aux_offset + 16].copy_from_slice(&16u32.to_le_bytes());
    fs::write(&bad, bytes).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mini-elf-needed-check"))
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("final Vernaux record has non-zero vna_next 16"),
        "{stderr}"
    );
    assert!(output.stdout.is_empty());
}

fn dynamic_value(bytes: &[u8], wanted: i64) -> Result<u64, String> {
    let (offset, size) = dynamic_segment(bytes)?;
    for entry in (offset..offset + size).step_by(16) {
        let tag = read_i64(bytes, entry);
        if tag == wanted {
            return Ok(read_u64(bytes, entry + 8));
        }
        if tag == DT_NULL {
            break;
        }
    }
    Err(format!("dynamic tag {wanted:#x} not found"))
}

fn dynamic_segment(bytes: &[u8]) -> Result<(usize, usize), String> {
    for ph in program_headers(bytes) {
        if read_u32(bytes, ph) == PT_DYNAMIC {
            return Ok((
                read_u64(bytes, ph + 8) as usize,
                read_u64(bytes, ph + 32) as usize,
            ));
        }
    }
    Err("PT_DYNAMIC not found".to_owned())
}

fn virtual_to_file(bytes: &[u8], address: u64, size: u64) -> Result<usize, String> {
    let end = address
        .checked_add(size)
        .ok_or_else(|| "virtual range overflow".to_owned())?;
    for ph in program_headers(bytes) {
        if read_u32(bytes, ph) != PT_LOAD {
            continue;
        }
        let offset = read_u64(bytes, ph + 8);
        let vaddr = read_u64(bytes, ph + 16);
        let filesz = read_u64(bytes, ph + 32);
        let backed_end = vaddr + filesz;
        if address >= vaddr && end <= backed_end {
            return usize::try_from(offset + (address - vaddr))
                .map_err(|_| "file offset does not fit usize".to_owned());
        }
    }
    Err("virtual range is not file-backed".to_owned())
}

fn program_headers(bytes: &[u8]) -> Vec<usize> {
    let phoff = read_u64(bytes, 32) as usize;
    let phentsize = read_u16(bytes, 54) as usize;
    let phnum = read_u16(bytes, 56) as usize;
    (0..phnum).map(|index| phoff + index * phentsize).collect()
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn read_i64(bytes: &[u8], offset: usize) -> i64 {
    i64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}
