use mini_elf_toolchain::elf64::{Elf64Header, SHT_STRTAB};
use std::env;
use std::ffi::OsString;
use std::fs;
use std::process::ExitCode;

const SHT_DYNAMIC: u32 = 6;
const ELF64_DYNAMIC_SIZE: u64 = 16;

fn main() -> ExitCode {
    match run(env::args_os().skip(1)) {
        Ok(output) => {
            print!("{output}");
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run<I>(args: I) -> Result<String, String>
where
    I: Iterator<Item = OsString>,
{
    let args = args.collect::<Vec<_>>();
    if args.is_empty() || args[0] == "--help" || args[0] == "-h" {
        return if args.len() <= 1 {
            Ok("usage: mini-elf-dynamic <input>...\n".to_owned())
        } else {
            Err("usage: mini-elf-dynamic <input>...".to_owned())
        };
    }

    let multiple_inputs = args.len() > 1;
    let mut inspected = Vec::with_capacity(args.len());
    for input in args {
        let file = fs::read(&input)
            .map_err(|error| format!("cannot read '{}': {error}", input.to_string_lossy()))?;
        let display = input.to_string_lossy().into_owned();
        let header = Elf64Header::parse(&file).map_err(|error| format!("{display}: {error}"))?;
        let rendered =
            format_dynamic(header, &file).map_err(|error| format!("{display}: {error}"))?;
        inspected.push((display, rendered));
    }

    let mut output = String::new();
    for (index, (display, rendered)) in inspected.into_iter().enumerate() {
        if index != 0 {
            output.push('\n');
        }
        if multiple_inputs {
            output.push_str(&format!("File: {display}\n"));
        }
        output.push_str(&rendered);
    }
    Ok(output)
}

fn format_dynamic(header: Elf64Header, file: &[u8]) -> Result<String, String> {
    let sections = header
        .section_headers(file)
        .map_err(|error| error.to_string())?;
    let mut output = String::new();
    let mut rendered_tables = 0usize;

    for (section_index, section) in sections.iter().enumerate() {
        if section.section_type != SHT_DYNAMIC {
            continue;
        }
        if section.entry_size != ELF64_DYNAMIC_SIZE {
            return Err(format!(
                "dynamic section {section_index} has entry size {}, expected {ELF64_DYNAMIC_SIZE}",
                section.entry_size
            ));
        }
        if section.size % section.entry_size != 0 {
            return Err(format!(
                "dynamic section {section_index} has size {}, which is not a multiple of entry size {}",
                section.size, section.entry_size
            ));
        }
        let section_end = section
            .offset
            .checked_add(section.size)
            .ok_or_else(|| format!("dynamic section {section_index} file range overflows u64"))?;
        if section_end > file.len() as u64 {
            return Err(format!(
                "dynamic section {section_index} ends at file offset {section_end}, beyond file length {}",
                file.len()
            ));
        }
        let string_table_index = usize::try_from(section.link).map_err(|_| {
            format!("dynamic section {section_index} string-table index does not fit usize")
        })?;
        let string_table = sections.get(string_table_index).ok_or_else(|| {
            format!(
                "dynamic section {section_index} links to string-table section {}, outside section-header count {}",
                section.link,
                sections.len()
            )
        })?;
        if string_table.section_type != SHT_STRTAB {
            return Err(format!(
                "dynamic section {section_index} links to section {}, which is not a string table",
                section.link
            ));
        }
        let string_table_end = string_table
            .offset
            .checked_add(string_table.size)
            .ok_or_else(|| {
                format!("dynamic string table {string_table_index} file range overflows u64")
            })?;
        if string_table_end > file.len() as u64 {
            return Err(format!(
                "dynamic string table {string_table_index} ends at file offset {string_table_end}, beyond file length {}",
                file.len()
            ));
        }

        if rendered_tables != 0 {
            output.push('\n');
        }
        rendered_tables += 1;
        let entry_count = section.size / section.entry_size;
        output.push_str(&format!(
            "Dynamic section {section_index} contains {entry_count} entries:\n"
        ));
        output.push_str("  Tag                Type                 Name/Value\n");

        for entry_index in 0..entry_count {
            let relative = entry_index.checked_mul(section.entry_size).ok_or_else(|| {
                format!("dynamic section {section_index} entry offset overflows u64")
            })?;
            let entry_offset = section.offset.checked_add(relative).ok_or_else(|| {
                format!("dynamic section {section_index} entry offset overflows u64")
            })?;
            let entry_end = entry_offset
                .checked_add(section.entry_size)
                .ok_or_else(|| {
                    format!("dynamic section {section_index} entry range overflows u64")
                })?;
            if entry_end > file.len() as u64 {
                return Err(format!(
                    "dynamic section {section_index} entry {entry_index} ends at file offset {entry_end}, beyond file length {}",
                    file.len()
                ));
            }
            let entry_offset = usize::try_from(entry_offset).map_err(|_| {
                format!("dynamic section {section_index} entry offset does not fit usize")
            })?;
            let tag = read_i64(file, entry_offset);
            let value = read_u64(file, entry_offset + 8);
            let rendered_value = if is_string_tag(tag) {
                let name = dynamic_string(file, string_table.offset, string_table.size, value)?;
                format!("[{}]", String::from_utf8_lossy(name))
            } else {
                format!("{value:#x}")
            };
            output.push_str(&format!(
                "  {tag:#018x} {:<20} {rendered_value}\n",
                dynamic_tag_name(tag)
            ));
        }
    }

    Ok(output)
}

fn dynamic_string(
    file: &[u8],
    table_offset: u64,
    table_size: u64,
    name_offset: u64,
) -> Result<&[u8], String> {
    if name_offset >= table_size {
        return Err(format!(
            "dynamic string offset {name_offset} is outside string-table size {table_size}"
        ));
    }
    let start = table_offset
        .checked_add(name_offset)
        .ok_or_else(|| "dynamic string offset overflows u64".to_owned())?;
    let end = table_offset
        .checked_add(table_size)
        .ok_or_else(|| "dynamic string-table range overflows u64".to_owned())?;
    let start = usize::try_from(start)
        .map_err(|_| "dynamic string offset does not fit usize".to_owned())?;
    let end = usize::try_from(end)
        .map_err(|_| "dynamic string-table end does not fit usize".to_owned())?;
    let bytes = file
        .get(start..end)
        .ok_or_else(|| "dynamic string-table range is outside the file".to_owned())?;
    let nul = bytes
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| "dynamic string is not NUL-terminated within its string table".to_owned())?;
    Ok(&bytes[..nul])
}

fn is_string_tag(tag: i64) -> bool {
    matches!(tag, 1 | 14 | 15 | 29)
}

fn dynamic_tag_name(tag: i64) -> String {
    match tag {
        0 => "NULL".to_owned(),
        1 => "NEEDED".to_owned(),
        2 => "PLTRELSZ".to_owned(),
        3 => "PLTGOT".to_owned(),
        4 => "HASH".to_owned(),
        5 => "STRTAB".to_owned(),
        6 => "SYMTAB".to_owned(),
        7 => "RELA".to_owned(),
        8 => "RELASZ".to_owned(),
        9 => "RELAENT".to_owned(),
        10 => "STRSZ".to_owned(),
        11 => "SYMENT".to_owned(),
        12 => "INIT".to_owned(),
        13 => "FINI".to_owned(),
        14 => "SONAME".to_owned(),
        15 => "RPATH".to_owned(),
        16 => "SYMBOLIC".to_owned(),
        17 => "REL".to_owned(),
        18 => "RELSZ".to_owned(),
        19 => "RELENT".to_owned(),
        20 => "PLTREL".to_owned(),
        21 => "DEBUG".to_owned(),
        22 => "TEXTREL".to_owned(),
        23 => "JMPREL".to_owned(),
        24 => "BIND_NOW".to_owned(),
        25 => "INIT_ARRAY".to_owned(),
        26 => "FINI_ARRAY".to_owned(),
        27 => "INIT_ARRAYSZ".to_owned(),
        28 => "FINI_ARRAYSZ".to_owned(),
        29 => "RUNPATH".to_owned(),
        30 => "FLAGS".to_owned(),
        value => return format!("DT_{value:#x}"),
    }
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn read_i64(bytes: &[u8], offset: usize) -> i64 {
    i64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}
