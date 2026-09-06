use mini_elf_toolchain::elf64::Elf64Header;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::process::ExitCode;

const USAGE: &str = "usage: mini-elf-readelf -h|--file-header <input>...";

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
    let mut args = args.collect::<Vec<_>>();
    if args.is_empty() {
        return Err(USAGE.to_owned());
    }
    if args[0] == "--help" || args[0] == "-H" {
        if args.len() != 1 {
            return Err(USAGE.to_owned());
        }
        return Ok(format!("{USAGE}\n"));
    }
    if args[0] != "-h" && args[0] != "--file-header" {
        return Err(USAGE.to_owned());
    }
    args.remove(0);
    if args.is_empty() {
        return Err(USAGE.to_owned());
    }

    let multiple_inputs = args.len() > 1;
    let mut inspected = Vec::with_capacity(args.len());
    for input in args {
        let file = fs::read(&input)
            .map_err(|error| format!("cannot read '{}': {error}", input.to_string_lossy()))?;
        let display = input.to_string_lossy().into_owned();
        let header = Elf64Header::parse(&file).map_err(|error| format!("{display}: {error}"))?;
        header
            .section_headers(&file)
            .map_err(|error| format!("{display}: {error}"))?;
        inspected.push((display, format_header(header)));
    }

    let mut output = String::new();
    for (index, (display, header)) in inspected.into_iter().enumerate() {
        if index != 0 {
            output.push('\n');
        }
        if multiple_inputs {
            output.push_str(&format!("File: {display}\n"));
        }
        output.push_str(&header);
    }
    Ok(output)
}

fn format_header(header: Elf64Header) -> String {
    format!(
        "ELF Header:\n  Class:                             ELF64\n  Data:                              2's complement, little endian\n  Type:                              {}\n  Machine:                           Advanced Micro Devices X86-64\n  Entry point address:               {:#x}\n  Start of program headers:          {} (bytes into file)\n  Start of section headers:          {} (bytes into file)\n  Flags:                             {:#x}\n  Size of this header:               {} (bytes)\n  Size of program headers:           {} (bytes)\n  Number of program headers:         {}\n  Size of section headers:           {} (bytes)\n  Number of section headers:         {}\n  Section header string table index: {}\n",
        type_name(header.elf_type),
        header.entry,
        header.program_header_offset,
        header.section_header_offset,
        header.flags,
        header.header_size,
        header.program_header_entry_size,
        header.program_header_count,
        header.section_header_entry_size,
        header.section_header_count,
        header.section_name_string_table_index,
    )
}

fn type_name(elf_type: u16) -> String {
    match elf_type {
        0 => "NONE (None)".to_owned(),
        1 => "REL (Relocatable file)".to_owned(),
        2 => "EXEC (Executable file)".to_owned(),
        3 => "DYN (Shared object file)".to_owned(),
        4 => "CORE (Core file)".to_owned(),
        value => format!("0x{value:x}"),
    }
}
