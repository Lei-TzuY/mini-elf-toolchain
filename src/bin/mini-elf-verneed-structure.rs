use std::env;
use std::ffi::OsString;
use std::process::ExitCode;

#[allow(dead_code)]
mod checked {
    include!("mini-elf-verneed.rs");

    pub fn inspect(input: &std::ffi::OsStr) -> Result<String, String> {
        let display = input.to_string_lossy().into_owned();
        let file = fs::read(input).map_err(|error| format!("cannot read '{display}': {error}"))?;
        let header = Elf64Header::parse(&file).map_err(|error| format!("{display}: {error}"))?;
        inspect_bytes(header, &file).map_err(|error| format!("{display}: {error}"))
    }

    fn inspect_bytes(header: Elf64Header, file: &[u8]) -> Result<String, String> {
        let headers = program_headers(header, file)?;
        let entries = dynamic_entries(&headers, file)?;
        let address = unique_tag_value(&entries, DT_VERNEED, "DT_VERNEED")?;
        let count = unique_tag_value(&entries, DT_VERNEEDNUM, "DT_VERNEEDNUM")?;
        match (address, count) {
            (None, None) => {
                return Ok("No DT_VERNEED version-requirement table found.\n".to_owned());
            }
            (Some(_), None) | (None, Some(_)) => {
                return Err(
                    "PT_DYNAMIC must provide DT_VERNEED and DT_VERNEEDNUM together".to_owned(),
                );
            }
            _ => {}
        }

        let count = count.unwrap();
        if count == 0 {
            return Err("DT_VERNEEDNUM must be non-zero when DT_VERNEED is present".to_owned());
        }

        let mut current = address.unwrap();
        let mut aux_total = 0u64;
        for record_index in 0..count {
            let offset = map_virtual_range(
                &headers,
                file.len(),
                current,
                ELF64_VERNEED_SIZE,
                &format!("DT_VERNEED entry {record_index}"),
            )?;
            let offset = usize::try_from(offset)
                .map_err(|_| "DT_VERNEED file offset does not fit usize".to_owned())?;
            let version = read_u16(file, offset);
            let aux_count = read_u16(file, offset + 2);
            let aux_relative = read_u32(file, offset + 8);
            let next_relative = read_u32(file, offset + 12);

            if version != VER_NEED_CURRENT {
                return Err(format!(
                    "DT_VERNEED entry {record_index} has version {version}, expected {VER_NEED_CURRENT}"
                ));
            }
            if aux_count == 0 {
                return Err(format!(
                    "DT_VERNEED entry {record_index} must reference at least one Vernaux record"
                ));
            }
            if u64::from(aux_relative) < ELF64_VERNEED_SIZE {
                return Err(format!(
                    "DT_VERNEED entry {record_index} vn_aux {aux_relative} overlaps its {ELF64_VERNEED_SIZE}-byte Verneed record"
                ));
            }

            let mut aux_address = current
                .checked_add(u64::from(aux_relative))
                .ok_or_else(|| format!("DT_VERNEED entry {record_index} vn_aux overflows u64"))?;
            for aux_index in 0..u64::from(aux_count) {
                let aux_offset = map_virtual_range(
                    &headers,
                    file.len(),
                    aux_address,
                    ELF64_VERNAUX_SIZE,
                    &format!("DT_VERNEED entry {record_index} Vernaux {aux_index}"),
                )?;
                let aux_offset = usize::try_from(aux_offset)
                    .map_err(|_| "Vernaux file offset does not fit usize".to_owned())?;
                let next = read_u32(file, aux_offset + 12);
                aux_total = aux_total
                    .checked_add(1)
                    .ok_or_else(|| "Vernaux count overflows u64".to_owned())?;

                let last = aux_index + 1 == u64::from(aux_count);
                if last {
                    if next != 0 {
                        return Err(format!(
                            "DT_VERNEED entry {record_index} final Vernaux has non-zero vna_next {next}"
                        ));
                    }
                } else {
                    if u64::from(next) < ELF64_VERNAUX_SIZE {
                        return Err(format!(
                            "DT_VERNEED entry {record_index} Vernaux {aux_index} vna_next {next} does not advance past its {ELF64_VERNAUX_SIZE}-byte record"
                        ));
                    }
                    aux_address = aux_address.checked_add(u64::from(next)).ok_or_else(|| {
                        format!("DT_VERNEED entry {record_index} Vernaux address overflows u64")
                    })?;
                }
            }

            let last = record_index + 1 == count;
            if last {
                if next_relative != 0 {
                    return Err(format!(
                        "final DT_VERNEED entry has non-zero vn_next {next_relative} beyond DT_VERNEEDNUM {count}"
                    ));
                }
            } else {
                if u64::from(next_relative) < ELF64_VERNEED_SIZE {
                    return Err(format!(
                        "DT_VERNEED entry {record_index} vn_next {next_relative} does not advance past its {ELF64_VERNEED_SIZE}-byte record"
                    ));
                }
                current = current
                    .checked_add(u64::from(next_relative))
                    .ok_or_else(|| "DT_VERNEED next-entry address overflows u64".to_owned())?;
            }
        }

        Ok(format!(
            "DT_VERNEED structural offsets are forward and non-overlapping across {count} dependency entries and {aux_total} Vernaux records.\n"
        ))
    }
}

fn main() -> ExitCode {
    match run(env::args_os().skip(1)) {
        Ok(output) => {
            print!("{output}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("error: {error}");
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
            Ok("usage: mini-elf-verneed-structure <input>...\n".to_owned())
        } else {
            Err("usage: mini-elf-verneed-structure <input>...".to_owned())
        };
    }
    if args
        .iter()
        .any(|arg| arg.to_string_lossy().starts_with('-'))
    {
        return Err("usage: mini-elf-verneed-structure <input>...".to_owned());
    }

    let multiple = args.len() > 1;
    let mut reports = Vec::with_capacity(args.len());
    for input in args {
        let display = input.to_string_lossy().into_owned();
        let report = checked::inspect(&input)?;
        reports.push((display, report));
    }

    let mut output = String::new();
    for (index, (display, report)) in reports.into_iter().enumerate() {
        if index != 0 {
            output.push('\n');
        }
        if multiple {
            output.push_str(&format!("File: {display}\n"));
        }
        output.push_str(&report);
    }
    Ok(output)
}
