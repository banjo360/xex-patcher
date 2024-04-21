use std::io::*;
use std::fs::File;
use std::fs;
use byteorder::{ReadBytesExt, WriteBytesExt, LittleEndian, BigEndian};
use clap::Parser;
use std::collections::HashMap;

/// Patches an .OBJ file
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// File to patch
    #[arg(default_value = "default.xex")]
    filename: String,

    /// File containing the function to inject
    #[arg(default_value = "patch.txt")]
    patch: String,

    /// File containing the symbols addresses
    #[arg(short, long, default_value = "addresses.txt")]
    addresses: String,

    /// File patched
    #[arg(short, long, default_value = "default-patched.xex")]
    output: String,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let _ = fs::remove_file(&args.output);
    fs::copy(&args.filename, &args.output)?;

    let mut base_address = 0;
    let mut reading = File::open(&args.output)?;
    reading.seek(SeekFrom::Start(8))?;
    let offset_pe = reading.read_u32::<BigEndian>()? as u64;
    reading.seek(SeekFrom::Start(20))?;
    let xex_opt_header_count = reading.read_u32::<BigEndian>()? as u64;
    for i in 0..xex_opt_header_count {
        let id = reading.read_u32::<BigEndian>()?;
        let _ = reading.read_u32::<BigEndian>()?;

        if (id >> 8) == 0x102 {
            reading.seek(SeekFrom::Start(24 + i * 8 + 4))?;
            base_address = reading.read_u32::<BigEndian>()? as u64;
            break;
        }
    }
    let base_address = base_address;
    assert!(base_address > 0);
    reading.seek(SeekFrom::Start(offset_pe + 60))?;
    let offset_nt = reading.read_u32::<LittleEndian>()? as u64;
    reading.seek(SeekFrom::Start(offset_pe + offset_nt + 6))?;
    let number_of_sections = reading.read_u16::<LittleEndian>()? as u64;
    reading.seek(SeekFrom::Start(offset_pe + offset_nt + 20))?;
    let size_of_opt_headers = reading.read_u16::<LittleEndian>()? as u64;

    let mut start_of_text_section_phys = 0;
    let mut text_section_size_addr = 0;
    for i in 0..number_of_sections {
        reading.seek(SeekFrom::Start(offset_pe + offset_nt + 24 + size_of_opt_headers + i * 40))?;

        let mut name = [0u8; 8];
        reading.read(&mut name)?;
        let name = std::str::from_utf8(&name).unwrap().trim_matches('\0');

        if name == ".text" {
            text_section_size_addr = reading.seek(SeekFrom::Current(0))?;
            reading.seek(SeekFrom::Current(4))?;
            start_of_text_section_phys = reading.read_u32::<LittleEndian>()? as u64 + offset_pe;
            break;
        }
    }
    let start_of_text_section_phys = start_of_text_section_phys;
    let text_section_size_addr = text_section_size_addr;

    if text_section_size_addr == 0 {
        panic!("No .text section in file.");
    }

    let virt_to_phys_addr = base_address - offset_pe;

    let mut symbol_addresses = HashMap::<String, u64>::new();

    if std::fs::metadata(&args.addresses).is_ok() {
        for line in std::fs::read_to_string(&args.addresses).unwrap().lines() {
            let linedata: Vec<_> = line.split(" ").collect();
            assert_eq!(linedata.len(), 2);
            
            let addr = u64::from_str_radix(&linedata[0][2..], 16).unwrap();
            let name = linedata[1].to_string();

            symbol_addresses.insert(name, addr);
        }
    } else {
        panic!("can't find '{}'", args.addresses);
    }
    let symbol_addresses = symbol_addresses;

    let mut patches = vec![];

    if std::fs::metadata(&args.patch).is_ok() {
        for line in std::fs::read_to_string(&args.patch).unwrap().lines() {
            patches.push(line.to_string());
        }
    } else {
        panic!("can't find '{}'", args.patch);
    }

    let patches = patches;

    if patches.len() == 0 {
        println!("Nothing to patch.");
        return Ok(());
    }

    let mut f = File::options().write(true).open(&args.output)?;

    let mut max_addr = 0u64;
    for patch in patches {
        let patch_data: Vec<_> = patch.split(':').collect();
        match patch_data[0] {
            "inject" => {
                let symbol = patch_data[1].to_string();

                let sym_addr = symbol_addresses[&symbol];
                let sym_phys_addr = sym_addr - virt_to_phys_addr;
                println!("Injecting {symbol}.");

                let bytes = fs::read(format!("build/{symbol}.bin"))?;
                f.seek(SeekFrom::Start(sym_phys_addr))?;
                f.write(&bytes)?;

                max_addr = std::cmp::max(max_addr, f.seek(SeekFrom::Current(0))?);
            },
            "call" => {
                // TODO: check that it's a BL instruction (0..5 = 0b010010 = 18)
                let call_addr = patch_data[1].to_string();
                let symbol = patch_data[2].to_string();
                println!("Patching {call_addr} with {symbol}.");

                let sym_addr = symbol_addresses[&symbol];
                let sym_phys_addr = sym_addr - virt_to_phys_addr;
                let call_addr = u64::from_str_radix(&call_addr[2..], 16).unwrap() - virt_to_phys_addr;

                f.seek(SeekFrom::Start(call_addr))?;
                let jump_offset = ((sym_phys_addr as i64) - (call_addr as i64)) as u64;
                let jump = (jump_offset & 0x3FFFFFFC) as u32 | 0x48000001;
                f.write_u32::<BigEndian>(jump)?;
            },
            _ => {
                eprintln!("Unknown command: {}", patch_data[0]);
            }
        }
    }
    let max_addr = max_addr;

    let new_size = (max_addr - start_of_text_section_phys) as u32;
    f.seek(SeekFrom::Start(text_section_size_addr))?;
    f.write_u32::<LittleEndian>(new_size)?;
    // need to patch also the "raw size" (which is the size rounded to some value)
    // Ghidra shows an error when opening (if size > raw size) but xenia doesn't seem to care
    
    Ok(())
}
