use std::path::Path;
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

    /// File containing the instructions
    #[arg(default_value = "patch.txt")]
    patch: String,

    /// File containing the symbols addresses
    #[arg(short, long, default_value = "addresses.txt")]
    addresses: String,

    /// File containing the symbols to inject
    #[arg(short, long, default_value = "addresses.generated.txt")]
    generated: String,

    /// File patched
    #[arg(short, long, default_value = "default-patched.xex")]
    output: String,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let _ = fs::remove_file(&args.output);
    fs::copy(&args.filename, &args.output)?;

    let mut base_address = 0;
    let mut data_descriptor_header = 0;
    let mut reading = File::open(&args.output).expect(&format!("Can't open {}.", args.output));
    reading.seek(SeekFrom::Start(8))?;
    let offset_pe = reading.read_u32::<BigEndian>()? as u64;
    reading.seek(SeekFrom::Start(20))?;
    let xex_opt_header_count = reading.read_u32::<BigEndian>()? as u64;
    for _ in 0..xex_opt_header_count {
        let id = reading.read_u32::<BigEndian>()?;
        let val = reading.read_u32::<BigEndian>()?;

        if (id >> 8) == 0x102 {
            base_address = val;
        } else if (id >> 8) == 0x03 {
            data_descriptor_header = val;
        }
    }

    let mut zero_offsets = vec![];

    let data_descriptor_header = data_descriptor_header;
    reading.seek(SeekFrom::Start(data_descriptor_header as u64))?;
    let ddh_size = reading.read_u32::<BigEndian>()?;
    let _ = reading.read_u32::<BigEndian>()?;
    let ddh_count = (ddh_size / 8) - 1;
    let mut real_position = 0;
    for _ in 0..ddh_count {
        let block_size = reading.read_u32::<BigEndian>()?;
        let block_zero = reading.read_u32::<BigEndian>()?;
        real_position += block_size;
        zero_offsets.push((block_size, real_position, block_zero));
        real_position += block_zero;
    }

    let base_address = base_address;
    assert!(base_address > 0);
    reading.seek(SeekFrom::Start(offset_pe + 60))?;
    let offset_nt = reading.read_u32::<LittleEndian>()? as u64;
    reading.seek(SeekFrom::Start(offset_pe + offset_nt + 6))?;
    let number_of_sections = reading.read_u16::<LittleEndian>()? as u64;
    reading.seek(SeekFrom::Start(offset_pe + offset_nt + 20))?;
    let size_of_opt_headers = reading.read_u16::<LittleEndian>()? as u64;

    let mut text_section_size_addr = 0;
    let mut data_section_size_addr = 0;
    let mut rdata_section_size_addr = 0;
    let mut pdata_section_start = 0;
    let mut curr_rdata_addr = 0;
    for i in 0..number_of_sections {
        reading.seek(SeekFrom::Start(offset_pe + offset_nt + 24 + size_of_opt_headers + i * 40))?;

        let mut name = [0u8; 8];
        reading.read(&mut name)?;
        let name = std::str::from_utf8(&name).unwrap().trim_matches('\0');

        if name == ".pdata" {
            pdata_section_start = reading.seek(SeekFrom::Current(0))?;
        } else if name == ".text" {
            text_section_size_addr = reading.seek(SeekFrom::Current(0))?;
        } else if name == ".data" {
            data_section_size_addr = reading.seek(SeekFrom::Current(0))?;
        } else if name == ".rdata" {
            rdata_section_size_addr = reading.seek(SeekFrom::Current(0))?;
            let vsize = reading.read_u32::<LittleEndian>()?;
            let vaddr = reading.read_u32::<LittleEndian>()?;
            curr_rdata_addr = base_address + vaddr + vsize;
        }
    }
    let text_section_size_addr = text_section_size_addr;
    let data_section_size_addr = data_section_size_addr;
    let rdata_section_size_addr = rdata_section_size_addr;
    let pdata_section_start = pdata_section_start;

    if text_section_size_addr == 0 {
        panic!("No .text section in file.");
    }

    let mut symbol_addresses = HashMap::<String, u32>::new();

    let mut injector = HashMap::new();
    for line in std::fs::read_to_string(&args.generated).unwrap().lines() {
        let linedata: Vec<_> = line.split(" ").collect();
        assert_eq!(linedata.len(), 2);
        
        let addr = u32::from_str_radix(&linedata[0], 16).unwrap();
        let name = linedata[1].to_string();

        injector.insert(addr, name);
    }

    let args_addresses = vec![args.addresses, args.generated];
    for addresses in args_addresses {
        if std::fs::metadata(&addresses).is_ok() {
            for line in std::fs::read_to_string(&addresses).unwrap().lines() {
                let linedata: Vec<_> = line.split(" ").collect();
                assert_eq!(linedata.len(), 2);
                
                let addr = u32::from_str_radix(&linedata[0], 16).unwrap();
                let name = linedata[1].to_string();

                symbol_addresses.insert(name, addr);
            }
        } else {
            panic!("can't find '{}'", addresses);
        }
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

    let mut f = File::options().read(true).write(true).open(&args.output).expect(&format!("Can't read {}.", args.output));

    // remove .pdata section
    f.seek(SeekFrom::Start(text_section_size_addr + 4))?;
    let text_section_vaddr = f.read_u32::<LittleEndian>()?;
    let _ = f.read_u32::<LittleEndian>()?;
    let text_section_raw_ptr = f.read_u32::<LittleEndian>()?;
    f.seek(SeekFrom::Start(pdata_section_start))?;
    f.write_u32::<LittleEndian>(0)?;
    f.write_u32::<LittleEndian>(text_section_vaddr)?;
    f.write_u32::<LittleEndian>(0)?;
    f.write_u32::<LittleEndian>(text_section_raw_ptr)?;

    let mut added_bytes_to_text = 0;
    let mut added_bytes_to_data = 0;
    let mut added_bytes_to_rdata = 0;
    for (addr, symbol) in injector {
        if Path::new(&format!("build/{symbol}.bin")).exists() {
            let bytes = fs::read(format!("build/{symbol}.bin"))?;
            println!("Injecting {symbol} at {:#X}.", addr);
            let sym_phys_addr = convert_virtual_address_to_physical_address(base_address, &zero_offsets, addr) + offset_pe;
            f.seek(SeekFrom::Start(sym_phys_addr))?;
            added_bytes_to_text += bytes.len() as u32;

            f.write(&bytes)?;
        } else {
            eprintln!("File 'build/{symbol}.bin' not found. skipped.");
        }
    }

    for patch in patches {
        let patch_data: Vec<_> = patch.split(':').collect();
        match patch_data[0] {
            "inject" => {
                let symbol = patch_data[1].to_string();

                if Path::new(&format!("build/{symbol}.bin")).exists() {
                    let bytes = fs::read(format!("build/{symbol}.bin"))?;

                    if symbol.ends_with(".rdata") {
                        println!("Injecting {symbol} at {:#X}.", curr_rdata_addr);
                        let sym_phys_addr = convert_virtual_address_to_physical_address(base_address, &zero_offsets, curr_rdata_addr) + offset_pe;
                        f.seek(SeekFrom::Start(sym_phys_addr))?;
                        added_bytes_to_rdata += bytes.len() as u32;
                        curr_rdata_addr += bytes.len() as u32;
                    } else {
                        panic!("Can only inject .rdata blobs, not '{symbol}'");
                    }

                    f.write(&bytes)?;
                } else {
                    eprintln!("File 'build/{symbol}.bin' not found. skipped.");
                }
            },
            "expand" => {
                let symbol = patch_data[1].to_string();

                if Path::new(&format!("build/{symbol}.bin")).exists() {
                    let bytes = fs::read(format!("build/{symbol}.bin"))?;
                    println!("Adding {} bytes to .data.", bytes.len());
                    added_bytes_to_data = bytes.len() as u32;
                } else {
                    eprintln!("File 'build/{symbol}.bin' not found. skipped.");
                }
            },
            "patch" => {
                let addr = u32::from_str_radix(&patch_data[1], 16).unwrap();
                let inst = u32::from_str_radix(&patch_data[2], 16).unwrap();
                let sym_phys_addr = convert_virtual_address_to_physical_address(base_address, &zero_offsets, addr) + offset_pe;
                f.seek(SeekFrom::Start(sym_phys_addr))?;
                f.write_u32::<BigEndian>(inst)?;
                println!("Patching instruction at {:#X}.", addr);
            },
            "addr" => {
                let call_addr = patch_data[1].to_string();
                let symbol = patch_data[2].to_string();
                println!("Patching 0x{call_addr} with {symbol}.");

                let Some(sym_addr) = symbol_addresses.get(&symbol) else {
                    panic!("Unknown symbol '{symbol}'.");
                };
                let call_addr = u32::from_str_radix(&call_addr, 16).unwrap();
                let call_addr = convert_virtual_address_to_physical_address(base_address, &zero_offsets, call_addr) + offset_pe;

                f.seek(SeekFrom::Start(call_addr))?;
                f.write_u32::<BigEndian>(*sym_addr)?;
            },
            "noop" | "nop" => {
                let addr = u32::from_str_radix(&patch_data[1], 16).unwrap();
                let sym_phys_addr = convert_virtual_address_to_physical_address(base_address, &zero_offsets, addr) + offset_pe;
                f.seek(SeekFrom::Start(sym_phys_addr))?;
                f.write_u32::<BigEndian>(0x60000000)?; // ori r0, r0, 0
                println!("Patching NOOP at {:#X}.", addr);
            },
            "call" | "jump" => {
                let call_addr = patch_data[1].to_string();
                let symbol = patch_data[2].to_string();
                println!("Patching 0x{call_addr} with {symbol}.");

                let Some(sym_addr) = symbol_addresses.get(&symbol) else {
                    panic!("Unknown symbol '{symbol}'.");
                };
                let sym_phys_addr = convert_virtual_address_to_physical_address(base_address, &zero_offsets, *sym_addr) + offset_pe;
                let call_addr = u32::from_str_radix(&call_addr, 16).unwrap();
                let call_addr = convert_virtual_address_to_physical_address(base_address, &zero_offsets, call_addr) + offset_pe;

                f.seek(SeekFrom::Start(call_addr))?;
                let jump_offset = ((sym_phys_addr as i64) - (call_addr as i64)) as u64;
                let mut jump = (jump_offset & 0x3FFFFFFC) as u32 | 0x48000000;
                if patch_data[0] == "call" {
                    jump = jump | 1; // update link register
                }
                f.write_u32::<BigEndian>(jump)?;
            },
            _ => {
                eprintln!("Unknown command: {}", patch_data[0]);
            }
        }
    }
    let added_bytes_to_text = added_bytes_to_text;

    f.seek(SeekFrom::Start(text_section_size_addr))?;
    let previous_virtual_size = f.read_u32::<LittleEndian>()?;
    f.seek(SeekFrom::Current(-4))?;
    f.write_u32::<LittleEndian>(previous_virtual_size + added_bytes_to_text)?;
    f.seek(SeekFrom::Current(4))?;
    let previous_raw_size = f.read_u32::<LittleEndian>()?;
    f.seek(SeekFrom::Current(-4))?;
    f.write_u32::<LittleEndian>(previous_raw_size + added_bytes_to_text)?;

    f.seek(SeekFrom::Start(data_section_size_addr))?;
    let previous_virtual_size = f.read_u32::<LittleEndian>()?;
    f.seek(SeekFrom::Current(-4))?;
    f.write_u32::<LittleEndian>(previous_virtual_size + added_bytes_to_data)?;

    f.seek(SeekFrom::Start(rdata_section_size_addr))?;
    let previous_virtual_size = f.read_u32::<LittleEndian>()?;
    f.seek(SeekFrom::Current(-4))?;
    f.write_u32::<LittleEndian>(previous_virtual_size + added_bytes_to_rdata)?;
    f.seek(SeekFrom::Current(4))?;
    let previous_raw_size = f.read_u32::<LittleEndian>()?;
    f.seek(SeekFrom::Current(-4))?;
    f.write_u32::<LittleEndian>(previous_raw_size + added_bytes_to_rdata)?;
    Ok(())
}

fn convert_virtual_address_to_physical_address(base_address: u32, subsections: &Vec<(u32, u32, u32)>, virtual_address: u32) -> u64 {
    let mut total_removed = 0;
    let virtual_address = virtual_address - base_address;
    for (_, virt, zero) in subsections {
        if virtual_address < *virt {
            return (virtual_address - total_removed) as u64;
        } else {
            total_removed += zero;
        }
    }
    panic!("Unknown address");
}