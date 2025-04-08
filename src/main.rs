use std::io::Read;

use imp::elf64::Elf64;

pub mod imp;

const MAGIC_IDENT: [u8; 4] = [0x7f, 0x45, 0x4c, 0x46];

// So what should be the workflow of the program?
// - Open up the ELF file the user wants to analyze and read it to a buffer.
// - Validate and confirm that the file is in fact an ELF file
//   (We can do so by checking for equivalence with the MAGIC_IDENT)
// - Read the ELF header and extracting the position and size of the program header sections
// - Read the program header sections locating the dynamic section
// - Examining the DT_NEEDED entries of the dynamic section
// - Extracting the offset of the DT_STRTABLE in the ELF file
// - Reading NEEDED dynamically linked libraries by the program
//
// ** SUPPORT FOR 64BIT **
fn main() {
    let args: Vec<_> = std::env::args().collect();
    let path = args.get(1);

    if path.is_none() {
        panic!("Path is missing");
    }

    let path = path.unwrap();

    let file = std::fs::File::open(path);

    if let Err(ref e) = file {
        eprintln!("Error reading file {e}");
        return;
    }

    let mut file = file.unwrap();
    let mut buf: Vec<u8> = vec![];

    file.read_to_end(&mut buf).unwrap();
    
    if &buf[0..4] != &MAGIC_IDENT {
        panic!("Not an ELF file.");
    }
    
    // This program is yet to support 32 bit programs
    if buf[4] != 2 || buf[5] != 1 {
        panic!("Supporting only 64bit objects.");
    }
    
    let sh_meta = Elf64::extract_section_header_meta(&buf).unwrap();
    let program_sec_meta = Elf64::extract_program_section_meta(&buf, &sh_meta).unwrap();
    let dynamic_section_criticals = Elf64::read_dynamic_section(&buf, &program_sec_meta);
    let required = Elf64::extract_library_names(&buf, &dynamic_section_criticals);
    
    println!("Required libraries by {}", path);
    for req in required {
        println!(" ===> {}", req);
    }
}
