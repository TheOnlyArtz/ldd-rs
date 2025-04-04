use std::io::Read;

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

    let magic = &buf[0..4];
    if MAGIC_IDENT != magic {
        eprintln!("Not an ELF file.");
        eprintln!("First four bytes don't match the ELF specification.");
    }

    let elf_identifiers = &buf[0..52];

    let elf_identifier: Elf32Header =
        unsafe { std::ptr::read(elf_identifiers.as_ptr() as *const _) };

    println!(" {:?}", elf_identifier);
    let section_header_offset = elf_identifier.e_shoff as usize;
    let section_header_entry_size = elf_identifier.e_shentsize as usize;
    let section_header_end = section_header_offset + section_header_entry_size;

    let section_header = &buf[64..12 * 56]
        .chunks(56)
        .map(|x| unsafe { std::ptr::read(x.as_ptr() as *const _) })
        .filter(|x: &ElfProgramSection| x.p_type == 2)
        .collect::<Vec<ElfProgramSection>>();

    let needed = &section_header[0];
    let dyn_section_offset = needed.p_offset as usize;
    let dyn_section_size = needed.p_filesz as usize;
    let dynamic_section_elements = &buf[dyn_section_offset..(dyn_section_offset+dyn_section_size)];
    let dynamic_section_elements = dynamic_section_elements
        .chunks(16)
        .map(|x| unsafe { std::ptr::read(x.as_ptr() as *const DynamicSectionElement) })
        .collect::<Vec<_>>();
    println!("{:2x?}", dynamic_section_elements.iter().filter(|x| x.d_tag == 29).collect::<Vec<_>>()[0]);
}

const EI_NIDENT_NO_MAGIC: usize = 12;

#[derive(Debug)]
#[repr(packed)]
struct ElfIdentifier {
    magic: [u8; 4],
    ei_class: u8,
    ei_data: u8,
    ei_version: u8,
    ei_os_abi: u8,
    ei_abi_version: u8,
    ei_pad: [u8; 6],
    ei_nident: u8,
}

#[derive(Debug)]
#[repr(C)]
struct Elf32Header {
    e_ident: ElfIdentifier,
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
}

#[derive(Debug)]
#[repr(C)]
struct ElfProgramSection {
    pub p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
}

#[derive(Debug)]
#[repr(C)]
struct DynamicSectionElement {
    d_tag: i32,
    /// This is determenistic by the d_tag
    d_thing: u64,
}
