use std::io::{BufRead, Cursor, Seek};

/// For the 64 Bit the datatypes of the ELF specifications
/// are kind of different, they can be found here https://docs.oracle.com/cd/E23824_01/html/819-0690/chapter7-6.html
/// Elf64_Addr | Elf64_XWord | Elf64_Off = u64
/// Elf64_Half = u16
/// Elf64_Sword = i32
/// Elf64_Word = u32
/// Elf64_SXWord = i64
/// unsigned char = u8
pub struct Elf64;

impl Elf64 {
    /// Extracts the section header meta
    /// crucial for us to read the section header
    /// e_phoff: u64 - byte 0x28 to 0x30
    /// e_shentsize: u16 - byte 0x3a to 0x3c
    pub fn extract_section_header_meta(buffer: &[u8]) -> Option<Elf64SHeaderMeta> {
        let (e_phoff, e_phentsize, e_phnum) = (
            u64::from_le_bytes(buffer[0x20..0x28].try_into().unwrap()),
            u16::from_le_bytes(buffer[0x36..0x38].try_into().unwrap()),
            u16::from_le_bytes(buffer[0x38..0x3a].try_into().unwrap()),
        );

        if e_phoff == 0 {
            return None;
        }

        Some(Elf64SHeaderMeta {
            e_phoff,
            e_phentsize,
            e_phnum,
        })
    }

    /// Extract the program sections contained in the ELF file
    pub fn extract_program_section_meta(
        buffer: &[u8],
        h_meta: &Elf64SHeaderMeta,
    ) -> Option<ElfProgramSection> {
        // const PROGRAM_SECTION_SIZE: usize = 56;

        let section_offset = h_meta.e_phoff as usize;
        let section_size = h_meta.e_phentsize as usize;
        let section_amount = h_meta.e_phnum as usize;
        let program_sections =
            &buffer[section_offset..section_offset + (section_size * section_amount)];

        program_sections
            .chunks(section_size)
            .map(|ch| ElfProgramSection {
                p_type: ElfSegmentType::from(u32::from_le_bytes(ch[0x0..0x04].try_into().unwrap())),
                p_offset: u64::from_le_bytes(ch[0x08..0x10].try_into().unwrap()),
                p_filesz: u64::from_le_bytes(ch[0x20..0x28].try_into().unwrap()),
            })
            .filter(|sec| sec.p_type == ElfSegmentType::PtDynamic)
            .collect::<Vec<_>>()
            .get(0)
            .cloned()
    }

    /// Reads and extracts the dynamic section criticals
    /// which is basically the DT_NEEDED entries and DT_STRTAB
    /// you can call it whatever the fuck honestly.
    /// and in chunks of 16 bytes which is the size of a program section element
    pub fn read_dynamic_section(
        buffer: &[u8],
        dyn_meta: &ElfProgramSection,
    ) -> DynamicSectionCriticals {
        const PROGRAM_SECTIONS_ELEMENT_SIZE: usize = 16;

        let offset = dyn_meta.p_offset as usize;
        let size = dyn_meta.p_filesz as usize;
        let complete_section = &buffer[offset..offset + size];

        let elements = complete_section
            .chunks(PROGRAM_SECTIONS_ELEMENT_SIZE)
            .map(|x| DynSectionElement {
                d_tag: DynSectionTag::from(u64::from_le_bytes(x[0x0..0x08].try_into().unwrap())),
                d_thing: u64::from_le_bytes(x[0x08..].try_into().unwrap()),
            })
            .collect::<Vec<_>>();

        let str_table = elements
            .iter()
            .find(|x| x.d_tag == DynSectionTag::DtStrTab)
            .cloned()
            .expect("No string table found for ELF file");

        let str_sz = elements
            .iter()
            .find(|x| x.d_tag == DynSectionTag::DtStrTab)
            .cloned()
            .expect("No string table size found for ELF file");

        let needed = elements
            .iter()
            .filter(|x| x.d_tag == DynSectionTag::DtNeeded)
            .cloned()
            .collect::<Vec<_>>();

        DynamicSectionCriticals {
            dt_strtab: str_table,
            dt_strsz: str_sz.d_thing,
            dt_needed: needed,
        }
    }

    pub fn extract_library_names(
        buffer: &[u8],
        criticals: &DynamicSectionCriticals,
    ) -> Vec<String> {
        let mut results = Vec::new();
        let str_table_offset = criticals.dt_strtab.d_thing as usize;
        let str_table_size = criticals.dt_strsz as usize;
        let string_table = &buffer[str_table_offset..(str_table_offset + str_table_size)];

        // Copying into an owned structure so we can modify the data
        let string_table = string_table.to_vec();
        let mut cursor = Cursor::new(string_table);

        for needed in &criticals.dt_needed {
            cursor
                .seek(std::io::SeekFrom::Start(needed.d_thing))
                .unwrap();
            
            let mut library_name = Vec::new();
            cursor.read_until(0u8, &mut library_name).unwrap();
            
            results.push(String::from_utf8(library_name).unwrap());
        }

        results
    }
}

/// Represents the section header metadata
/// which is only crucial for the task for our task
/// Which is e_phoff and e_shentsize
/// where e_phoff represents the offset from the beggining of the file
/// and e_shentsize represents the size of the section header
#[derive(Debug)]
pub struct Elf64SHeaderMeta {
    e_phoff: u64,
    e_phentsize: u16,
    e_phnum: u16,
}

/// Represents a program section which is a part of
/// the section array
/// We will only represent the crucial data
/// ASSUMING WE PARSE THE DATA FROM [e_phoff .. e_phoff + e_shentsize]
/// and in chunks of 56 bytes which is the size of a program section
/// p_type: u32 byte 0x0 to 0x04
/// p_offset: u64 byte 0x08 to 0x10
/// p_filesz: u64 byte 0x20 to 0x28
#[derive(Debug, Clone)]
pub struct ElfProgramSection {
    p_type: ElfSegmentType,
    p_offset: u64,
    p_filesz: u64,
}

#[derive(Debug, PartialEq, Clone)]
enum ElfSegmentType {
    PtDynamic,
    Irrelevant,
}

impl From<u32> for ElfSegmentType {
    fn from(value: u32) -> Self {
        match value {
            0x02 => Self::PtDynamic,
            _ => Self::Irrelevant,
        }
    }
}

/// Represents an entry in the dynamic section
/// d_tag is essentially an i32 representing the type of the
///     entry
/// d_thing is basically a union on the original specification and it's usage
///     derives from the d_tag
///     we can just merge it to a single field
///     since both types of the unions are equivalent in the 64bit
///     specification
#[derive(Debug, Clone)]
struct DynSectionElement {
    d_tag: DynSectionTag,
    /// This is determenistic by the d_tag
    /// the original field is actually called d_un
    /// and looks like
    /// union {
    ///     Elf64_Xword     d_val;
    ///     Elf64_Addr      d_ptr;
    /// } d_un;
    /// it can be a pointer (which is an offset) (DT_STRTAB)
    /// or simply a value (DT_NEEDED)
    d_thing: u64,
}

#[derive(Debug, PartialEq, Clone)]
enum DynSectionTag {
    DtNeeded,
    /// This marks the offset from the beggining of the file
    /// to the string tab where we will eventually find the libraries
    /// names
    DtStrTab,
    /// The size (in bytes) off string table
    DtStrSz,
    Irrelevant,
}

impl From<u64> for DynSectionTag {
    fn from(value: u64) -> Self {
        match value {
            0x01 => Self::DtNeeded,
            0x05 => Self::DtStrTab,
            0xa => Self::DtStrSz,
            _ => Self::Irrelevant,
        }
    }
}

#[derive(Debug)]
pub struct DynamicSectionCriticals {
    /// The dynamic section element(s) which represent the
    /// needed libraries
    dt_needed: Vec<DynSectionElement>,
    /// The dynamic section element which represents
    /// the dt_strtab
    dt_strtab: DynSectionElement,
    /// The size in bytes of the string table
    dt_strsz: u64,
}
