#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_pointer: u32,
    pub raw_size: u32,
}

#[derive(Debug, Clone)]
pub struct Image {
    pub entry_point_offset: Option<u64>,
    pub sections: Vec<Section>,
}

impl Image {
    pub fn parse(data: &[u8]) -> Option<Image> {
        if data.len() < 64 || data[0] != b'M' || data[1] != b'Z' {
            return None;
        }
        let lfanew = u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
        if lfanew == 0 || lfanew + 24 > data.len() || &data[lfanew..lfanew + 4] != b"PE\0\0" {
            return None;
        }
        let coff = lfanew + 4;
        let section_count = u16::from_le_bytes([data[coff + 2], data[coff + 3]]) as usize;
        let optional_size = u16::from_le_bytes([data[coff + 16], data[coff + 17]]) as usize;
        let optional = coff + 20;
        if optional + 2 > data.len() {
            return None;
        }
        let magic = u16::from_le_bytes([data[optional], data[optional + 1]]);
        if magic != 0x10b && magic != 0x20b {
            return None;
        }
        if optional + 24 > data.len() {
            return None;
        }
        let entry_rva = u32::from_le_bytes([
            data[optional + 16],
            data[optional + 17],
            data[optional + 18],
            data[optional + 19],
        ]);
        let sections_at = optional + optional_size;
        let section_bytes = section_count.checked_mul(40)?;
        if sections_at + section_bytes > data.len() {
            return None;
        }
        let mut sections = Vec::with_capacity(section_count);
        for i in 0..section_count {
            let base = sections_at + i * 40;
            let name = String::from_utf8_lossy(&data[base..base + 8])
                .trim_end_matches(['\0'])
                .to_string();
            let virtual_size = u32::from_le_bytes(data[base + 8..base + 12].try_into().ok()?);
            let virtual_address = u32::from_le_bytes(data[base + 12..base + 16].try_into().ok()?);
            let raw_size = u32::from_le_bytes(data[base + 16..base + 20].try_into().ok()?);
            let raw_pointer = u32::from_le_bytes(data[base + 20..base + 24].try_into().ok()?);
            sections.push(Section {
                name,
                virtual_address,
                virtual_size,
                raw_pointer,
                raw_size,
            });
        }
        let entry_point_offset = Self::rva_to_offset(&sections, data.len() as u64, entry_rva);
        Some(Image {
            entry_point_offset,
            sections,
        })
    }

    fn rva_to_offset(sections: &[Section], file_len: u64, rva: u32) -> Option<u64> {
        for section in sections {
            let start = section.virtual_address;
            let end = start.saturating_add(section.virtual_size.max(section.raw_size));
            if rva >= start && rva < end {
                let delta = rva - start;
                let offset = section.raw_pointer as u64 + delta as u64;
                if offset < file_len {
                    return Some(offset);
                }
                return None;
            }
        }
        None
    }

    pub fn last_section(&self) -> Option<&Section> {
        self.sections.last()
    }

    pub fn section_start_offset(&self, index: usize) -> Option<u64> {
        let section = self.sections.get(index)?;
        if section.raw_pointer == 0 {
            return None;
        }
        Some(section.raw_pointer as u64)
    }
}
