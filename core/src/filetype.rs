#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Unknown,
    Pe,
    Elf,
    Ole2,
    Zip,
    Gzip,
    Tar,
    Cab,
    SevenZip,
    Rar,
    Pdf,
    Html,
    Text,
}

impl Kind {
    pub fn match_target(self) -> u32 {
        match self {
            Kind::Pe => 1,
            Kind::Ole2 => 2,
            Kind::Html => 3,
            Kind::Elf => 6,
            Kind::Text => 7,
            Kind::Pdf => 10,
            _ => 255,
        }
    }

    pub fn is_archive(self) -> bool {
        matches!(
            self,
            Kind::Zip | Kind::Gzip | Kind::Tar | Kind::Cab | Kind::SevenZip
        )
    }
}

fn looks_like_text(data: &[u8]) -> bool {
    let limit = data.len().min(4096);
    if limit == 0 {
        return false;
    }
    let sample = &data[..limit];
    let nul = sample.iter().filter(|&&b| b == 0).count();
    nul * 20 < limit
}

fn looks_like_html(data: &[u8]) -> bool {
    let limit = data.len().min(2048);
    let sample = &data[..limit];
    let lower = sample.to_ascii_lowercase();
    let text = String::from_utf8_lossy(&lower);
    for marker in [
        "<!doctype html",
        "<html",
        "<head",
        "<body",
        "<script",
        "<iframe",
        "<a href",
    ] {
        if text.contains(marker) {
            return true;
        }
    }
    false
}

pub fn detect(data: &[u8]) -> Kind {
    if data.len() >= 2 && data[0] == b'M' && data[1] == b'Z' {
        if data.len() >= 64 {
            let lfanew =
                u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
            if lfanew > 0 && lfanew + 4 <= data.len() && &data[lfanew..lfanew + 4] == b"PE\0\0" {
                return Kind::Pe;
            }
        }
        return Kind::Unknown;
    }
    if data.len() >= 8 && data[..8] == [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1] {
        return Kind::Ole2;
    }
    if data.len() >= 4 && data[..4] == [0x7f, b'E', b'L', b'F'] {
        return Kind::Elf;
    }
    if data.len() >= 4 && data[..4] == [0x50, 0x4b, 0x03, 0x04] {
        return Kind::Zip;
    }
    if data.len() >= 2 && data[..2] == [0x1f, 0x8b] {
        return Kind::Gzip;
    }
    if data.len() >= 4 && data[..4] == b"MSCF"[..] {
        return Kind::Cab;
    }
    if data.len() >= 6 && data[..6] == [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c] {
        return Kind::SevenZip;
    }
    if data.len() >= 6 && (data[..6] == b"Rar!\x1a\x07"[..] || data[..6] == b"Rar!\x1a\x06"[..]) {
        return Kind::Rar;
    }
    if data.len() >= 5 && data[..5] == b"%PDF-"[..] {
        return Kind::Pdf;
    }
    if looks_like_text(data) {
        if looks_like_html(data) {
            return Kind::Html;
        }
        return Kind::Text;
    }
    Kind::Unknown
}
