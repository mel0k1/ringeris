use crate::hashdb::HashDatabase;
use crate::sigdb::SigDb;
use crate::Result;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

const SIG_EXTENSIONS: [&str; 8] = [
    ".hdb", ".hsb", ".fp", ".sfp", ".ndb", ".ldb", ".mdb", ".msb",
];

pub struct Database {
    pub hashes: HashDatabase,
    pub patterns: SigDb,
}

impl Database {
    pub fn new() -> Self {
        Database {
            hashes: HashDatabase::new(),
            patterns: SigDb::new(),
        }
    }

    pub fn load_dir(&mut self, dir: &Path) -> Result<usize> {
        let mut count = 0;
        if !dir.is_dir() {
            return Ok(0);
        }
        let read = match std::fs::read_dir(dir) {
            Ok(r) => r,
            Err(e) => {
                self.hashes
                    .register_load_error(format!("read_dir {}: {e}", dir.display()));
                return Ok(0);
            }
        };
        let mut files: Vec<_> = read.flatten().map(|e| e.path()).collect();
        files.sort();
        for path in files {
            let name = path
                .file_name()
                .map(|v| v.to_string_lossy().to_lowercase())
                .unwrap_or_default();
            if !is_signature_file(&name) {
                continue;
            }
            if name.ends_with(".cvd") || name.ends_with(".cld") {
                match self.load_container(&path) {
                    Ok(n) => count += n,
                    Err(e) => self.hashes.register_load_error(format!("{name}: {e}")),
                }
            } else if name.ends_with(".ndb")
                || name.ends_with(".ldb")
                || name.ends_with(".mdb")
                || name.ends_with(".msb")
            {
                match std::fs::read_to_string(&path) {
                    Ok(text) => count += self.patterns.load_text(&name, &text),
                    Err(e) => self.hashes.register_load_error(format!("{name}: {e}")),
                }
            } else {
                count += self.hashes.load_plain_file(&path);
            }
        }
        self.patterns.finalize();
        Ok(count)
    }

    fn load_container(&mut self, path: &Path) -> Result<usize> {
        let mut handle = std::io::BufReader::new(std::fs::File::open(path)?);
        handle.seek(SeekFrom::Start(512))?;
        let mut magic = [0u8; 2];
        handle.read_exact(&mut magic)?;
        handle.seek(SeekFrom::Start(512))?;
        if magic == [0x1f, 0x8b] {
            self.load_gzip_tar(handle)
        } else {
            self.load_zip(handle)
        }
    }

    fn load_gzip_tar<R: Read>(&mut self, handle: R) -> Result<usize> {
        let decoder = flate2::read::GzDecoder::new(handle);
        let mut archive = tar::Archive::new(decoder);
        let mut count = 0;
        for member in archive.entries()? {
            let mut member = match member {
                Ok(m) => m,
                Err(_) => continue,
            };
            let member_name = member.path()?.to_string_lossy().to_string();
            if !is_signature_file(&member_name.to_lowercase()) {
                continue;
            }
            let mut text = String::new();
            if member.read_to_string(&mut text).is_err() {
                continue;
            }
            count += self.dispatch_member(&member_name, &text);
        }
        Ok(count)
    }

    fn load_zip<R: Read + Seek>(&mut self, handle: R) -> Result<usize> {
        let mut archive = zip::ZipArchive::new(handle)?;
        let mut count = 0;
        for i in 0..archive.len() {
            let mut member = match archive.by_index(i) {
                Ok(m) => m,
                Err(_) => continue,
            };
            let member_name = member.name().to_string();
            if !is_signature_file(&member_name.to_lowercase()) {
                continue;
            }
            let mut text = String::new();
            if member.read_to_string(&mut text).is_err() {
                continue;
            }
            count += self.dispatch_member(&member_name, &text);
        }
        Ok(count)
    }

    fn dispatch_member(&mut self, member_name: &str, text: &str) -> usize {
        let lower = member_name.to_lowercase();
        if lower.ends_with(".ndb")
            || lower.ends_with(".ldb")
            || lower.ends_with(".mdb")
            || lower.ends_with(".msb")
        {
            self.patterns.load_text(member_name, text)
        } else {
            self.hashes.load_container_member(member_name, text)
        }
    }

    pub fn total_signatures(&self) -> usize {
        self.hashes.total() + self.patterns.total()
    }

    pub fn whitelist_count(&self) -> usize {
        self.hashes.whitelist_count()
    }
}

impl Default for Database {
    fn default() -> Self {
        Self::new()
    }
}

pub fn is_signature_file(name: &str) -> bool {
    name.ends_with(".cvd")
        || name.ends_with(".cld")
        || SIG_EXTENSIONS.iter().any(|ext| name.ends_with(ext))
}
