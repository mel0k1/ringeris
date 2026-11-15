use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashKind {
    Md5,
    Sha256,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureEntry {
    pub size: Option<u64>,
    pub name: String,
}

#[derive(Debug, Default)]
pub struct HashDatabase {
    md5: HashMap<String, SignatureEntry>,
    sha256: HashMap<String, SignatureEntry>,
    whitelist: HashMap<String, Option<u64>>,
    pub source_files: Vec<String>,
    pub load_errors: Vec<String>,
}

impl HashDatabase {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load_plain_file(&mut self, path: &Path) -> usize {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) => {
                self.load_errors.push(format!("{}: {e}", path.display()));
                return 0;
            }
        };
        let name = path
            .file_name()
            .map(|v| v.to_string_lossy().to_string())
            .unwrap_or_default();
        let count = self.parse_text(&name, &text);
        if count > 0 {
            self.source_files.push(name);
        }
        count
    }

    pub fn load_container_member(&mut self, file_name: &str, text: &str) -> usize {
        let count = self.parse_text(file_name, text);
        if count > 0 {
            self.source_files.push(file_name.to_string());
        }
        count
    }

    pub fn register_load_error(&mut self, message: String) {
        self.load_errors.push(message);
    }

    fn parse_text(&mut self, file_name: &str, text: &str) -> usize {
        let lower = file_name.to_lowercase();
        if lower.ends_with(".fp") || lower.ends_with(".sfp") {
            return self.parse_whitelist(text);
        }
        if !lower.ends_with(".hdb") && !lower.ends_with(".hsb") {
            return 0;
        }
        let mut count = 0;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let mut parts = line.splitn(3, ':');
            let hash = parts.next().unwrap_or("").trim().to_lowercase();
            let size_raw = parts.next().unwrap_or("").trim();
            let name = parts.next().unwrap_or("").trim();
            if name.is_empty() || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
                continue;
            }
            if hash.len() != 32 && hash.len() != 64 {
                continue;
            }
            let size = if size_raw == "*" {
                None
            } else {
                match size_raw.parse::<u64>() {
                    Ok(v) => Some(v),
                    Err(_) => continue,
                }
            };
            let entry = SignatureEntry {
                size,
                name: name.to_string(),
            };
            match hash.len() {
                32 => {
                    self.md5.insert(hash, entry);
                    count += 1;
                }
                64 => {
                    self.sha256.insert(hash, entry);
                    count += 1;
                }
                _ => {}
            }
        }
        count
    }

    fn parse_whitelist(&mut self, text: &str) -> usize {
        let mut count = 0;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let mut parts = line.splitn(3, ':');
            let hash = parts.next().unwrap_or("").trim().to_lowercase();
            let size_raw = parts.next().unwrap_or("").trim();
            if !hash.chars().all(|c| c.is_ascii_hexdigit()) {
                continue;
            }
            if hash.len() != 32 && hash.len() != 64 {
                continue;
            }
            let size = if size_raw == "*" {
                None
            } else {
                match size_raw.parse::<u64>() {
                    Ok(v) => Some(v),
                    Err(_) => continue,
                }
            };
            self.whitelist.insert(hash, size);
            count += 1;
        }
        count
    }

    pub fn lookup(&self, kind: HashKind, value: &str, size: u64) -> Option<&SignatureEntry> {
        let map = match kind {
            HashKind::Md5 => &self.md5,
            HashKind::Sha256 => &self.sha256,
        };
        let entry = map.get(value)?;
        if entry.size.is_none() || entry.size == Some(size) {
            Some(entry)
        } else {
            None
        }
    }

    pub fn is_whitelisted(&self, md5: &str, sha256: &str, size: u64) -> bool {
        for value in [md5, sha256] {
            if let Some(entry_size) = self.whitelist.get(value) {
                if entry_size.is_none() || *entry_size == Some(size) {
                    return true;
                }
            }
        }
        false
    }

    pub fn total(&self) -> usize {
        self.md5.len() + self.sha256.len()
    }

    pub fn whitelist_count(&self) -> usize {
        self.whitelist.len()
    }
}
