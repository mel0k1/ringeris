use crate::Result;
use md5::Digest;
use serde::Serialize;
use std::path::Path;

#[derive(Debug, Clone, Serialize)]
pub struct CvdInfo {
    pub file: String,
    pub version: u32,
    pub build_time: String,
    pub signatures: u64,
}

pub fn read_info(path: &Path) -> Result<CvdInfo> {
    let mut file = std::fs::File::open(path)?;
    let mut buf = vec![0u8; 512];
    std::io::Read::read_exact(&mut file, &mut buf)?;
    let text = String::from_utf8_lossy(&buf);
    let mut version = 0;
    let mut build_time = String::new();
    let mut signatures = 0;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("ClamAV-VDB:") {
            let fields: Vec<&str> = value.trim().split(':').collect();
            if fields.len() >= 4 {
                if let Ok(v) = fields[1].trim().parse::<u32>() {
                    version = v;
                }
                if let Ok(s) = fields[2].trim().parse::<u64>() {
                    signatures = s;
                }
                build_time = fields[0].trim().to_string();
            } else {
                build_time = value.trim().to_string();
            }
        } else if let Some(value) = line.strip_prefix("Version:") {
            version = value.trim().parse().unwrap_or(version);
        } else if let Some(value) = line.strip_prefix("Number of Signatures:") {
            signatures = value.trim().parse().unwrap_or(signatures);
        }
    }
    let file_name = path
        .file_name()
        .map(|v| v.to_string_lossy().to_string())
        .unwrap_or_default();
    Ok(CvdInfo {
        file: file_name,
        version,
        build_time,
        signatures,
    })
}

pub fn is_hash_database_name(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower.ends_with(".hdb") || lower.ends_with(".hsb")
}

pub fn is_database_container_name(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower.ends_with(".cvd") || lower.ends_with(".cld")
}

pub fn body_md5_valid(path: &Path) -> Result<bool> {
    let mut file = std::io::BufReader::new(std::fs::File::open(path)?);
    let mut header = vec![0u8; 512];
    std::io::Read::read_exact(&mut file, &mut header)?;
    let text = String::from_utf8_lossy(&header);
    let mut stated = "";
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("ClamAV-VDB:") {
            stated = value.split(':').nth(4).unwrap_or("");
        }
    }
    if stated.is_empty() {
        return Ok(false);
    }
    let mut hasher = md5::Md5::new();
    std::io::copy(&mut file, &mut hasher)?;
    Ok(hex::encode(hasher.finalize()) == stated.to_lowercase())
}
