use md5::Md5;
use sha2::{Digest as _, Sha256};
use std::io::Read;
use std::path::Path;

const CHUNK: usize = 64 * 1024;

pub struct FileHashes {
    pub md5: String,
    pub sha256: String,
    pub size: u64,
}

pub fn compute_bytes(data: &[u8]) -> FileHashes {
    let mut md5 = Md5::new();
    let mut sha = Sha256::new();
    md5.update(data);
    sha.update(data);
    FileHashes {
        md5: hex::encode(md5.finalize()),
        sha256: hex::encode(sha.finalize()),
        size: data.len() as u64,
    }
}

pub fn compute<R: Read>(mut reader: R) -> std::io::Result<FileHashes> {
    let mut md5 = Md5::new();
    let mut sha = Sha256::new();
    let mut size = 0u64;
    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        md5.update(&buf[..n]);
        sha.update(&buf[..n]);
        size += n as u64;
    }
    Ok(FileHashes {
        md5: hex::encode(md5.finalize()),
        sha256: hex::encode(sha.finalize()),
        size,
    })
}

pub fn compute_file(path: &Path) -> std::io::Result<FileHashes> {
    let file = std::fs::File::open(path)?;
    compute(std::io::BufReader::new(file))
}
