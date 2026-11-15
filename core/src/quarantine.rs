use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub file: String,
    pub original_path: String,
    pub moved_at: u64,
    pub size: u64,
    pub md5: Option<String>,
    pub sha256: Option<String>,
}

pub struct Quarantine {
    dir: PathBuf,
}

impl Quarantine {
    pub fn new(dir: PathBuf) -> Self {
        let _ = std::fs::create_dir_all(&dir);
        Quarantine { dir }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn capture(
        &self,
        path: &Path,
        hashes: &crate::hashes::FileHashes,
    ) -> crate::Result<PathBuf> {
        let name = path
            .file_name()
            .map(|v| v.to_string_lossy().to_string())
            .unwrap_or_else(|| "unnamed".to_string());
        let stamp = now_ms();
        let stored = format!("{name}.{stamp}.quar");
        let dest = self.dir.join(&stored);
        if std::fs::rename(path, &dest).is_err() {
            std::fs::copy(path, &dest)?;
            let _ = std::fs::remove_file(path);
        }
        let meta = Entry {
            file: stored,
            original_path: path.display().to_string(),
            moved_at: stamp,
            size: hashes.size,
            md5: Some(hashes.md5.clone()),
            sha256: Some(hashes.sha256.clone()),
        };
        let meta_path = self.dir.join(format!("{}.meta.json", meta.file));
        std::fs::write(&meta_path, serde_json::to_vec(&meta)?)?;
        Ok(dest)
    }

    pub fn list(&self) -> Vec<Entry> {
        let mut out = Vec::new();
        let read = match std::fs::read_dir(&self.dir) {
            Ok(r) => r,
            Err(_) => return out,
        };
        for entry in read.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if !name.ends_with(".meta.json") {
                continue;
            }
            if let Ok(text) = std::fs::read_to_string(entry.path()) {
                if let Ok(meta) = serde_json::from_str::<Entry>(&text) {
                    out.push(meta);
                }
            }
        }
        out.sort_by_key(|entry| std::cmp::Reverse(entry.moved_at));
        out
    }

    pub fn restore(&self, file: &str) -> std::io::Result<PathBuf> {
        let meta = self.read_meta(file)?;
        let dest = PathBuf::from(&meta.original_path);
        let final_dest = if dest.exists() {
            PathBuf::from(format!("{}.__restored", dest.display()))
        } else {
            dest
        };
        if let Some(parent) = final_dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::rename(self.dir.join(file), &final_dest)?;
        let _ = std::fs::remove_file(self.dir.join(format!("{file}.meta.json")));
        Ok(final_dest)
    }

    pub fn remove(&self, file: &str) -> std::io::Result<()> {
        std::fs::remove_file(self.dir.join(file))?;
        let _ = std::fs::remove_file(self.dir.join(format!("{file}.meta.json")));
        Ok(())
    }

    fn read_meta(&self, file: &str) -> std::io::Result<Entry> {
        let path = self.dir.join(format!("{file}.meta.json"));
        if !path.exists() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "quarantine entry not found",
            ));
        }
        let text = std::fs::read_to_string(path)?;
        serde_json::from_str::<Entry>(&text)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
