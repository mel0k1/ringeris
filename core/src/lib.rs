pub mod cvd;
pub mod db;
pub mod filetype;
pub mod hashdb;
pub mod hashes;
pub mod pattern;
pub mod pe;
pub mod quarantine;
pub mod report;
pub mod scanner;
pub mod sigdb;
pub mod targets;
pub mod update;
pub mod watcher;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum RingerisError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("zip error: {0}")]
    Zip(#[from] zip::result::ZipError),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("database error: {0}")]
    Database(String),
    #[error("update error: {0}")]
    Update(String),
    #[error("watcher error: {0}")]
    Notify(String),
}

pub type Result<T> = std::result::Result<T, RingerisError>;
