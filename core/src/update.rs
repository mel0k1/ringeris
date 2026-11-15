use crate::cvd;
use crate::report::{emit, Event};
use crate::Result;
use std::path::Path;
use std::time::Duration;

const BASE: &str = "https://database.clamav.net";

pub fn run(db_dir: &Path) -> Result<()> {
    std::fs::create_dir_all(db_dir)?;
    let targets: Vec<(&str, bool)> = vec![("daily.cvd", true), ("main.cvd", false)];
    for (name, always) in targets {
        let dest = db_dir.join(name);
        if !always && dest.exists() {
            continue;
        }
        emit(&Event::UpdateStarted {
            database: name.to_string(),
        });
        match download(&format!("{BASE}/{name}"), &dest) {
            Ok(()) => {
                let info = cvd::read_info(&dest)?;
                emit(&Event::UpdateDone {
                    database: name.to_string(),
                    version: info.version,
                    build_time: info.build_time,
                });
            }
            Err(e) => {
                emit(&Event::UpdateError {
                    message: format!("{name}: {e}"),
                });
                return Err(crate::RingerisError::Update(e.to_string()));
            }
        }
    }
    Ok(())
}

fn download(url: &str, dest: &Path) -> Result<()> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(600))
        .user_agent("ClamAV/1.4.2 (Ringeris)")
        .build()
        .map_err(|e| crate::RingerisError::Update(e.to_string()))?;
    let response = client
        .get(url)
        .send()
        .map_err(|e| crate::RingerisError::Update(e.to_string()))?;
    if !response.status().is_success() {
        return Err(crate::RingerisError::Update(format!(
            "http status {}",
            response.status()
        )));
    }
    let bytes = response
        .bytes()
        .map_err(|e| crate::RingerisError::Update(e.to_string()))?;
    let tmp = dest.with_extension("tmp");
    std::fs::write(&tmp, &bytes)?;
    let lower = dest.to_string_lossy().to_lowercase();
    if (lower.ends_with(".cvd") || lower.ends_with(".cld")) && !crate::cvd::body_md5_valid(&tmp)? {
        let _ = std::fs::remove_file(&tmp);
        return Err(crate::RingerisError::Update(format!(
            "checksum mismatch for {}",
            dest.display()
        )));
    }
    if dest.exists() {
        std::fs::remove_file(dest)?;
    }
    std::fs::rename(&tmp, dest)?;
    Ok(())
}
