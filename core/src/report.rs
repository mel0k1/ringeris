use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    ScanStarted {
        target: String,
        signatures: usize,
    },
    Progress {
        scanned: u64,
        threats: u64,
        current: String,
    },
    Threat {
        path: String,
        name: String,
        kind: String,
        size: u64,
        md5: String,
        sha256: String,
        container: Option<String>,
    },
    FileSkipped {
        path: String,
        reason: String,
    },
    ScanDone {
        scanned: u64,
        threats: u64,
        skipped: u64,
        duration_ms: u64,
    },
    WatchStarted {
        paths: Vec<String>,
    },
    WatchEvent {
        path: String,
        verdict: String,
        name: Option<String>,
        kind: Option<String>,
        time_ms: u64,
    },
    QuarantineMoved {
        from: String,
        to: String,
    },
    QuarantineList {
        entries: Vec<crate::quarantine::Entry>,
    },
    QuarantineDone {
        action: String,
        file: String,
        message: Option<String>,
    },
    UpdateStarted {
        database: String,
    },
    UpdateDone {
        database: String,
        version: u32,
        build_time: String,
    },
    UpdateError {
        message: String,
    },
    DbInfo {
        path: String,
        signatures: usize,
        hash_signatures: usize,
        patterns: usize,
        logical: usize,
        sections: usize,
        whitelist: usize,
        databases: Vec<crate::cvd::CvdInfo>,
        parsed_files: Vec<String>,
    },
    Error {
        message: String,
    },
}

pub fn emit(event: &Event) {
    if let Ok(line) = serde_json::to_string(event) {
        println!("{line}");
    }
}
