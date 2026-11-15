use crate::hashes;
use crate::quarantine::{now_ms, Quarantine};
use crate::report::{emit, Event};
use crate::scanner::{Engine, Sink};
use notify::{EventKind, RecursiveMode, Watcher};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::{channel, RecvTimeoutError};
use std::sync::Arc;
use std::time::{Duration, Instant};

const QUIET: Duration = Duration::from_millis(800);
const TICK: Duration = Duration::from_millis(200);
const MIN_WATCH_SIZE: u64 = 64;

const PARTIAL_EXTENSIONS: [&str; 5] = ["crdownload", "part", "partial", "tmp", "download"];

pub fn should_inspect(path: &Path, size: u64) -> bool {
    if size < MIN_WATCH_SIZE {
        return false;
    }
    let extension = path
        .extension()
        .map(|v| v.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    !PARTIAL_EXTENSIONS.contains(&extension.as_str())
}

pub fn run(
    engine: &Arc<Engine>,
    dirs: Vec<PathBuf>,
    quarantine: Option<Quarantine>,
) -> crate::Result<()> {
    let (tx, rx) = channel::<std::result::Result<notify::Event, notify::Error>>();
    let mut watcher =
        notify::recommended_watcher(tx).map_err(|e| crate::RingerisError::Notify(e.to_string()))?;
    let mut watched: Vec<String> = Vec::new();
    for dir in &dirs {
        if dir.is_dir() {
            match watcher.watch(dir, RecursiveMode::NonRecursive) {
                Ok(()) => watched.push(dir.display().to_string()),
                Err(e) => emit(&Event::Error {
                    message: format!("{}: {e}", dir.display()),
                }),
            }
        }
    }
    if watched.is_empty() {
        return Err(crate::RingerisError::Notify("no watch folders".to_string()));
    }
    emit(&Event::WatchStarted { paths: watched });
    let cancel = Arc::new(AtomicBool::new(false));
    let mut pending: HashMap<PathBuf, Instant> = HashMap::new();
    loop {
        match rx.recv_timeout(TICK) {
            Ok(Ok(event)) => {
                if matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_)) {
                    for path in event.paths {
                        if path.is_dir() {
                            continue;
                        }
                        if engine.excluded(&path) {
                            continue;
                        }
                        pending.insert(path, Instant::now());
                    }
                }
            }
            Ok(Err(e)) => emit(&Event::Error {
                message: e.to_string(),
            }),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return Ok(()),
        }
        flush(engine, &mut pending, quarantine.as_ref(), cancel.clone());
    }
}

fn flush(
    engine: &Arc<Engine>,
    pending: &mut HashMap<PathBuf, Instant>,
    quarantine: Option<&Quarantine>,
    cancel: Arc<AtomicBool>,
) {
    let now = Instant::now();
    let due: Vec<PathBuf> = pending
        .iter()
        .filter(|(_, t)| now.duration_since(**t) >= QUIET)
        .map(|(p, _)| p.clone())
        .collect();
    if due.is_empty() {
        return;
    }
    for path in due {
        pending.remove(&path);
        inspect(engine, &path, quarantine, &cancel);
    }
}

fn inspect(
    engine: &Arc<Engine>,
    path: &Path,
    quarantine: Option<&Quarantine>,
    cancel: &Arc<AtomicBool>,
) {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return;
    };
    if !meta.is_file() || !should_inspect(path, meta.len()) {
        return;
    }
    if engine.excluded(path) {
        return;
    }
    let label = path.display().to_string();
    let (tx, rx) = channel();
    let sink = Sink::new(tx, cancel.clone());
    engine.inspect_file(path, None, 0, &sink);
    let mut threat: Option<(String, String)> = None;
    while let Ok(event) = rx.try_recv() {
        match event {
            Event::Threat { name, kind, .. } => {
                if threat.is_none() {
                    threat = Some((name, kind));
                }
            }
            Event::FileSkipped { .. } => {}
            _ => emit(&Event::Error {
                message: "unexpected event in watcher".to_string(),
            }),
        }
    }
    match threat {
        Some((name, kind)) => {
            if let Some(quarantine) = quarantine {
                if let Ok(file_hashes) = hashes::compute_file(path) {
                    match quarantine.capture(path, &file_hashes) {
                        Ok(dest) => emit(&Event::QuarantineMoved {
                            from: label.clone(),
                            to: dest.display().to_string(),
                        }),
                        Err(e) => emit(&Event::Error {
                            message: e.to_string(),
                        }),
                    }
                }
            }
            emit(&Event::WatchEvent {
                path: label,
                verdict: "threat".to_string(),
                name: Some(name),
                kind: Some(kind),
                time_ms: now_ms(),
            });
        }
        None => emit(&Event::WatchEvent {
            path: label,
            verdict: "clean".to_string(),
            name: None,
            kind: None,
            time_ms: now_ms(),
        }),
    }
}

pub fn dedupe_dirs(dirs: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for dir in dirs {
        if dir.is_dir() && seen.insert(dir.clone()) {
            out.push(dir);
        }
    }
    out
}
