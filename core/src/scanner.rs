use crate::db::Database;
use crate::filetype::{self, Kind};
use crate::hashdb::HashKind;
use crate::hashes;
use crate::pe;
use crate::report::Event;
use std::collections::VecDeque;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use walkdir::WalkDir;

const MAX_BOMB_RATIO: u64 = 500;
const PROGRESS_EVERY: u64 = 50;
const QUEUE_LIMIT: usize = 20000;

pub struct ScanOptions {
    pub max_file_size: u64,
    pub max_archive_depth: u8,
    pub max_archive_entries: usize,
    pub exclusions: Vec<String>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        ScanOptions {
            max_file_size: 64 * 1024 * 1024,
            max_archive_depth: 3,
            max_archive_entries: 10000,
            exclusions: Vec::new(),
        }
    }
}

pub struct ScanOutcome {
    pub scanned: u64,
    pub threats: u64,
    pub skipped: u64,
    pub duration_ms: u64,
}

pub struct Engine {
    pub db: Arc<Database>,
    pub options: ScanOptions,
}

impl Engine {
    pub fn new(db: Arc<Database>, options: ScanOptions) -> Self {
        Engine { db, options }
    }

    pub fn excluded(&self, path: &Path) -> bool {
        if self.options.exclusions.is_empty() {
            return false;
        }
        let text = path.to_string_lossy().to_lowercase();
        self.options
            .exclusions
            .iter()
            .any(|needle| !needle.is_empty() && text.contains(needle))
    }

    pub fn inspect_file(&self, path: &Path, container: Option<String>, depth: u8, sink: &Sink) {
        let label = path.display().to_string();
        let meta = match std::fs::symlink_metadata(path) {
            Ok(m) => m,
            Err(_) => {
                sink.skip(&label, "io");
                return;
            }
        };
        if !meta.is_file() {
            return;
        }
        if meta.len() > self.options.max_file_size {
            sink.skip(&label, "size");
            return;
        }
        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(_) => {
                sink.skip(&label, "io");
                return;
            }
        };
        if filetype::detect(&data) == Kind::SevenZip {
            self.inspect_sevenz_file(path, &data, &label, container, depth, sink);
            return;
        }
        self.inspect_bytes(&data, &label, container, depth, sink);
    }

    fn inspect_sevenz_file(
        &self,
        path: &Path,
        data: &[u8],
        label: &str,
        container: Option<String>,
        depth: u8,
        sink: &Sink,
    ) {
        let file_hashes = hashes::compute_bytes(data);
        sink.scanned();
        let mut findings: Vec<(String, String)> = Vec::new();
        for (hash_kind, value) in [
            (HashKind::Md5, file_hashes.md5.as_str()),
            (HashKind::Sha256, file_hashes.sha256.as_str()),
        ] {
            if let Some(entry) = self.db.hashes.lookup(hash_kind, value, file_hashes.size) {
                findings.push((entry.name.clone(), "hash".to_string()));
            }
        }
        if !findings.is_empty() {
            sink.threat(
                label.to_string(),
                findings,
                file_hashes.size,
                file_hashes.md5.clone(),
                file_hashes.sha256.clone(),
                container,
            );
        }
        if depth >= self.options.max_archive_depth || sink.cancelled() {
            return;
        }
        let mut archive =
            match sevenz_rust::SevenZReader::open(path, sevenz_rust::Password::empty()) {
                Ok(a) => a,
                Err(_) => {
                    sink.skip(label, "archive");
                    return;
                }
            };
        let _ = archive.for_each_entries(|entry, reader| {
            if sink.cancelled() {
                return Ok(false);
            }
            if entry.is_directory || entry.size > self.options.max_file_size {
                return Ok(true);
            }
            let sub_label = format!("{label}!{}", entry.name);
            let mut buffer = Vec::with_capacity(entry.size as usize);
            if reader.read_to_end(&mut buffer).is_err() {
                sink.skip(&sub_label, "read");
                return Ok(true);
            }
            self.inspect_bytes(
                &buffer,
                &sub_label,
                Some(label.to_string()),
                depth + 1,
                sink,
            );
            Ok(true)
        });
    }

    pub fn inspect_bytes(
        &self,
        data: &[u8],
        label: &str,
        container: Option<String>,
        depth: u8,
        sink: &Sink,
    ) {
        let file_hashes = hashes::compute_bytes(data);
        sink.scanned();
        if self
            .db
            .hashes
            .is_whitelisted(&file_hashes.md5, &file_hashes.sha256, file_hashes.size)
        {
            return;
        }
        let kind = filetype::detect(data);
        let image = if kind == Kind::Pe {
            pe::Image::parse(data)
        } else {
            None
        };
        let target = kind.match_target();
        let mut findings: Vec<(String, String)> = Vec::new();
        for (hash_kind, value) in [
            (HashKind::Md5, file_hashes.md5.as_str()),
            (HashKind::Sha256, file_hashes.sha256.as_str()),
        ] {
            if let Some(entry) = self.db.hashes.lookup(hash_kind, value, file_hashes.size) {
                findings.push((entry.name.clone(), "hash".to_string()));
            }
        }
        for detection in self.db.patterns.scan_buffer(data, target, image.as_ref()) {
            findings.push((detection.name, detection.kind));
        }
        if !findings.is_empty() {
            sink.threat(
                label.to_string(),
                findings,
                file_hashes.size,
                file_hashes.md5.clone(),
                file_hashes.sha256.clone(),
                container,
            );
        }
        if sink.cancelled() {
            return;
        }
        if depth < self.options.max_archive_depth && kind.is_archive() {
            self.open_archive(data, kind, label, depth, sink, file_hashes.size);
        }
    }

    fn open_archive(
        &self,
        data: &[u8],
        kind: Kind,
        label: &str,
        depth: u8,
        sink: &Sink,
        compressed_size: u64,
    ) {
        match kind {
            Kind::Zip => self.scan_zip(data, label, depth, sink, compressed_size),
            Kind::Cab => self.scan_cab(data, label, depth, sink, compressed_size),
            Kind::Gzip => self.scan_gzip(data, label, depth, sink, compressed_size),
            Kind::Tar => self.scan_tar(data, label, depth, sink, compressed_size),
            _ => {}
        }
    }

    fn scan_zip(&self, data: &[u8], label: &str, depth: u8, sink: &Sink, compressed_size: u64) {
        let cursor = Cursor::new(data);
        let mut archive = match zip::ZipArchive::new(cursor) {
            Ok(a) => a,
            Err(_) => {
                sink.skip(label, "archive");
                return;
            }
        };
        if archive.len() > self.options.max_archive_entries {
            sink.skip(label, "entries");
            return;
        }
        let count = archive.len();
        let mut members: Vec<(usize, u64)> = Vec::new();
        let mut total_uncompressed = 0u64;
        for i in 0..count {
            if let Ok(member) = archive.by_index_raw(i) {
                total_uncompressed += member.size();
                members.push((i, member.size()));
            }
        }
        if compressed_size > 0 && total_uncompressed / compressed_size.max(1) > MAX_BOMB_RATIO {
            sink.skip(label, "bomb");
            return;
        }
        for (i, size) in members {
            if sink.cancelled() {
                return;
            }
            if size > self.options.max_file_size {
                continue;
            }
            let sub_label = match archive.by_index(i) {
                Ok(member) => format!("{label}!{}", member.name()),
                Err(_) => continue,
            };
            let mut buffer = Vec::with_capacity(size as usize);
            match archive.by_index(i) {
                Ok(mut member) => {
                    if member.read_to_end(&mut buffer).is_err() {
                        sink.skip(&sub_label, "read");
                        continue;
                    }
                }
                Err(_) => continue,
            }
            self.inspect_bytes(
                &buffer,
                &sub_label,
                Some(label.to_string()),
                depth + 1,
                sink,
            );
        }
    }

    fn scan_cab(&self, data: &[u8], label: &str, depth: u8, sink: &Sink, compressed_size: u64) {
        let cursor = Cursor::new(data);
        let mut cabinet = match cab::Cabinet::new(cursor) {
            Ok(c) => c,
            Err(_) => {
                sink.skip(label, "archive");
                return;
            }
        };
        let mut names: Vec<(String, u64)> = Vec::new();
        let mut total_uncompressed = 0u64;
        for folder in cabinet.folder_entries() {
            for file in folder.file_entries() {
                let size = file.uncompressed_size() as u64;
                total_uncompressed += size;
                names.push((file.name().to_string(), size));
            }
        }
        if compressed_size > 0 && total_uncompressed / compressed_size.max(1) > MAX_BOMB_RATIO {
            sink.skip(label, "bomb");
            return;
        }
        if names.len() > self.options.max_archive_entries {
            sink.skip(label, "entries");
            return;
        }
        for (name, size) in names {
            if sink.cancelled() {
                return;
            }
            if size > self.options.max_file_size {
                continue;
            }
            let sub_label = format!("{label}!{name}");
            let mut buffer = Vec::with_capacity(size as usize);
            match cabinet.read_file(&name) {
                Ok(mut reader) => {
                    if reader.read_to_end(&mut buffer).is_err() {
                        sink.skip(&sub_label, "read");
                        continue;
                    }
                }
                Err(_) => {
                    sink.skip(&sub_label, "read");
                    continue;
                }
            }
            self.inspect_bytes(
                &buffer,
                &sub_label,
                Some(label.to_string()),
                depth + 1,
                sink,
            );
        }
    }

    fn scan_gzip(&self, data: &[u8], label: &str, depth: u8, sink: &Sink, compressed_size: u64) {
        let decoder = flate2::read::GzDecoder::new(Cursor::new(data));
        let mut reader = decoder.take(self.options.max_file_size);
        let mut buffer = Vec::new();
        if reader.read_to_end(&mut buffer).is_err() {
            sink.skip(label, "archive");
            return;
        }
        if compressed_size > 0 && buffer.len() as u64 / compressed_size.max(1) > MAX_BOMB_RATIO {
            sink.skip(label, "bomb");
            return;
        }
        let sub_label = format!("{label}!content");
        self.inspect_bytes(
            &buffer,
            &sub_label,
            Some(label.to_string()),
            depth + 1,
            sink,
        );
    }

    fn scan_tar(&self, data: &[u8], label: &str, depth: u8, sink: &Sink, compressed_size: u64) {
        if compressed_size > 0 && data.len() as u64 / compressed_size.max(1) > MAX_BOMB_RATIO {
            sink.skip(label, "bomb");
            return;
        }
        let cursor = Cursor::new(data);
        let mut archive = tar::Archive::new(cursor);
        let entries = match archive.entries() {
            Ok(e) => e,
            Err(_) => {
                sink.skip(label, "archive");
                return;
            }
        };
        for entry in entries {
            if sink.cancelled() {
                return;
            }
            let mut entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            let member_name = match entry.path() {
                Ok(p) => p.to_string_lossy().to_string(),
                Err(_) => continue,
            };
            if entry.header().entry_type().is_dir() {
                continue;
            }
            let size = entry.header().size().unwrap_or(0);
            if size > self.options.max_file_size {
                continue;
            }
            let sub_label = format!("{label}!{member_name}");
            let mut buffer = Vec::with_capacity(size as usize);
            if entry.read_to_end(&mut buffer).is_err() {
                sink.skip(&sub_label, "read");
                continue;
            }
            self.inspect_bytes(
                &buffer,
                &sub_label,
                Some(label.to_string()),
                depth + 1,
                sink,
            );
        }
    }
}

pub struct Sink {
    events: Sender<Event>,
    scanned: AtomicU64,
    threats: AtomicU64,
    skipped: AtomicU64,
    cancel: Arc<AtomicBool>,
    progress_lock: Mutex<()>,
}

impl Sink {
    pub fn new(events: Sender<Event>, cancel: Arc<AtomicBool>) -> Self {
        Sink {
            events,
            scanned: AtomicU64::new(0),
            threats: AtomicU64::new(0),
            skipped: AtomicU64::new(0),
            cancel,
            progress_lock: Mutex::new(()),
        }
    }

    pub fn scanned(&self) {
        let value = self.scanned.fetch_add(1, Ordering::Relaxed) + 1;
        if value.is_multiple_of(PROGRESS_EVERY) {
            let _guard = self.progress_lock.lock();
            let _ = self.events.send(Event::Progress {
                scanned: self.scanned.load(Ordering::Relaxed),
                threats: self.threats.load(Ordering::Relaxed),
                current: String::new(),
            });
        }
    }

    pub fn threat(
        &self,
        path: String,
        findings: Vec<(String, String)>,
        size: u64,
        md5: String,
        sha256: String,
        container: Option<String>,
    ) {
        self.threats.fetch_add(1, Ordering::Relaxed);
        for (name, kind) in findings {
            let _ = self.events.send(Event::Threat {
                path: path.clone(),
                name,
                kind,
                size,
                md5: md5.clone(),
                sha256: sha256.clone(),
                container: container.clone(),
            });
        }
    }

    pub fn skip(&self, path: &str, reason: &str) {
        self.skipped.fetch_add(1, Ordering::Relaxed);
        let _ = self.events.send(Event::FileSkipped {
            path: path.to_string(),
            reason: reason.to_string(),
        });
    }

    pub fn cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }

    pub fn totals(&self) -> (u64, u64, u64) {
        (
            self.scanned.load(Ordering::Relaxed),
            self.threats.load(Ordering::Relaxed),
            self.skipped.load(Ordering::Relaxed),
        )
    }
}

pub struct Scanner {
    engine: Arc<Engine>,
    cancel: Arc<AtomicBool>,
    walker_done: Arc<AtomicBool>,
    events: Sender<Event>,
}

impl Scanner {
    pub fn new(engine: Arc<Engine>, events: Sender<Event>) -> Self {
        Scanner {
            engine,
            cancel: Arc::new(AtomicBool::new(false)),
            walker_done: Arc::new(AtomicBool::new(false)),
            events,
        }
    }

    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }

    pub fn scan_path(&self, root: &Path) -> ScanOutcome {
        let started = Instant::now();
        self.walker_done.store(false, Ordering::SeqCst);
        let _ = self.events.send(Event::ScanStarted {
            target: root.display().to_string(),
            signatures: self.engine.db.total_signatures(),
        });
        let sink = Arc::new(Sink::new(self.events.clone(), self.cancel.clone()));
        let queue = Arc::new(Mutex::new(VecDeque::<PathBuf>::new()));
        if root.is_file() {
            self.engine.inspect_file(root, None, 0, &sink);
        } else {
            std::thread::scope(|scope| {
                let walker = scope.spawn(|| self.walk(root, queue.clone(), sink.clone()));
                let available = std::thread::available_parallelism()
                    .map(|v| v.get())
                    .unwrap_or(2);
                let workers = available.clamp(1, 8);
                let mut handles = Vec::new();
                for _ in 0..workers {
                    let queue = queue.clone();
                    let sink = sink.clone();
                    handles.push(scope.spawn(move || self.work(queue, sink)));
                }
                for handle in handles {
                    let _ = handle.join();
                }
                let _ = walker.join();
            });
        }
        let (scanned, threats, skipped) = sink.totals();
        ScanOutcome {
            scanned,
            threats,
            skipped,
            duration_ms: started.elapsed().as_millis() as u64,
        }
    }

    fn work(&self, queue: Arc<Mutex<VecDeque<PathBuf>>>, sink: Arc<Sink>) {
        loop {
            let next = {
                let mut guard = queue.lock().unwrap();
                guard.pop_front()
            };
            match next {
                Some(path) => self.engine.inspect_file(&path, None, 0, &sink),
                None => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                    let empty = { queue.lock().unwrap().is_empty() };
                    if empty && self.walker_done.load(Ordering::SeqCst) {
                        break;
                    }
                }
            }
        }
    }

    fn walk(&self, root: &Path, queue: Arc<Mutex<VecDeque<PathBuf>>>, sink: Arc<Sink>) {
        for entry in WalkDir::new(root).into_iter().filter_map(|e| e.ok()) {
            if self.cancel.load(Ordering::Relaxed) {
                break;
            }
            let path = entry.path();
            if self.engine.excluded(path) {
                if entry.file_type().is_dir() {
                    continue;
                }
                sink.skip(&path.display().to_string(), "excluded");
                continue;
            }
            if entry.file_type().is_file() {
                loop {
                    {
                        let mut guard = queue.lock().unwrap();
                        if guard.len() < QUEUE_LIMIT {
                            guard.push_back(path.to_path_buf());
                            break;
                        }
                    }
                    if self.cancel.load(Ordering::Relaxed) {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
            }
        }
        self.walker_done.store(true, Ordering::SeqCst);
    }
}
