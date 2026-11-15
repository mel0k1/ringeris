use clap::{Parser, Subcommand};
use ringeris_core::db::Database;
use ringeris_core::quarantine::Quarantine;
use ringeris_core::report::{emit, Event};
use ringeris_core::scanner::{Engine, ScanOptions, Scanner};
use ringeris_core::{targets, update, watcher};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::mpsc::channel;
use std::sync::Arc;
use std::time::Instant;

#[derive(Parser)]
#[command(name = "ringeris-core", version, about = "Ringeris antivirus core")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    #[command(name = "quick")]
    Quick(ScanArgs),
    #[command(name = "full")]
    Full(ScanArgs),
    #[command(name = "scan")]
    Scan {
        #[arg(long)]
        path: PathBuf,
        #[command(flatten)]
        args: ScanArgs,
    },
    #[command(name = "update")]
    Update {
        #[arg(long)]
        db: Option<PathBuf>,
    },
    #[command(name = "watch")]
    Watch {
        #[arg(long)]
        db: Option<PathBuf>,
        #[arg(long)]
        path: Vec<PathBuf>,
        #[arg(long, default_value_t = false)]
        no_quarantine: bool,
        #[arg(long = "exclude")]
        exclusions: Vec<String>,
    },
    #[command(name = "info")]
    Info {
        #[arg(long)]
        db: Option<PathBuf>,
    },
    #[command(name = "quarantine")]
    Quarantine {
        #[command(subcommand)]
        action: QuarantineAction,
    },
}

#[derive(Subcommand)]
enum QuarantineAction {
    #[command(name = "list")]
    List,
    #[command(name = "restore")]
    Restore {
        #[arg(default_value_t = String::new())]
        file: String,
    },
    #[command(name = "remove")]
    Remove {
        #[arg(default_value_t = String::new())]
        file: String,
    },
}

#[derive(clap::Args)]
struct ScanArgs {
    #[arg(long)]
    db: Option<PathBuf>,
    #[arg(long, default_value_t = 64 * 1024 * 1024)]
    max_file_size: u64,
    #[arg(long = "exclude")]
    exclusions: Vec<String>,
}

fn default_db() -> PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("Ringeris")
        .join("db")
}

fn quarantine_dir() -> PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("Ringeris")
        .join("quarantine")
}

fn load_database(path: &Path) -> Arc<Database> {
    let mut database = Database::new();
    match database.load_dir(path) {
        Ok(_) => {}
        Err(e) => emit(&Event::Error {
            message: e.to_string(),
        }),
    }
    for error in &database.hashes.load_errors {
        emit(&Event::Error {
            message: error.clone(),
        });
    }
    Arc::new(database)
}

fn build_engine(args: &ScanArgs, db: Option<&PathBuf>) -> Engine {
    let dir = db.cloned().unwrap_or_else(default_db);
    let database = load_database(&dir);
    let options = ScanOptions {
        max_file_size: args.max_file_size,
        exclusions: args.exclusions.iter().map(|v| v.to_lowercase()).collect(),
        ..ScanOptions::default()
    };
    Engine::new(database, options)
}

fn run_scan(args: ScanArgs, targets_list: Vec<PathBuf>) -> ExitCode {
    let engine = Arc::new(build_engine(&args, args.db.as_ref()));
    if engine.db.total_signatures() == 0 {
        emit(&Event::Error {
            message: "signature database is empty, run update first".to_string(),
        });
        return ExitCode::from(2);
    }
    let (tx, rx) = channel();
    let scanner = Scanner::new(engine, tx);
    let printer = std::thread::spawn(move || {
        for event in rx {
            emit(&event);
        }
    });
    let started = Instant::now();
    let mut scanned = 0;
    let mut threats = 0;
    let mut skipped = 0;
    for target in &targets_list {
        let outcome = scanner.scan_path(target);
        scanned += outcome.scanned;
        threats += outcome.threats;
        skipped += outcome.skipped;
    }
    drop(scanner);
    let _ = printer.join();
    emit(&Event::ScanDone {
        scanned,
        threats,
        skipped,
        duration_ms: started.elapsed().as_millis() as u64,
    });
    if threats > 0 {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Quick(args) => run_scan(args, targets::quick_targets()),
        Command::Full(args) => run_scan(args, targets::full_targets()),
        Command::Scan { path, args } => run_scan(args, vec![path]),
        Command::Update { db } => {
            let dir = db.unwrap_or_else(default_db);
            match update::run(&dir) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    emit(&Event::Error {
                        message: e.to_string(),
                    });
                    ExitCode::from(2)
                }
            }
        }
        Command::Watch {
            db,
            path,
            no_quarantine,
            exclusions,
        } => {
            let database = load_database(db.as_deref().unwrap_or(&default_db()));
            if database.total_signatures() == 0 {
                emit(&Event::Error {
                    message: "signature database is empty, run update first".to_string(),
                });
                return ExitCode::from(2);
            }
            let mut watch_dirs = path;
            if watch_dirs.is_empty() {
                if let Some(downloads) = dirs::download_dir() {
                    watch_dirs.push(downloads);
                }
                if let Some(temp) = std::env::var_os("TEMP").map(PathBuf::from) {
                    watch_dirs.push(temp);
                }
            }
            let watch_dirs = watcher::dedupe_dirs(watch_dirs);
            let options = ScanOptions {
                exclusions: exclusions.iter().map(|v| v.to_lowercase()).collect(),
                ..ScanOptions::default()
            };
            let engine = Arc::new(Engine::new(database, options));
            let quarantine = if no_quarantine {
                None
            } else {
                Some(Quarantine::new(quarantine_dir()))
            };
            match watcher::run(&engine, watch_dirs, quarantine) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    emit(&Event::Error {
                        message: e.to_string(),
                    });
                    ExitCode::from(2)
                }
            }
        }
        Command::Info { db } => {
            let dir = db.unwrap_or_else(default_db);
            let database = load_database(&dir);
            let mut databases = Vec::new();
            if let Ok(read) = std::fs::read_dir(&dir) {
                for entry in read.flatten() {
                    let name = entry.file_name().to_string_lossy().to_lowercase();
                    if name.ends_with(".cvd") || name.ends_with(".cld") {
                        if let Ok(info) = ringeris_core::cvd::read_info(&entry.path()) {
                            databases.push(info);
                        }
                    }
                }
            }
            databases.sort_by_key(|info| info.file.clone());
            emit(&Event::DbInfo {
                path: dir.display().to_string(),
                signatures: database.total_signatures(),
                hash_signatures: database.hashes.total(),
                patterns: database.patterns.pattern_count(),
                logical: database.patterns.logical_count(),
                sections: database.patterns.section_count(),
                whitelist: database.whitelist_count(),
                databases,
                parsed_files: {
                    let mut files = database.hashes.source_files.clone();
                    files.extend(database.patterns.source_files.iter().cloned());
                    files
                },
            });
            ExitCode::SUCCESS
        }
        Command::Quarantine { action } => match action {
            QuarantineAction::List => {
                let q = Quarantine::new(quarantine_dir());
                emit(&Event::QuarantineList { entries: q.list() });
                ExitCode::SUCCESS
            }
            QuarantineAction::Restore { file } => {
                let q = Quarantine::new(quarantine_dir());
                match q.restore(&file) {
                    Ok(dest) => {
                        emit(&Event::QuarantineDone {
                            action: "restore".to_string(),
                            file,
                            message: Some(dest.display().to_string()),
                        });
                        ExitCode::SUCCESS
                    }
                    Err(e) => {
                        emit(&Event::Error {
                            message: e.to_string(),
                        });
                        ExitCode::from(2)
                    }
                }
            }
            QuarantineAction::Remove { file } => {
                let q = Quarantine::new(quarantine_dir());
                match q.remove(&file) {
                    Ok(()) => {
                        emit(&Event::QuarantineDone {
                            action: "remove".to_string(),
                            file,
                            message: None,
                        });
                        ExitCode::SUCCESS
                    }
                    Err(e) => {
                        emit(&Event::Error {
                            message: e.to_string(),
                        });
                        ExitCode::from(2)
                    }
                }
            }
        },
    }
}
