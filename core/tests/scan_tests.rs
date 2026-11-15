use ringeris_core::db::Database;
use ringeris_core::filetype;
use ringeris_core::pe;
use ringeris_core::report::Event;
use ringeris_core::scanner::{Engine, ScanOptions, Scanner};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::mpsc::channel;
use std::sync::Arc;

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ringeris-test-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn write_file(path: &Path, data: &[u8]) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    let mut file = std::fs::File::create(path).unwrap();
    file.write_all(data).unwrap();
}

fn write_db(tag: &str, files: &[(&str, String)]) -> PathBuf {
    let db_dir = temp_dir(&format!("{tag}-db"));
    for (name, content) in files {
        write_file(&db_dir.join(name), content.as_bytes());
    }
    db_dir
}

fn scan_dir(target: &Path, db_dir: &Path) -> (Vec<Event>, ringeris_core::scanner::ScanOutcome) {
    let mut database = Database::new();
    database.load_dir(db_dir).unwrap();
    let engine = Arc::new(Engine::new(
        Arc::new(database),
        ScanOptions {
            ..ScanOptions::default()
        },
    ));
    let (tx, rx) = channel();
    let scanner = Scanner::new(engine, tx);
    let outcome = scanner.scan_path(target);
    let mut events = Vec::new();
    while let Ok(event) = rx.try_recv() {
        events.push(event);
    }
    (events, outcome)
}

fn threat_events(events: &[Event]) -> Vec<(String, String, Option<String>)> {
    events
        .iter()
        .filter_map(|event| match event {
            Event::Threat {
                path,
                name,
                container,
                ..
            } => Some((path.clone(), name.clone(), container.clone())),
            _ => None,
        })
        .collect()
}

const PAYLOAD: &[u8] = b"malware-payload-ringeris-001";

#[test]
fn detects_md5_hash_match() {
    let plain = temp_dir("md5").join("plain.bin");
    write_file(&plain, PAYLOAD);
    let hashes = ringeris_core::hashes::compute_file(&plain).unwrap();
    let db_dir = write_db(
        "md5",
        &[(
            "test.hdb",
            format!("{0}:{1}:Win.Test.Md5-1", hashes.md5, hashes.size),
        )],
    );
    let target = plain.parent().unwrap().join("sample.bin");
    write_file(&target, PAYLOAD);
    let (events, outcome) = scan_dir(&target, &db_dir);
    assert_eq!(outcome.threats, 1);
    let threats = threat_events(&events);
    assert_eq!(threats[0].1, "Win.Test.Md5-1");
}

#[test]
fn detects_sha256_hash_match() {
    let plain = temp_dir("sha").join("plain.bin");
    write_file(&plain, PAYLOAD);
    let hashes = ringeris_core::hashes::compute_file(&plain).unwrap();
    let db_dir = write_db(
        "sha",
        &[(
            "test.hsb",
            format!("{0}:{1}:Win.Test.Sha-1", hashes.sha256, hashes.size),
        )],
    );
    let target = plain.parent().unwrap().join("nested").join("sample.bin");
    write_file(&target, PAYLOAD);
    let (_, outcome) = scan_dir(&target, &db_dir);
    assert_eq!(outcome.threats, 1);
}

#[test]
fn whitelist_suppresses_hash_detection() {
    let root = temp_dir("fp");
    let plain = root.join("plain.bin");
    write_file(&plain, PAYLOAD);
    let hashes = ringeris_core::hashes::compute_file(&plain).unwrap();
    let db_dir = write_db(
        "fp",
        &[
            (
                "test.hdb",
                format!("{0}:{1}:Win.Test.Md5-2", hashes.md5, hashes.size),
            ),
            (
                "whitelist.fp",
                format!("{0}:{1}:false-positive", hashes.md5, hashes.size),
            ),
        ],
    );
    let target = root.join("sample.bin");
    write_file(&target, PAYLOAD);
    let (_, outcome) = scan_dir(&target, &db_dir);
    assert_eq!(outcome.threats, 0);
}

#[test]
fn detects_ndb_pattern_any_offset() {
    let root = temp_dir("ndb-any");
    let payload = b"AAAA-evilbytes-BBBB";
    write_file(&root.join("sample.txt"), payload);
    let db_dir = write_db(
        "ndb-any",
        &[(
            "test.ndb",
            "Win.Test.Ndb:0:*:6576696C6279746573".to_string(),
        )],
    );
    let (events, outcome) = scan_dir(&root, &db_dir);
    assert_eq!(outcome.threats, 1);
    assert_eq!(threat_events(&events)[0].1, "Win.Test.Ndb");
}

#[test]
fn ndb_absolute_offset_must_match() {
    let root = temp_dir("ndb-abs");
    let payload = b"xxxx-evilbytes-yyyy";
    write_file(&root.join("a.txt"), payload);
    write_file(&root.join("b.txt"), b"evilbytes-not-here-prefix");
    let db_dir = write_db(
        "ndb-abs",
        &[(
            "test.ndb",
            "Win.Test.Abs:0:5:6576696C6279746573".to_string(),
        )],
    );
    let (_, outcome) = scan_dir(&root, &db_dir);
    assert_eq!(outcome.threats, 1);
}

#[test]
fn ndb_gap_pattern_matches() {
    let root = temp_dir("ndb-gap");
    let payload = b"AA-payload-99-BB";
    write_file(&root.join("sample.txt"), payload);
    let db_dir = write_db(
        "ndb-gap",
        &[("test.ndb", "Win.Test.Gap:0:*:4141{10-14}4242".to_string())],
    );
    let (events, outcome) = scan_dir(&root, &db_dir);
    assert_eq!(outcome.threats, 1);
    let threats = threat_events(&events);
    assert_eq!(threats[0].1, "Win.Test.Gap");
}

#[test]
fn ndb_wildcard_nibbles_match() {
    let root = temp_dir("ndb-nib");
    write_file(&root.join("sample.txt"), b"key=AX9-end");
    let db_dir = write_db(
        "ndb-nib",
        &[("test.ndb", "Win.Test.Nib:0:*:41??5A??2D656E64".to_string())],
    );
    let (_, outcome) = scan_dir(&root, &db_dir);
    assert_eq!(outcome.threats, 0);
    write_file(&root.join("sample2.txt"), b"key=A1Z9-end");
    let (_, outcome) = scan_dir(&root, &db_dir);
    assert_eq!(outcome.threats, 1);
}

fn build_pe(section_raw: &[u8], entry_rva: u32) -> Vec<u8> {
    let header_size: u32 = 0x400;
    let mut data = vec![0u8; header_size as usize + section_raw.len()];
    data[0] = b'M';
    data[1] = b'Z';
    data[0x3c] = 0x40;
    let pe = 0x40;
    data[pe..pe + 4].copy_from_slice(b"PE\0\0");
    let coff = pe + 4;
    data[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
    data[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
    data[coff + 16..coff + 18].copy_from_slice(&0xe0u16.to_le_bytes());
    let optional = coff + 20;
    data[optional..optional + 2].copy_from_slice(&0x10bu16.to_le_bytes());
    data[optional + 16..optional + 20].copy_from_slice(&entry_rva.to_le_bytes());
    let section = optional + 0xe0;
    data[section..section + 8].copy_from_slice(b".text\0\0\0");
    data[section + 8..section + 12].copy_from_slice(&0x2000u32.to_le_bytes());
    data[section + 12..section + 16].copy_from_slice(&0x1000u32.to_le_bytes());
    data[section + 16..section + 20].copy_from_slice(&(section_raw.len() as u32).to_le_bytes());
    data[section + 20..section + 24].copy_from_slice(&header_size.to_le_bytes());
    data[header_size as usize..].copy_from_slice(section_raw);
    data
}

#[test]
fn pe_parser_reads_entry_and_sections() {
    let section = b"hello-section-content";
    let data = build_pe(section, 0x1000);
    let image = pe::Image::parse(&data).unwrap();
    assert_eq!(image.sections.len(), 1);
    assert_eq!(image.sections[0].raw_pointer, 0x400);
    let entry = image.entry_point_offset.unwrap();
    assert_eq!(entry, 0x400);
}

#[test]
fn ndb_pe_target_entry_point_offset() {
    let root = temp_dir("ndb-pe");
    let mut section = vec![0x90u8; 16];
    section.extend_from_slice(b"evilcode!!");
    section.extend_from_slice(&[0x90u8; 16]);
    let data = build_pe(&section, 0x1000);
    write_file(&root.join("sample.exe"), &data);
    let needle = b"evilcode!!";
    let hex: String = needle.iter().map(|b| format!("{b:02X}")).collect();
    let db_dir = write_db(
        "ndb-pe",
        &[("test.ndb", format!("Win.Test.Pe:{1}:EP+16:{0}", hex, 1))],
    );
    let (_, outcome) = scan_dir(&root, &db_dir);
    assert_eq!(outcome.threats, 1);
}

#[test]
fn ndb_pe_target_misses_wrong_offset() {
    let root = temp_dir("ndb-pe2");
    let mut section = vec![0x90u8; 16];
    section.extend_from_slice(b"evilcode!!");
    let data = build_pe(&section, 0x1000);
    write_file(&root.join("sample.exe"), &data);
    let needle = b"evilcode!!";
    let hex: String = needle.iter().map(|b| format!("{b:02X}")).collect();
    let db_dir = write_db(
        "ndb-pe2",
        &[("test.ndb", format!("Win.Test.Pe:{1}:EP+4:{0}", hex, 1))],
    );
    let (_, outcome) = scan_dir(&root, &db_dir);
    assert_eq!(outcome.threats, 0);
}

#[test]
fn mdb_section_hash_detects() {
    let root = temp_dir("mdb");
    let secret = b"section-unique-content-1234567890";
    let mut section = vec![0x00u8; 32];
    section.extend_from_slice(secret);
    let data = build_pe(&section, 0x1000);
    write_file(&root.join("sample.dll"), &data);
    let hashes = ringeris_core::hashes::compute_bytes(&section);
    let db_dir = write_db(
        "mdb",
        &[(
            "test.mdb",
            format!("{0}:{1}:Win.Test.Section", hashes.md5, section.len()),
        )],
    );
    let (events, outcome) = scan_dir(&root, &db_dir);
    assert_eq!(outcome.threats, 1);
    assert_eq!(threat_events(&events)[0].1, "Win.Test.Section");
}

#[test]
fn ldb_logical_and_detects() {
    let root = temp_dir("ldb");
    let payload = b"HEADER-XXXX-first-part-TAIL";
    write_file(&root.join("sample.bin"), payload);
    let db_dir = write_db(
        "ldb",
        &[(
            "test.ldb",
            "Win.Test.Ldb;0;0&1;48454144;5441494C".to_string(),
        )],
    );
    let (_, outcome) = scan_dir(&root, &db_dir);
    assert_eq!(outcome.threats, 1);
}

#[test]
fn ldb_distance_constraint() {
    let root = temp_dir("ldb-dist");
    let close = b"HEAD-payload-00-TAIL";
    let far = format!("HEAD{}TAIL", "F".repeat(64));
    write_file(&root.join("close.bin"), close);
    write_file(&root.join("far.bin"), far.as_bytes());
    let db_dir = write_db(
        "ldb-dist",
        &[(
            "test.ldb",
            "Win.Test.Dist;0;0&1{10-20};48454144;5441494C".to_string(),
        )],
    );
    let (_, outcome) = scan_dir(&root, &db_dir);
    assert_eq!(outcome.threats, 1);
}

#[test]
fn ldb_or_expression() {
    let root = temp_dir("ldb-or");
    write_file(&root.join("a.bin"), b"ALPHA-only");
    write_file(&root.join("b.bin"), b"BETA-only");
    let db_dir = write_db(
        "ldb-or",
        &[(
            "test.ldb",
            "Win.Test.Or;0;0|1;414C504841;42455441".to_string(),
        )],
    );
    let (_, outcome) = scan_dir(&root, &db_dir);
    assert_eq!(outcome.threats, 2);
}

#[test]
fn zip_member_pattern_detection() {
    let root = temp_dir("zip");
    let zip_path = root.join("archive.zip");
    let payload = b"evilbytes-inside-zip";
    {
        let file = std::fs::File::create(&zip_path).unwrap();
        let mut writer = zip::ZipWriter::new(file);
        let options = zip::write::FileOptions::default();
        writer.start_file("inner/payload.bin", options).unwrap();
        writer.write_all(payload).unwrap();
        writer.finish().unwrap();
    }
    let db_dir = write_db(
        "zip",
        &[(
            "test.ndb",
            "Win.Test.Zip:0:*:6576696C6279746573".to_string(),
        )],
    );
    let (events, outcome) = scan_dir(&root, &db_dir);
    assert_eq!(outcome.threats, 1);
    let threats = threat_events(&events);
    assert!(threats[0]
        .2
        .as_deref()
        .unwrap_or("")
        .contains("archive.zip"));
}

#[test]
fn zip_bomb_is_skipped() {
    let root = temp_dir("bomb");
    let zip_path = root.join("bomb.zip");
    {
        let file = std::fs::File::create(&zip_path).unwrap();
        let mut writer = zip::ZipWriter::new(file);
        let options = zip::write::FileOptions::default();
        writer.start_file("zeros.bin", options).unwrap();
        let chunk = vec![0u8; 65536];
        for _ in 0..64 {
            writer.write_all(&chunk).unwrap();
        }
        writer.finish().unwrap();
    }
    let db_dir = write_db("bomb", &[("test.ndb", "Win.Test.Z:0:*:4141".to_string())]);
    let (events, outcome) = scan_dir(&root, &db_dir);
    assert_eq!(outcome.threats, 0);
    assert!(outcome.skipped >= 1);
    assert!(events.iter().any(|event| matches!(
        event,
        Event::FileSkipped { reason, .. } if reason == "bomb"
    )));
}

#[test]
fn file_type_detection() {
    assert_eq!(filetype::detect(b"PK\x03\x04rest"), filetype::Kind::Zip);
    assert_eq!(
        filetype::detect(b"\x1f\x8bcompressed"),
        filetype::Kind::Gzip
    );
    assert_eq!(filetype::detect(b"MSCFabc"), filetype::Kind::Cab);
    assert_eq!(
        filetype::detect(&[0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]),
        filetype::Kind::SevenZip
    );
    assert_eq!(
        filetype::detect(&build_pe(b"x", 0x1000)),
        filetype::Kind::Pe
    );
    assert_eq!(
        filetype::detect(b"<html><body>hello</body></html>"),
        filetype::Kind::Html
    );
    assert_eq!(filetype::detect(b"plain text"), filetype::Kind::Text);
}

#[test]
fn exclusions_skip_paths() {
    let root = temp_dir("excl");
    write_file(&root.join("normal.bin"), b"evilbytes-here");
    let skip_dir = root.join("skip-me");
    write_file(&skip_dir.join("hidden.bin"), b"evilbytes-here");
    let db_dir = write_db(
        "excl",
        &[("test.ndb", "Win.Test.Ex:0:*:6576696C6279746573".to_string())],
    );
    let mut database = Database::new();
    database.load_dir(&db_dir).unwrap();
    let engine = Arc::new(Engine::new(
        Arc::new(database),
        ScanOptions {
            exclusions: vec!["skip-me".to_string()],
            ..ScanOptions::default()
        },
    ));
    let (tx, rx) = channel();
    let scanner = Scanner::new(engine, tx);
    let outcome = scanner.scan_path(&root);
    let mut threats = 0;
    while let Ok(event) = rx.try_recv() {
        if matches!(event, Event::Threat { .. }) {
            threats += 1;
        }
    }
    assert_eq!(outcome.threats, 1);
    assert_eq!(threats, 1);
}

#[test]
fn pattern_parse_rejects_garbage() {
    assert!(ringeris_core::pattern::Pattern::parse("ZZZZ").is_err());
    assert!(ringeris_core::pattern::Pattern::parse("").is_err());
    assert!(ringeris_core::pattern::Pattern::parse("{2-3}").is_err());
    assert!(ringeris_core::pattern::Pattern::parse("4A4B").is_ok());
    assert!(ringeris_core::pattern::Pattern::parse("4?4B").is_ok());
    assert!(ringeris_core::pattern::Pattern::parse("4A4B(b)").is_ok());
    assert!(ringeris_core::pattern::Pattern::parse("4A4B(i|g)").is_err());
}

#[test]
fn eicar_test_file_detected_by_pattern() {
    let eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    let root = temp_dir("eicar");
    write_file(&root.join("eicar.com"), eicar);
    let hex: String = eicar.iter().map(|b| format!("{b:02X}")).collect();
    let db_dir = write_db(
        "eicar",
        &[("test.ndb", format!("Win.Test.EICAR-1:0:*:{0}", hex))],
    );
    let (events, outcome) = scan_dir(&root, &db_dir);
    assert_eq!(outcome.threats, 1);
    assert_eq!(threat_events(&events)[0].1, "Win.Test.EICAR-1");
}

#[test]
fn synthetic_cvd_container_loads_all_signature_kinds() {
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Read;

    let root = temp_dir("cvd");
    write_file(&root.join("evil.txt"), b"evilbytes-in-cvd-001");
    let plain_hash = ringeris_core::hashes::compute_bytes(b"evilbytes-in-cvd-001");

    let tar_dir = temp_dir("cvd-tar");
    let tar_path = tar_dir.join("db.tar");
    {
        let file = std::fs::File::create(&tar_path).unwrap();
        let mut builder = tar::Builder::new(file);
        let ndb = b"Win.Test.CvdNdb:0:*:6576696C6279746573\n";
        let mut header = tar::Header::new_gnu();
        header.set_size(ndb.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "daily.ndb", &ndb[..])
            .unwrap();
        let hdb = format!("{0}:{1}:Win.Test.CvdHdb\n", plain_hash.md5, plain_hash.size);
        let mut header = tar::Header::new_gnu();
        header.set_size(hdb.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "daily.hdb", hdb.as_bytes())
            .unwrap();
        builder.finish().unwrap();
    }

    let mut cvd: Vec<u8> = vec![0u8; 512];
    let header_text = b"ClamAV-VDB:15 Nov 2026 12-00 -0400:30000:30000:0:61:99:12345";
    cvd[..header_text.len()].copy_from_slice(header_text);
    let tar_bytes = std::fs::read(&tar_path).unwrap();
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&tar_bytes).unwrap();
    cvd.extend_from_slice(&encoder.finish().unwrap());

    let db_dir = temp_dir("cvd-db");
    write_file(&db_dir.join("daily.cvd"), &cvd);

    let (events, _outcome) = scan_dir(&root, &db_dir);
    let names: Vec<String> = threat_events(&events)
        .into_iter()
        .map(|(_, n, _)| n)
        .collect();
    assert_eq!(names.len(), 2);
    assert!(names.contains(&"Win.Test.CvdNdb".to_string()));
    assert!(names.contains(&"Win.Test.CvdHdb".to_string()));
    let _ = std::io::stdout().flush();
    let _ = tar_path;
    let _ = Read::read(&mut std::io::empty(), &mut [0u8; 0]);
}
