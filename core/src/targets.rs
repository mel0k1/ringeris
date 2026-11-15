use std::path::PathBuf;

fn push_existing(out: &mut Vec<PathBuf>, path: Option<PathBuf>) {
    if let Some(p) = path {
        if p.is_dir() && !out.contains(&p) {
            out.push(p);
        }
    }
}

pub fn quick_targets() -> Vec<PathBuf> {
    let mut out = Vec::new();
    push_existing(&mut out, dirs::download_dir());
    push_existing(&mut out, Some(std::env::temp_dir()));
    if let Some(local) = dirs::data_local_dir() {
        push_existing(&mut out, Some(local.join("Temp")));
    }
    if let Some(roaming) = dirs::data_dir() {
        push_existing(
            &mut out,
            Some(
                roaming
                    .join("Microsoft")
                    .join("Windows")
                    .join("Start Menu")
                    .join("Programs")
                    .join("Startup"),
            ),
        );
    }
    if let Some(program_data) = std::env::var_os("ProgramData").map(PathBuf::from) {
        push_existing(
            &mut out,
            Some(
                program_data
                    .join("Microsoft")
                    .join("Windows")
                    .join("Start Menu")
                    .join("Programs")
                    .join("Startup"),
            ),
        );
    }
    out
}

pub fn full_targets() -> Vec<PathBuf> {
    let mut out = Vec::new();
    for code in b'A'..=b'Z' {
        let letter = code as char;
        let drive = PathBuf::from(format!("{letter}:\\"));
        if drive.is_dir() {
            out.push(drive);
        }
    }
    if out.is_empty() {
        out.push(PathBuf::from("/"));
    }
    out
}
