use crate::pattern::Pattern;
use aho_corasick::AhoCorasick;
use md5::{Digest, Md5};
use sha2::Sha256;
use std::collections::HashMap;

pub const ENGINE_FLEVEL: u32 = 188;

const BRUTE_SCAN_LIMIT: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone)]
pub enum OffsetSpec {
    Any,
    Absolute(u32),
    EofMinus(u32),
    EpPlus(u32),
    EpMinus(u32),
    SlPlus(u32),
    SectionPlus(usize, u32),
}

fn parse_offset(spec: &str) -> Option<OffsetSpec> {
    let text = spec.trim();
    if text.is_empty() || text == "*" {
        return Some(OffsetSpec::Any);
    }
    if text == "EP" {
        return Some(OffsetSpec::EpPlus(0));
    }
    if let Some(rest) = text.strip_prefix("EP+") {
        return Some(OffsetSpec::EpPlus(rest.parse().ok()?));
    }
    if let Some(rest) = text.strip_prefix("EP-") {
        return Some(OffsetSpec::EpMinus(rest.parse().ok()?));
    }
    if let Some(rest) = text.strip_prefix("SL+") {
        return Some(OffsetSpec::SlPlus(rest.parse().ok()?));
    }
    if let Some(rest) = text.strip_prefix("EOF-") {
        return Some(OffsetSpec::EofMinus(rest.parse().ok()?));
    }
    if let Some(rest) = text.strip_prefix('S') {
        if let Some((index, shift)) = rest.split_once('+') {
            let index: usize = index.parse().ok()?;
            let shift: u32 = shift.parse().ok()?;
            if index < 96 {
                return Some(OffsetSpec::SectionPlus(index, shift));
            }
            return None;
        }
        return None;
    }
    if text.starts_with("VI") || text.starts_with("SE") || text.starts_with('$') {
        return None;
    }
    Some(OffsetSpec::Absolute(text.parse().ok()?))
}

struct ByteSig {
    pattern: Pattern,
    target: u32,
    offset: OffsetSpec,
    name: String,
    from_ldb: bool,
    exact_offset: Option<u32>,
}

enum LogicNode {
    Subsig(usize, Option<(u32, u32)>),
    And(Box<LogicNode>, Box<LogicNode>),
    Or(Box<LogicNode>, Box<LogicNode>),
    Not(Box<LogicNode>),
}

struct LogicalSig {
    name: String,
    target: u32,
    file_size: Option<(u64, u64)>,
    expression: LogicNode,
    subsig_ids: Vec<usize>,
}

type MatchSpan = (usize, usize);

struct Tdb {
    target: u32,
    file_size: Option<(u64, u64)>,
    engine: Option<(u32, u32)>,
}

fn parse_tdb(spec: &str) -> Option<Tdb> {
    let text = spec.trim();
    if text.is_empty() {
        return Some(Tdb {
            target: 0,
            file_size: None,
            engine: None,
        });
    }
    if !text.contains(':') {
        return Some(Tdb {
            target: text.parse().ok()?,
            file_size: None,
            engine: None,
        });
    }
    let mut tdb = Tdb {
        target: 0,
        file_size: None,
        engine: None,
    };
    for pair in text.split(';') {
        let (key, value) = pair.split_once(':')?;
        let key = key.trim();
        let value = value.trim();
        match key {
            "Target" => tdb.target = value.split(',').next()?.trim().parse().ok()?,
            "Engine" => tdb.engine = Some(parse_range_values(value)?),
            "FileSize" => {
                let (min, max) = parse_range_values(value)?;
                tdb.file_size = Some((min as u64, max as u64));
            }
            _ => return None,
        }
    }
    Some(tdb)
}

fn parse_range_values(value: &str) -> Option<(u32, u32)> {
    let value = value.trim();
    if let Some((a, b)) = value.split_once('-') {
        let min: u32 = a.trim().parse().ok()?;
        let max: u32 = b.trim().parse().ok()?;
        if max < min {
            return None;
        }
        return Some((min, max));
    }
    let single: u32 = value.parse().ok()?;
    Some((single, single))
}

fn tokenize_expression(expression: &str) -> Vec<String> {
    let chars: Vec<char> = expression.chars().collect();
    let mut tokens = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        match c {
            '&' | '|' | '!' | '(' | ')' => {
                tokens.push(c.to_string());
                i += 1;
            }
            '{' => {
                let mut token = String::from("{");
                i += 1;
                while i < chars.len() && chars[i] != '}' {
                    token.push(chars[i]);
                    i += 1;
                }
                if i < chars.len() {
                    token.push('}');
                    i += 1;
                }
                tokens.push(token);
            }
            _ => {
                let mut token = String::new();
                while i < chars.len() && !matches!(chars[i], '&' | '|' | '!' | '(' | ')' | '{') {
                    token.push(chars[i]);
                    i += 1;
                }
                tokens.push(token);
            }
        }
    }
    tokens
}

fn parse_ldb_expression(expression: &str) -> Option<LogicNode> {
    let tokens = tokenize_expression(expression);
    let mut pos = 0;
    let node = parse_or(&tokens, &mut pos)?;
    if pos != tokens.len() {
        return None;
    }
    Some(node)
}

fn collect_subsig_count(node: &LogicNode) -> usize {
    match node {
        LogicNode::Subsig(_, _) => 1,
        LogicNode::And(a, b) | LogicNode::Or(a, b) => {
            collect_subsig_count(a) + collect_subsig_count(b)
        }
        LogicNode::Not(a) => collect_subsig_count(a),
    }
}

fn max_subsig_index(node: &LogicNode) -> usize {
    match node {
        LogicNode::Subsig(index, _) => *index,
        LogicNode::And(a, b) | LogicNode::Or(a, b) => max_subsig_index(a).max(max_subsig_index(b)),
        LogicNode::Not(a) => max_subsig_index(a),
    }
}

fn parse_or(tokens: &[String], pos: &mut usize) -> Option<LogicNode> {
    let mut left = parse_and(tokens, pos)?;
    while *pos < tokens.len() && tokens[*pos] == "|" {
        *pos += 1;
        let right = parse_and(tokens, pos)?;
        left = LogicNode::Or(Box::new(left), Box::new(right));
    }
    Some(left)
}

fn parse_and(tokens: &[String], pos: &mut usize) -> Option<LogicNode> {
    let mut left = parse_unary(tokens, pos)?;
    while *pos < tokens.len() && tokens[*pos] == "&" {
        *pos += 1;
        let right = parse_unary(tokens, pos)?;
        left = LogicNode::And(Box::new(left), Box::new(right));
    }
    Some(left)
}

fn parse_unary(tokens: &[String], pos: &mut usize) -> Option<LogicNode> {
    if *pos < tokens.len() && tokens[*pos] == "!" {
        *pos += 1;
        let inner = parse_unary(tokens, pos)?;
        return Some(LogicNode::Not(Box::new(inner)));
    }
    parse_primary(tokens, pos)
}

fn parse_primary(tokens: &[String], pos: &mut usize) -> Option<LogicNode> {
    if *pos < tokens.len() && tokens[*pos] == "(" {
        *pos += 1;
        let node = parse_or(tokens, pos)?;
        if *pos >= tokens.len() || tokens[*pos] != ")" {
            return None;
        }
        *pos += 1;
        return Some(node);
    }
    let token = tokens.get(*pos)?;
    if token.is_empty() || !token.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let index: usize = token.parse().ok()?;
    *pos += 1;
    let mut constraint = None;
    if *pos < tokens.len() && tokens[*pos].starts_with('{') && tokens[*pos].ends_with('}') {
        let inner = &tokens[*pos][1..tokens[*pos].len() - 1];
        constraint = Some(parse_range_values(inner)?);
        *pos += 1;
    }
    Some(LogicNode::Subsig(index, constraint))
}

#[derive(Default)]
pub struct SigDb {
    byte_sigs: Vec<ByteSig>,
    logical: Vec<LogicalSig>,
    section_md5: HashMap<String, (Option<u64>, String)>,
    section_sha256: HashMap<String, (Option<u64>, String)>,
    automaton: Option<AhoCorasick>,
    prefix_map: HashMap<usize, Vec<usize>>,
    unprefixed: Vec<usize>,
    sig_to_logic: HashMap<usize, (usize, usize)>,
    pub source_files: Vec<String>,
    pub load_errors: Vec<String>,
}

impl SigDb {
    pub fn new() -> Self {
        SigDb::default()
    }

    pub fn load_text(&mut self, file_name: &str, text: &str) -> usize {
        let lower = file_name.to_lowercase();
        let count = if lower.ends_with(".ndb") {
            self.load_ndb(text)
        } else if lower.ends_with(".ldb") {
            self.load_ldb(text)
        } else if lower.ends_with(".mdb") || lower.ends_with(".msb") {
            self.load_mdb(text, lower.ends_with(".msb"))
        } else {
            0
        };
        if count > 0 {
            self.source_files.push(file_name.to_string());
        }
        count
    }

    pub fn finalize(&mut self) {
        let mut prefix_ids: HashMap<Vec<u8>, usize> = HashMap::new();
        let mut prefixes: Vec<Vec<u8>> = Vec::new();
        let mut prefix_of: Vec<Option<usize>> = Vec::new();
        for sig in &self.byte_sigs {
            let entry = match sig.pattern.leading_fixed_bytes() {
                Some((bytes, _))
                    if matches!(sig.offset, OffsetSpec::Any) && sig.exact_offset.is_none() =>
                {
                    Some(bytes.to_vec())
                }
                _ => None,
            };
            match entry {
                Some(bytes) => {
                    let next = prefixes.len();
                    let index = *prefix_ids.entry(bytes.clone()).or_insert(next);
                    if index == next {
                        prefixes.push(bytes);
                    }
                    prefix_of.push(Some(index));
                }
                None => prefix_of.push(None),
            }
        }
        self.prefix_map.clear();
        self.unprefixed.clear();
        for (id, prefix) in prefix_of.iter().enumerate() {
            match prefix {
                Some(index) => self.prefix_map.entry(*index).or_default().push(id),
                None => self.unprefixed.push(id),
            }
        }
        self.automaton = if prefixes.is_empty() {
            None
        } else {
            AhoCorasick::new(prefixes).ok()
        };
        self.sig_to_logic.clear();
        for (logic_index, logic) in self.logical.iter().enumerate() {
            for (slot, sig_id) in logic.subsig_ids.iter().enumerate() {
                self.sig_to_logic.insert(*sig_id, (logic_index, slot));
            }
        }
    }

    fn load_ndb(&mut self, text: &str) -> usize {
        let mut count = 0;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() < 4 || parts.len() > 6 {
                continue;
            }
            if parts.len() >= 5 {
                let min: u32 = match parts[4].trim().parse() {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                if min > ENGINE_FLEVEL {
                    continue;
                }
                if parts.len() == 6 {
                    let max: u32 = match parts[5].trim().parse() {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    if max > 0 && max < ENGINE_FLEVEL {
                        continue;
                    }
                }
            }
            let target: u32 = match parts[1].trim() {
                "*" => 0,
                value => match value.parse() {
                    Ok(v) => v,
                    Err(_) => continue,
                },
            };
            let offset = match parse_offset(parts[2]) {
                Some(spec) => spec,
                None => continue,
            };
            let pattern = match Pattern::parse(parts[3]) {
                Ok(p) => p,
                Err(_) => continue,
            };
            self.byte_sigs.push(ByteSig {
                pattern,
                target,
                offset,
                name: parts[0].to_string(),
                from_ldb: false,
                exact_offset: None,
            });
            count += 1;
        }
        count
    }

    fn load_ldb(&mut self, text: &str) -> usize {
        let mut count = 0;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = line.split(';').collect();
            if parts.len() < 4 {
                continue;
            }
            let tdb = match parse_tdb(parts[1]) {
                Some(t) => t,
                None => continue,
            };
            if let Some((min, max)) = tdb.engine {
                if min > ENGINE_FLEVEL || (max > 0 && max < ENGINE_FLEVEL) {
                    continue;
                }
            }
            let subsig_count = parts.len() - 3;
            let expression = match parse_ldb_expression(parts[2]) {
                Some(e) => e,
                None => continue,
            };
            if collect_subsig_count(&expression) != subsig_count
                || max_subsig_index(&expression) >= subsig_count
            {
                continue;
            }
            let subsig_base = self.byte_sigs.len();
            let mut ok = true;
            for raw in &parts[3..] {
                let subsig = raw.trim();
                if subsig.is_empty() || subsig.starts_with('$') || subsig.contains('/') {
                    ok = false;
                    break;
                }
                let (exact_offset, body) = if let Some(rest) = subsig.strip_prefix("0:") {
                    (None, rest.to_string())
                } else if let Some(rest) = subsig.strip_prefix("1:") {
                    let (offset_raw, hex) = match rest.split_once(':') {
                        Some(v) => v,
                        None => {
                            ok = false;
                            break;
                        }
                    };
                    match offset_raw.parse::<u32>() {
                        Ok(v) => (Some(v), hex.to_string()),
                        Err(_) => {
                            ok = false;
                            break;
                        }
                    }
                } else {
                    (None, subsig.to_string())
                };
                let pattern = match Pattern::parse(&body) {
                    Ok(p) => p,
                    Err(_) => {
                        ok = false;
                        break;
                    }
                };
                self.byte_sigs.push(ByteSig {
                    pattern,
                    target: tdb.target,
                    offset: OffsetSpec::Any,
                    name: parts[0].to_string(),
                    from_ldb: true,
                    exact_offset,
                });
            }
            if !ok {
                self.byte_sigs.truncate(subsig_base);
                continue;
            }
            let subsig_ids: Vec<usize> = (subsig_base..self.byte_sigs.len()).collect();
            self.logical.push(LogicalSig {
                name: parts[0].to_string(),
                target: tdb.target,
                file_size: tdb.file_size,
                expression,
                subsig_ids,
            });
            count += 1;
        }
        count
    }

    fn load_mdb(&mut self, text: &str, sha256: bool) -> usize {
        let mut count = 0;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() < 3 {
                continue;
            }
            let hash = parts[0].trim().to_lowercase();
            if hash.len() != 32 && hash.len() != 64 {
                continue;
            }
            if !hash.chars().all(|c| c.is_ascii_hexdigit()) {
                continue;
            }
            let size = if parts[1].trim() == "*" {
                None
            } else {
                match parts[1].trim().parse::<u64>() {
                    Ok(v) => Some(v),
                    Err(_) => continue,
                }
            };
            let name = parts[2].trim().to_string();
            let map = if sha256 {
                &mut self.section_sha256
            } else {
                &mut self.section_md5
            };
            map.entry(hash).or_insert((size, name));
            count += 1;
        }
        count
    }

    pub fn total(&self) -> usize {
        self.byte_sigs.len() + self.section_md5.len() + self.section_sha256.len()
    }

    pub fn pattern_count(&self) -> usize {
        self.byte_sigs.len()
    }

    pub fn logical_count(&self) -> usize {
        self.logical.len()
    }

    pub fn section_count(&self) -> usize {
        self.section_md5.len() + self.section_sha256.len()
    }

    pub fn scan_buffer(
        &self,
        data: &[u8],
        target: u32,
        image: Option<&crate::pe::Image>,
    ) -> Vec<Detection> {
        if self.byte_sigs.is_empty()
            && self.section_md5.is_empty()
            && self.section_sha256.is_empty()
        {
            return Vec::new();
        }
        let mut hits: HashMap<usize, Vec<MatchSpan>> = HashMap::new();
        if let Some(automaton) = &self.automaton {
            for match_ in automaton.find_iter(data) {
                let prefix_index = match_.pattern().as_usize();
                let sig_ids = match self.prefix_map.get(&prefix_index) {
                    Some(ids) => ids,
                    None => continue,
                };
                let start = match_.start();
                for &id in sig_ids {
                    let sig = &self.byte_sigs[id];
                    if let Some(end) = sig.pattern.matches_at(data, start) {
                        hits.entry(id).or_default().push((start, end));
                    }
                }
            }
        }
        if !self.unprefixed.is_empty() && data.len() <= BRUTE_SCAN_LIMIT {
            for &id in &self.unprefixed {
                let sig = &self.byte_sigs[id];
                if let Some(start) = sig.pattern.match_anywhere(data, 0, data.len()) {
                    if let Some(end) = sig.pattern.matches_at(data, start) {
                        hits.entry(id).or_default().push((start, end));
                    }
                }
            }
        }
        let mut detections = Vec::new();
        for (id, spans) in &hits {
            let sig = &self.byte_sigs[*id];
            if sig.from_ldb || (sig.target != 0 && sig.target != target) {
                continue;
            }
            if !self.offset_matches(sig, data, image, spans) {
                continue;
            }
            detections.push(Detection {
                name: sig.name.clone(),
                kind: "pattern".to_string(),
            });
        }
        if !self.logical.is_empty() {
            let mut per_logic: Vec<Vec<Vec<MatchSpan>>> = vec![Vec::new(); self.logical.len()];
            for (id, spans) in &hits {
                let sig = &self.byte_sigs[*id];
                if !sig.from_ldb || (sig.target != 0 && sig.target != target) {
                    continue;
                }
                let expected = match sig.exact_offset {
                    Some(value) => Some(value as usize),
                    None => resolve_offset(&sig.offset, data, image),
                };
                if let Some(wanted) = expected {
                    if !spans.iter().any(|(start, _)| *start == wanted) {
                        continue;
                    }
                }
                if let Some((logic_index, slot)) = self.sig_to_logic.get(id) {
                    let slots = &mut per_logic[*logic_index];
                    if slots.len() <= *slot {
                        slots.resize(*slot + 1, Vec::new());
                    }
                    slots[*slot].extend(spans.iter().cloned());
                }
            }
            for (logic_index, logic) in self.logical.iter().enumerate() {
                if logic.target != 0 && logic.target != target {
                    continue;
                }
                if let Some((min, max)) = logic.file_size {
                    let len = data.len() as u64;
                    if len < min || len > max {
                        continue;
                    }
                }
                let slots = &per_logic[logic_index];
                if slots.iter().all(|v| v.is_empty()) {
                    continue;
                }
                if evaluate(&logic.expression, slots).is_some() {
                    detections.push(Detection {
                        name: logic.name.clone(),
                        kind: "logical".to_string(),
                    });
                }
            }
        }
        if target == 1 {
            if let Some(image) = image {
                for section in &image.sections {
                    if section.raw_size == 0
                        || section.raw_pointer as u64 + section.raw_size as u64 > data.len() as u64
                    {
                        continue;
                    }
                    let bytes = &data[section.raw_pointer as usize
                        ..(section.raw_pointer + section.raw_size) as usize];
                    let mut md5 = Md5::new();
                    md5.update(bytes);
                    let md5_hex = hex::encode(md5.finalize());
                    if let Some((size, name)) = self.section_md5.get(&md5_hex) {
                        if size.is_none() || *size == Some(section.raw_size as u64) {
                            detections.push(Detection {
                                name: name.clone(),
                                kind: "section".to_string(),
                            });
                        }
                    }
                    let mut sha = Sha256::new();
                    sha.update(bytes);
                    let sha_hex = hex::encode(sha.finalize());
                    if let Some((size, name)) = self.section_sha256.get(&sha_hex) {
                        if size.is_none() || *size == Some(section.raw_size as u64) {
                            detections.push(Detection {
                                name: name.clone(),
                                kind: "section".to_string(),
                            });
                        }
                    }
                }
            }
        }
        detections
    }

    fn offset_matches(
        &self,
        sig: &ByteSig,
        data: &[u8],
        image: Option<&crate::pe::Image>,
        spans: &[MatchSpan],
    ) -> bool {
        if matches!(sig.offset, OffsetSpec::Any) && sig.exact_offset.is_none() {
            return true;
        }
        let Some(expected) = resolve_offset(&sig.offset, data, image) else {
            return false;
        };
        let exact = sig.exact_offset.map(|v| v as usize).unwrap_or(expected);
        spans.iter().any(|(start, _)| *start == exact)
    }
}

#[derive(Debug, Clone)]
pub struct Detection {
    pub name: String,
    pub kind: String,
}

fn resolve_offset(
    spec: &OffsetSpec,
    data: &[u8],
    image: Option<&crate::pe::Image>,
) -> Option<usize> {
    match spec {
        OffsetSpec::Any => None,
        OffsetSpec::Absolute(value) => Some(*value as usize),
        OffsetSpec::EofMinus(value) => {
            let value = *value as usize;
            if data.len() >= value {
                Some(data.len() - value)
            } else {
                None
            }
        }
        OffsetSpec::EpPlus(value) => {
            let base = image?.entry_point_offset? as usize;
            Some(base + *value as usize)
        }
        OffsetSpec::EpMinus(value) => {
            let base = image?.entry_point_offset? as usize;
            base.checked_sub(*value as usize)
        }
        OffsetSpec::SlPlus(value) => {
            let image = image?;
            let section = image.last_section()?;
            if section.raw_pointer == 0 {
                return None;
            }
            Some(section.raw_pointer as usize + *value as usize)
        }
        OffsetSpec::SectionPlus(index, value) => {
            let image = image?;
            image
                .section_start_offset(*index)
                .map(|v| v as usize + *value as usize)
        }
    }
}

fn evaluate(node: &LogicNode, spans: &[Vec<MatchSpan>]) -> Option<Vec<MatchSpan>> {
    match node {
        LogicNode::Subsig(index, _) => {
            let value = spans.get(*index).cloned().unwrap_or_default();
            if value.is_empty() {
                return None;
            }
            Some(value)
        }
        LogicNode::Not(inner) => {
            if evaluate(inner, spans).is_some() {
                None
            } else {
                Some(Vec::new())
            }
        }
        LogicNode::Or(a, b) => match (evaluate(a, spans), evaluate(b, spans)) {
            (Some(mut left), Some(right)) => {
                left.extend(right);
                Some(left)
            }
            (Some(left), None) => Some(left),
            (None, Some(right)) => Some(right),
            (None, None) => None,
        },
        LogicNode::And(a, b) => {
            let left = evaluate(a, spans)?;
            let right = evaluate(b, spans)?;
            if let LogicNode::Subsig(_, Some((min, max))) = &**b {
                if !left.is_empty() && !right.is_empty() {
                    let filtered: Vec<MatchSpan> = right
                        .iter()
                        .filter(|(start, _)| {
                            left.iter().any(|(_, end)| {
                                let distance = start.saturating_sub(*end);
                                distance >= *min as usize && distance <= *max as usize
                            })
                        })
                        .cloned()
                        .collect();
                    if filtered.is_empty() {
                        return None;
                    }
                    return Some(filtered);
                }
            }
            Some(right)
        }
    }
}
