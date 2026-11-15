#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Nibble {
    Fixed(u8),
    Any,
}

#[derive(Debug, Clone, Default)]
pub struct BytesChunk {
    pub values: Vec<u8>,
    pub masks: Vec<u8>,
}

impl BytesChunk {
    pub fn len(&self) -> usize {
        self.values.len()
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    pub fn first_fully_fixed_prefix(&self) -> &[u8] {
        let mut end = 0;
        for (i, mask) in self.masks.iter().enumerate() {
            if *mask != 0xff {
                break;
            }
            end = i + 1;
        }
        &self.values[..end]
    }

    pub fn matches_at(&self, data: &[u8], start: usize) -> bool {
        if start + self.values.len() > data.len() {
            return false;
        }
        for i in 0..self.values.len() {
            if data[start + i] & self.masks[i] != self.values[i] & self.masks[i] {
                return false;
            }
        }
        true
    }
}

#[derive(Debug, Clone)]
pub enum Chunk {
    Bytes(BytesChunk),
    Gap(u32, u32),
}

#[derive(Debug, Clone)]
pub struct Pattern {
    chunks: Vec<Chunk>,
}

#[derive(Debug)]
pub struct PatternError;

impl Pattern {
    pub fn parse(spec: &str) -> Result<Pattern, PatternError> {
        let mut chunks: Vec<Chunk> = Vec::new();
        let mut current = BytesChunk {
            values: Vec::new(),
            masks: Vec::new(),
        };
        let chars: Vec<char> = spec.chars().collect();
        let mut i = 0;
        while i < chars.len() {
            let c = chars[i];
            if c.is_whitespace() {
                i += 1;
            } else if c == '{' {
                let mut j = i + 1;
                let mut inner = String::new();
                while j < chars.len() && chars[j] != '}' {
                    inner.push(chars[j]);
                    j += 1;
                }
                if j >= chars.len() {
                    return Err(PatternError);
                }
                let (min, max) = parse_range(&inner)?;
                if !current.values.is_empty() {
                    chunks.push(Chunk::Bytes(std::mem::take(&mut current)));
                }
                if let Some(Chunk::Gap(pmin, pmax)) = chunks.last_mut() {
                    *pmin += min;
                    *pmax += max;
                } else {
                    chunks.push(Chunk::Gap(min, max));
                }
                i = j + 1;
            } else if c == '(' {
                let mut j = i + 1;
                while j < chars.len() && chars[j] != ')' {
                    j += 1;
                }
                if j >= chars.len() {
                    return Err(PatternError);
                }
                let inner: String = chars[i + 1..j].iter().collect();
                if !matches!(inner.trim(), "b" | "B") {
                    return Err(PatternError);
                }
                i = j + 1;
            } else if c == '?' || c.is_ascii_hexdigit() {
                let hi = if c == '?' {
                    Nibble::Any
                } else {
                    Nibble::Fixed(c.to_digit(16).ok_or(PatternError)? as u8)
                };
                let lo = if i + 1 < chars.len() {
                    let n = chars[i + 1];
                    if n == '?' {
                        Nibble::Any
                    } else if n.is_ascii_hexdigit() {
                        Nibble::Fixed(n.to_digit(16).ok_or(PatternError)? as u8)
                    } else {
                        return Err(PatternError);
                    }
                } else {
                    Nibble::Any
                };
                let (value, mask) = combine(hi, lo);
                current.values.push(value);
                current.masks.push(mask);
                i += 2;
            } else {
                return Err(PatternError);
            }
        }
        if !current.values.is_empty() {
            chunks.push(Chunk::Bytes(current));
        }
        if chunks.is_empty() {
            return Err(PatternError);
        }
        if !matches!(chunks.first(), Some(Chunk::Bytes(_))) {
            return Err(PatternError);
        }
        if !chunks.iter().all(|c| matches!(c, Chunk::Bytes(_)))
            && matches!(chunks.last(), Some(Chunk::Gap(..)))
        {
            chunks.pop();
        }
        if !chunks.iter().any(|c| matches!(c, Chunk::Bytes(_))) {
            return Err(PatternError);
        }
        Ok(Pattern { chunks })
    }

    pub fn leading_fixed_bytes(&self) -> Option<(&[u8], usize)> {
        if let Some(Chunk::Bytes(bytes)) = self.chunks.first() {
            let prefix = bytes.first_fully_fixed_prefix();
            if prefix.len() >= 2 {
                return Some((prefix, 0));
            }
        }
        None
    }

    pub fn matches_at(&self, data: &[u8], start: usize) -> Option<usize> {
        let mut index = 0;
        let mut cursor = start;
        while index < self.chunks.len() {
            match &self.chunks[index] {
                Chunk::Bytes(bytes) => {
                    if !bytes.matches_at(data, cursor) {
                        return None;
                    }
                    cursor += bytes.len();
                    index += 1;
                }
                Chunk::Gap(min, max) => {
                    let next = match self.chunks.get(index + 1) {
                        Some(Chunk::Bytes(bytes)) => bytes,
                        _ => return None,
                    };
                    let lo = cursor + *min as usize;
                    let hi = cursor + *max as usize;
                    let mut pos = lo;
                    loop {
                        if pos > hi || pos + next.len() > data.len() {
                            return None;
                        }
                        if next.matches_at(data, pos) {
                            cursor = pos + next.len();
                            index += 2;
                            break;
                        }
                        pos += 1;
                    }
                }
            }
        }
        Some(cursor)
    }

    pub fn match_anywhere(&self, data: &[u8], from: usize, limit: usize) -> Option<usize> {
        let first = match self.chunks.first() {
            Some(Chunk::Bytes(bytes)) => bytes,
            _ => return None,
        };
        let end = data.len().min(limit).saturating_sub(first.len());
        let mut pos = from;
        while pos <= end {
            if first.matches_at(data, pos) && self.matches_at(data, pos).is_some() {
                return Some(pos);
            }
            pos += 1;
        }
        None
    }

    pub fn total_fixed_len(&self) -> usize {
        self.chunks
            .iter()
            .map(|c| match c {
                Chunk::Bytes(bytes) => bytes.len(),
                Chunk::Gap(min, max) => (*min as usize + *max as usize) / 2,
            })
            .sum()
    }
}

fn parse_range(inner: &str) -> Result<(u32, u32), PatternError> {
    if let Some((a, b)) = inner.split_once('-') {
        let min: u32 = a.trim().parse().map_err(|_| PatternError)?;
        let max: u32 = b.trim().parse().map_err(|_| PatternError)?;
        if max < min {
            return Err(PatternError);
        }
        Ok((min, max))
    } else {
        let value: u32 = inner.trim().parse().map_err(|_| PatternError)?;
        Ok((value, value))
    }
}

fn combine(hi: Nibble, lo: Nibble) -> (u8, u8) {
    let hi_mask = if matches!(hi, Nibble::Fixed(_)) {
        0xf0
    } else {
        0x00
    };
    let lo_mask = if matches!(lo, Nibble::Fixed(_)) {
        0x0f
    } else {
        0x00
    };
    let mask = hi_mask | lo_mask;
    let hi_value = match hi {
        Nibble::Fixed(v) => v << 4,
        Nibble::Any => 0,
    };
    let lo_value = match lo {
        Nibble::Fixed(v) => v,
        Nibble::Any => 0,
    };
    (hi_value | lo_value, mask)
}
