use serde::Serialize;
use std::{
    fs::File,
    io::{BufReader, Read},
    path::Path,
};

use sha1::Sha1;
use sha2::{Digest, Sha256};

#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Serialize)]
pub struct ArtifactReport {
    pub schema_version: u32,
    pub file: FileInfo,
    pub strings: StringsInfo,
}

#[derive(Serialize)]
pub struct FileInfo {
    pub path: String,
    pub size_bytes: u64,
    pub hashes: Hashes,
}

#[derive(Serialize)]
pub struct Hashes {
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    pub blake3: String,
}

#[derive(Serialize)]
pub struct StringsInfo {
    pub ascii_count: usize,
    pub utf16le_count: usize,
    pub ascii_samples: Vec<String>,
    pub utf16le_samples: Vec<String>,
}

pub fn analyze_file(path: &Path) -> Result<ArtifactReport, SandboxError> {
    let meta = std::fs::metadata(path)?;
    let size = meta.len();

    let hashes = compute_hashes(path)?;
    let strings = extract_strings(path)?;

    Ok(ArtifactReport {
        schema_version: 1,
        file: FileInfo {
            path: path.display().to_string(),
            size_bytes: size,
            hashes,
        },
        strings,
    })
}

fn compute_hashes(path: &Path) -> Result<Hashes, SandboxError> {
    let f = File::open(path)?;
    let mut r = BufReader::new(f);

    let mut md5_ctx = md5::Context::new();
    let mut sha1_ctx = Sha1::new();
    let mut sha256_ctx = Sha256::new();
    let mut blake3_hasher = blake3::Hasher::new();

    let mut buf = [0u8; 1024 * 64];
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        let chunk = &buf[..n];

        md5_ctx.consume(chunk);
        sha1_ctx.update(chunk);
        sha256_ctx.update(chunk);
        blake3_hasher.update(chunk);
    }

    Ok(Hashes {
        md5: format!("{:x}", md5_ctx.compute()),
        sha1: format!("{:x}", sha1_ctx.finalize()),
        sha256: format!("{:x}", sha256_ctx.finalize()),
        blake3: blake3_hasher.finalize().to_hex().to_string(),
    })
}

fn extract_strings(path: &Path) -> Result<StringsInfo, SandboxError> {
    let data = std::fs::read(path)?;
    
    // Extract ASCII strings (minimum 4 printable characters)
    let ascii_strings = extract_ascii_strings(&data);
    
    // Extract UTF-16LE strings
    let utf16le_strings = extract_utf16le_strings(&data);
    
    // Deduplicate and sort, take top samples
    let ascii_dedup: std::collections::HashSet<String> = ascii_strings.into_iter().collect();
    let mut ascii_samples: Vec<String> = ascii_dedup.into_iter().collect();
    ascii_samples.sort();
    ascii_samples.truncate(100); // Limit to top 100 samples
    
    let utf16le_dedup: std::collections::HashSet<String> = utf16le_strings.into_iter().collect();
    let mut utf16le_samples: Vec<String> = utf16le_dedup.into_iter().collect();
    utf16le_samples.sort();
    utf16le_samples.truncate(100); // Limit to top 100 samples
    
    Ok(StringsInfo {
        ascii_count: ascii_samples.len(),
        utf16le_count: utf16le_samples.len(),
        ascii_samples,
        utf16le_samples,
    })
}

fn extract_ascii_strings(data: &[u8]) -> Vec<String> {
    let mut strings = Vec::new();
    let mut current = Vec::new();
    const MIN_LENGTH: usize = 4;
    
    for &byte in data {
        // Printable ASCII range: 0x20 (space) to 0x7E (~)
        if (0x20..=0x7E).contains(&byte) {
            current.push(byte);
        } else {
            if current.len() >= MIN_LENGTH {
                if let Ok(s) = String::from_utf8(current.clone()) {
                    strings.push(s);
                }
            }
            current.clear();
        }
    }
    
    // Handle string at end of file
    if current.len() >= MIN_LENGTH {
        if let Ok(s) = String::from_utf8(current) {
            strings.push(s);
        }
    }
    
    strings
}

fn extract_utf16le_strings(data: &[u8]) -> Vec<String> {
    let mut strings = Vec::new();
    let mut current = Vec::new();
    const MIN_LENGTH: usize = 4;
    
    // Process in pairs for UTF-16LE
    let mut i = 0;
    while i + 1 < data.len() {
        let low = data[i];
        let high = data[i + 1];
        let code_unit = u16::from_le_bytes([low, high]);
        
        // Check if it's a printable character (basic range)
        // 0x0020-0x007E (printable ASCII) or 0x00A0-0xFFFD (extended)
        if (0x0020..=0x007E).contains(&code_unit) || (0x00A0..=0xFFFD).contains(&code_unit) {
            current.push(code_unit);
        } else {
            if current.len() >= MIN_LENGTH {
                if let Ok(s) = String::from_utf16(&current) {
                    strings.push(s);
                }
            }
            current.clear();
        }
        i += 2;
    }
    
    // Handle string at end
    if current.len() >= MIN_LENGTH {
        if let Ok(s) = String::from_utf16(&current) {
            strings.push(s);
        }
    }
    
    strings
}
