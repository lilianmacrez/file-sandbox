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

pub fn analyze_file(path: &Path) -> Result<ArtifactReport, SandboxError> {
    let meta = std::fs::metadata(path)?;
    let size = meta.len();

    let hashes = compute_hashes(path)?;

    Ok(ArtifactReport {
        schema_version: 1,
        file: FileInfo {
            path: path.display().to_string(),
            size_bytes: size,
            hashes,
        },
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
