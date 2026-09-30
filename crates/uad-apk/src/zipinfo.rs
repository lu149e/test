//! Structural ZIP parsing needed for APK signature verification: End of Central Directory,
//! central directory location and the APK Signing Block that sits right before it.
//!
//! Content (entry data) is read through the `zip` crate; this module only deals with offsets.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

const EOCD_SIG: u32 = 0x0605_4b50;
const EOCD_MIN: u64 = 22;
const MAX_COMMENT: u64 = 0xFFFF;
const APK_SIG_BLOCK_MAGIC: &[u8; 16] = b"APK Sig Block 42";
/// Upper bound for the signing block we load into memory (real ones are a few KB; verity
/// padding keeps them under a few hundred KB).
const MAX_SIG_BLOCK: u64 = 64 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum ZipLayoutError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("not a ZIP archive: end of central directory not found")]
    NoEocd,
    #[error("ZIP64 archives are not supported by Android package verification")]
    Zip64,
    #[error("inconsistent ZIP structure: {0}")]
    Inconsistent(String),
    #[error("malformed APK Signing Block: {0}")]
    BadSigningBlock(String),
}

/// Offsets of the ZIP sections covered by v2+ signatures.
#[derive(Debug, Clone)]
pub struct ZipLayout {
    pub file_size: u64,
    pub cd_offset: u64,
    pub cd_size: u64,
    pub eocd_offset: u64,
    pub eocd: Vec<u8>,
    pub entry_count: u16,
    /// Present when the archive contains an APK Signing Block.
    pub signing_block: Option<SigningBlock>,
    /// Bytes before the first local file header (should be 0 for APKs).
    pub first_local_header_offset: Option<u64>,
    /// Entry names in central-directory order (as raw lossy UTF-8).
    pub entry_names: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SigningBlock {
    pub offset: u64,
    pub size: u64,
    /// (id, value) pairs.
    pub pairs: Vec<(u32, Vec<u8>)>,
}

impl SigningBlock {
    pub fn get(&self, id: u32) -> Option<&[u8]> {
        self.pairs.iter().find(|(i, _)| *i == id).map(|(_, v)| v.as_slice())
    }
}

fn read_at(f: &mut File, off: u64, len: usize) -> std::io::Result<Vec<u8>> {
    f.seek(SeekFrom::Start(off))?;
    let mut buf = vec![0u8; len];
    f.read_exact(&mut buf)?;
    Ok(buf)
}

fn le16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn le32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn le64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

impl ZipLayout {
    pub fn read(f: &mut File) -> Result<Self, ZipLayoutError> {
        let file_size = f.metadata()?.len();
        if file_size < EOCD_MIN {
            return Err(ZipLayoutError::NoEocd);
        }
        let tail_len = file_size.min(EOCD_MIN + MAX_COMMENT);
        let tail = read_at(f, file_size - tail_len, tail_len as usize)?;
        // Search backwards for an EOCD whose comment length reaches exactly the end of file.
        let mut eocd_pos = None;
        let max_start = tail.len() - EOCD_MIN as usize;
        for i in (0..=max_start).rev() {
            if le32(&tail, i) == EOCD_SIG {
                let comment_len = le16(&tail, i + 20) as usize;
                if i + EOCD_MIN as usize + comment_len == tail.len() {
                    eocd_pos = Some(i);
                    break;
                }
            }
        }
        let i = eocd_pos.ok_or(ZipLayoutError::NoEocd)?;
        let eocd = tail[i..].to_vec();
        let eocd_offset = file_size - tail_len + i as u64;
        let entry_count = le16(&eocd, 10);
        let cd_size = le32(&eocd, 12) as u64;
        let cd_offset = le32(&eocd, 16) as u64;
        if cd_offset == 0xFFFF_FFFF || cd_size == 0xFFFF_FFFF || entry_count == 0xFFFF {
            return Err(ZipLayoutError::Zip64);
        }
        if eocd_offset >= 20 {
            // ZIP64 EOCD locator immediately precedes the EOCD.
            let loc = read_at(f, eocd_offset - 20, 4)?;
            if le32(&loc, 0) == 0x0706_4b50 {
                return Err(ZipLayoutError::Zip64);
            }
        }
        if cd_offset + cd_size != eocd_offset {
            return Err(ZipLayoutError::Inconsistent(format!(
                "central directory ends at {} but EOCD starts at {}",
                cd_offset + cd_size,
                eocd_offset
            )));
        }

        let signing_block = Self::read_signing_block(f, cd_offset)?;
        let (first_local_header_offset, entry_names) = Self::scan_central_directory(f, cd_offset, cd_size)?;
        Ok(Self {
            file_size,
            cd_offset,
            cd_size,
            eocd_offset,
            eocd,
            entry_count,
            signing_block,
            first_local_header_offset,
            entry_names,
        })
    }

    fn read_signing_block(f: &mut File, cd_offset: u64) -> Result<Option<SigningBlock>, ZipLayoutError> {
        if cd_offset < 32 {
            return Ok(None);
        }
        let footer = read_at(f, cd_offset - 24, 24)?;
        if &footer[8..24] != APK_SIG_BLOCK_MAGIC {
            return Ok(None);
        }
        let size_in_footer = le64(&footer, 0);
        if !(24..=MAX_SIG_BLOCK).contains(&size_in_footer) {
            return Err(ZipLayoutError::BadSigningBlock(format!("size {size_in_footer} out of range")));
        }
        let total = size_in_footer + 8;
        if total > cd_offset {
            return Err(ZipLayoutError::BadSigningBlock("block extends before start of file".into()));
        }
        let offset = cd_offset - total;
        let block = read_at(f, offset, total as usize)?;
        if le64(&block, 0) != size_in_footer {
            return Err(ZipLayoutError::BadSigningBlock("header and footer sizes differ".into()));
        }
        let mut pairs = Vec::new();
        let mut p = 8usize;
        let end = block.len() - 24;
        while p < end {
            if p + 8 > end {
                return Err(ZipLayoutError::BadSigningBlock("truncated pair length".into()));
            }
            let len = le64(&block, p);
            if len < 4 || len > (end - p - 8) as u64 {
                return Err(ZipLayoutError::BadSigningBlock(format!("pair length {len} out of range")));
            }
            let id = le32(&block, p + 8);
            let value = block[p + 12..p + 8 + len as usize].to_vec();
            pairs.push((id, value));
            p += 8 + len as usize;
        }
        Ok(Some(SigningBlock { offset, size: total, pairs }))
    }

    fn scan_central_directory(f: &mut File, cd_offset: u64, cd_size: u64) -> Result<(Option<u64>, Vec<String>), ZipLayoutError> {
        if cd_size == 0 {
            return Ok((None, vec![]));
        }
        if cd_size > 256 * 1024 * 1024 {
            return Err(ZipLayoutError::Inconsistent("central directory larger than 256 MiB".into()));
        }
        let cd = read_at(f, cd_offset, cd_size as usize)?;
        let mut p = 0usize;
        let mut min: Option<u64> = None;
        let mut names = Vec::new();
        while p + 46 <= cd.len() && le32(&cd, p) == 0x0201_4b50 {
            let name_len = le16(&cd, p + 28) as usize;
            let extra_len = le16(&cd, p + 30) as usize;
            let comment_len = le16(&cd, p + 32) as usize;
            let lho = le32(&cd, p + 42) as u64;
            min = Some(min.map_or(lho, |m| m.min(lho)));
            let name = cd
                .get(p + 46..p + 46 + name_len)
                .ok_or_else(|| ZipLayoutError::Inconsistent("truncated central directory".into()))?;
            names.push(String::from_utf8_lossy(name).into_owned());
            p += 46 + name_len + extra_len + comment_len;
        }
        Ok((min, names))
    }

    /// Entry names that appear more than once (a known APK confusion attack vector).
    pub fn duplicate_entries(&self) -> Vec<String> {
        let mut seen = std::collections::HashSet::new();
        let mut dups: Vec<String> = self.entry_names.iter().filter(|n| !seen.insert(n.as_str())).cloned().collect();
        dups.dedup();
        dups
    }

    /// End of the "contents of ZIP entries" section (section 1 in the v2 spec).
    pub fn entries_end(&self) -> u64 {
        self.signing_block.as_ref().map_or(self.cd_offset, |b| b.offset)
    }

    /// EOCD with the central-directory offset replaced by the signing-block offset, as the
    /// v2 scheme requires for digesting.
    pub fn eocd_for_digest(&self) -> Vec<u8> {
        let mut e = self.eocd.clone();
        let off = self.entries_end() as u32;
        e[16..20].copy_from_slice(&off.to_le_bytes());
        e
    }
}
