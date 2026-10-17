//! Encrypted, expiring media. The descriptor is secret and must travel inside MLS.

use std::{fs::File, io::Read, path::Path};

use anyhow::{Context, Result, anyhow, ensure};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{model::MESSAGE_TTL, transport::decode_ticket};

pub const CHUNK_SIZE: usize = 64 * 1024;
pub const MAX_MEDIA_BYTES: usize = 20 * 1024 * 1024;
pub const MAX_MEDIA_CHUNKS: u32 = (MAX_MEDIA_BYTES / CHUNK_SIZE) as u32;
const TAG_SIZE: usize = 16;
const MAX_NAME_BYTES: usize = 128;
const AAD_DOMAIN: &[u8] = b"clichat/media/chunk/v1\0";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MediaKind {
    Image,
    Audio,
    Video,
}

/// Contains the decryption key and bearer read capability; never publish or log it.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MediaDescriptor {
    pub id: String,
    pub name: String,
    pub kind: MediaKind,
    pub size: u64,
    pub chunks: u32,
    pub sha256: String,
    #[serde(with = "serde_base64")]
    pub key: Vec<u8>,
    #[serde(with = "serde_base64")]
    pub nonce_prefix: Vec<u8>,
    pub read_token: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub sources: Vec<String>,
}

impl std::fmt::Debug for MediaDescriptor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MediaDescriptor")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("kind", &self.kind)
            .field("size", &self.size)
            .field("chunks", &self.chunks)
            .field("sha256", &self.sha256)
            .field("key", &"[REDACTED]")
            .field("nonce_prefix", &"[REDACTED]")
            .field("read_token", &"[REDACTED]")
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("source_count", &self.sources.len())
            .finish()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MediaChunk {
    pub media_id: String,
    pub index: u32,
    pub created_at: i64,
    pub expires_at: i64,
    #[serde(with = "serde_base64")]
    pub ciphertext: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PreparedMedia {
    pub descriptor: MediaDescriptor,
    pub chunks: Vec<MediaChunk>,
}

impl MediaDescriptor {
    pub fn validate(&self, now: i64) -> Result<()> {
        ensure!(is_hex32(&self.id), "invalid media identifier");
        ensure!(is_hex32(&self.sha256), "invalid media digest");
        ensure!(is_hex32(&self.read_token), "invalid media read capability");
        ensure!(self.key.len() == 32, "invalid media key length");
        ensure!(self.nonce_prefix.len() == 16, "invalid media nonce prefix");
        ensure!(
            (1..=MAX_MEDIA_BYTES as u64).contains(&self.size),
            "invalid media size"
        );
        ensure!(
            self.chunks == self.size.div_ceil(CHUNK_SIZE as u64) as u32,
            "invalid media chunk count"
        );
        validate_lifetime(self.created_at, self.expires_at, now)?;
        validate_name(&self.name, &self.kind)?;
        ensure!(self.sources.len() <= 4, "too many media sources");
        for (index, source) in self.sources.iter().enumerate() {
            decode_ticket(source).context("invalid media source ticket")?;
            ensure!(
                !self.sources[..index].contains(source),
                "duplicate media source"
            );
        }
        Ok(())
    }

    fn plaintext_length(&self, index: u32) -> Result<usize> {
        ensure!(index < self.chunks, "media chunk index out of range");
        let offset = u64::from(index) * CHUNK_SIZE as u64;
        ensure!(offset < self.size, "media chunk offset out of range");
        Ok((self.size - offset).min(CHUNK_SIZE as u64) as usize)
    }
}

impl MediaChunk {
    /// Validation a ciphertext store can do without learning the descriptor key.
    pub fn validate(&self, now: i64) -> Result<()> {
        ensure!(is_hex32(&self.media_id), "invalid media identifier");
        ensure!(
            self.index < MAX_MEDIA_CHUNKS,
            "media chunk index out of range"
        );
        validate_lifetime(self.created_at, self.expires_at, now)?;
        ensure!(
            (TAG_SIZE + 1..=CHUNK_SIZE + TAG_SIZE).contains(&self.ciphertext.len()),
            "invalid media ciphertext length"
        );
        Ok(())
    }

    pub fn validate_for(&self, descriptor: &MediaDescriptor, now: i64) -> Result<()> {
        descriptor.validate(now)?;
        self.validate(now)?;
        self.matches_descriptor(descriptor)
    }

    fn matches_descriptor(&self, descriptor: &MediaDescriptor) -> Result<()> {
        ensure!(
            self.media_id == descriptor.id,
            "media chunk belongs to another file"
        );
        ensure!(
            self.created_at == descriptor.created_at && self.expires_at == descriptor.expires_at,
            "media chunk lifetime does not match descriptor"
        );
        ensure!(
            self.ciphertext.len() == descriptor.plaintext_length(self.index)? + TAG_SIZE,
            "media chunk has incorrect length"
        );
        Ok(())
    }
}

/// Reads at most the limit plus one byte. The original user file is never deleted.
/// Each call generates independent keys, identifiers, capabilities and nonce space.
pub fn prepare_file(path: &Path, sources: &[String], now: i64) -> Result<PreparedMedia> {
    ensure!(sources.len() <= 4, "too many media sources");
    let mut file = File::open(path).context("open media file")?;
    let metadata = file.metadata().context("read media file metadata")?;
    ensure!(metadata.is_file(), "media path is not a regular file");
    ensure!(
        metadata.len() <= MAX_MEDIA_BYTES as u64,
        "media file exceeds 20 MiB"
    );
    let extension = path
        .extension()
        .and_then(|s| s.to_str())
        .context("media file needs a supported extension")?
        .to_ascii_lowercase();
    let kind = extension_kind(&extension).context("unsupported media extension")?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(metadata.len() as usize));
    (&mut file)
        .take(MAX_MEDIA_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .context("read media file")?;
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_MEDIA_BYTES,
        "media file must be between 1 byte and 20 MiB"
    );
    ensure!(
        matches_magic(&extension, &bytes),
        "media contents do not match the file extension"
    );
    let expires_at = now
        .checked_add(MESSAGE_TTL)
        .context("invalid media creation time")?;
    let mut descriptor = MediaDescriptor {
        id: random_hex32()?,
        name: sanitized_name(path, &extension),
        kind,
        size: bytes.len() as u64,
        chunks: bytes.len().div_ceil(CHUNK_SIZE) as u32,
        sha256: hex::encode(Sha256::digest(&*bytes)),
        key: vec![0; 32],
        nonce_prefix: vec![0; 16],
        read_token: random_hex32()?,
        created_at: now,
        expires_at,
        sources: sources.to_vec(),
    };
    OsRng
        .try_fill_bytes(&mut descriptor.key)
        .map_err(|e| anyhow!("generate media key: {e}"))?;
    OsRng
        .try_fill_bytes(&mut descriptor.nonce_prefix)
        .map_err(|e| anyhow!("generate media nonce: {e}"))?;
    descriptor.validate(now)?;
    let cipher = cipher(&descriptor)?;
    let mut chunks = Vec::with_capacity(descriptor.chunks as usize);
    for (index, plaintext) in bytes.chunks(CHUNK_SIZE).enumerate() {
        let index = index as u32;
        let nonce = nonce(&descriptor, index);
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad(&descriptor, index),
                },
            )
            .map_err(|_| anyhow!("encrypt media chunk"))?;
        chunks.push(MediaChunk {
            media_id: descriptor.id.clone(),
            index,
            created_at: now,
            expires_at,
            ciphertext,
        });
    }
    Ok(PreparedMedia { descriptor, chunks })
}

pub fn decrypt_chunk(
    descriptor: &MediaDescriptor,
    chunk: &MediaChunk,
    now: i64,
) -> Result<Zeroizing<Vec<u8>>> {
    chunk.validate_for(descriptor, now)?;
    decrypt_validated_chunk(descriptor, chunk)
}

/// Requires exactly one copy of every chunk in ascending index order.
pub fn decrypt_complete(
    descriptor: &MediaDescriptor,
    chunks: &[MediaChunk],
    now: i64,
) -> Result<Zeroizing<Vec<u8>>> {
    descriptor.validate(now)?;
    ensure!(
        chunks.len() == descriptor.chunks as usize,
        "incomplete media chunk set"
    );
    let mut plaintext = Zeroizing::new(Vec::with_capacity(descriptor.size as usize));
    for (index, chunk) in chunks.iter().enumerate() {
        ensure!(
            chunk.index == index as u32,
            "media chunks are out of order or duplicated"
        );
        chunk.validate(now)?;
        chunk.matches_descriptor(descriptor)?;
        plaintext.extend_from_slice(&decrypt_validated_chunk(descriptor, chunk)?);
    }
    ensure!(
        plaintext.len() as u64 == descriptor.size,
        "incorrect complete media length"
    );
    ensure!(
        hex::encode(Sha256::digest(&*plaintext)) == descriptor.sha256,
        "media digest mismatch"
    );
    let extension = descriptor
        .name
        .rsplit_once('.')
        .context("invalid media name")?
        .1;
    ensure!(
        matches_magic(extension, &plaintext),
        "decrypted media format does not match its name"
    );
    Ok(plaintext)
}

fn decrypt_validated_chunk(
    descriptor: &MediaDescriptor,
    chunk: &MediaChunk,
) -> Result<Zeroizing<Vec<u8>>> {
    let nonce = nonce(descriptor, chunk.index);
    let plaintext = cipher(descriptor)?
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &chunk.ciphertext,
                aad: &aad(descriptor, chunk.index),
            },
        )
        .map_err(|_| anyhow!("media chunk authentication failed"))?;
    Ok(Zeroizing::new(plaintext))
}

fn cipher(descriptor: &MediaDescriptor) -> Result<XChaCha20Poly1305> {
    XChaCha20Poly1305::new_from_slice(&descriptor.key)
        .map_err(|_| anyhow!("invalid media encryption key"))
}

fn nonce(descriptor: &MediaDescriptor, index: u32) -> [u8; 24] {
    let mut nonce = [0; 24];
    nonce[..16].copy_from_slice(&descriptor.nonce_prefix);
    nonce[16..].copy_from_slice(&u64::from(index).to_be_bytes());
    nonce
}

fn aad(descriptor: &MediaDescriptor, index: u32) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_DOMAIN.len() + 64 + 32);
    aad.extend_from_slice(AAD_DOMAIN);
    aad.extend_from_slice(descriptor.id.as_bytes());
    aad.extend_from_slice(&index.to_be_bytes());
    aad.extend_from_slice(&descriptor.created_at.to_be_bytes());
    aad.extend_from_slice(&descriptor.expires_at.to_be_bytes());
    aad.extend_from_slice(&descriptor.chunks.to_be_bytes());
    aad.extend_from_slice(&descriptor.size.to_be_bytes());
    aad
}

fn random_hex32() -> Result<String> {
    let mut bytes = Zeroizing::new([0; 32]);
    OsRng
        .try_fill_bytes(&mut bytes[..])
        .map_err(|e| anyhow!("generate media randomness: {e}"))?;
    Ok(hex::encode(bytes.as_slice()))
}

fn is_hex32(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn validate_lifetime(created_at: i64, expires_at: i64, now: i64) -> Result<()> {
    ensure!(
        created_at >= 0 && expires_at.checked_sub(created_at) == Some(MESSAGE_TTL),
        "invalid media lifetime"
    );
    ensure!(
        created_at <= now.saturating_add(300),
        "media creation time is in the future"
    );
    ensure!(expires_at > now, "media expired");
    Ok(())
}

fn extension_kind(extension: &str) -> Option<MediaKind> {
    match extension {
        "png" | "jpg" | "jpeg" | "gif" | "webp" => Some(MediaKind::Image),
        "mp3" | "wav" | "flac" | "ogg" | "opus" | "m4a" => Some(MediaKind::Audio),
        "mp4" | "mov" | "webm" => Some(MediaKind::Video),
        _ => None,
    }
}

fn reserved_stem(stem: &str) -> bool {
    let upper = stem.to_ascii_uppercase();
    matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$")
        || matches!(
            upper.as_str(),
            "COM¹" | "COM²" | "COM³" | "LPT¹" | "LPT²" | "LPT³"
        )
        || ((upper.starts_with("COM") || upper.starts_with("LPT"))
            && upper.len() == 4
            && (b'1'..=b'9').contains(&upper.as_bytes()[3]))
}

fn sanitized_name(path: &Path, extension: &str) -> String {
    let input = path.file_stem().and_then(|s| s.to_str()).unwrap_or("media");
    let mut stem = String::new();
    for character in input.chars() {
        let character = if character.is_alphanumeric() || matches!(character, '_' | '-') {
            character
        } else {
            '_'
        };
        if stem.len() + character.len_utf8() > MAX_NAME_BYTES - extension.len() - 7 {
            break;
        }
        stem.push(character);
    }
    if stem.is_empty() {
        stem.push_str("media");
    }
    if reserved_stem(&stem) {
        stem.insert_str(0, "media_");
    }
    format!("{stem}.{extension}")
}

fn validate_name(name: &str, kind: &MediaKind) -> Result<()> {
    ensure!(name.len() <= MAX_NAME_BYTES, "media name too long");
    let (stem, extension) = name
        .rsplit_once('.')
        .context("media name needs an extension")?;
    ensure!(
        !stem.is_empty()
            && stem
                .chars()
                .all(|c| c.is_alphanumeric() || matches!(c, '_' | '-'))
            && !reserved_stem(stem),
        "unsafe media filename"
    );
    ensure!(
        extension_kind(extension).as_ref() == Some(kind),
        "media name and kind disagree"
    );
    Ok(())
}

/// Lightweight signatures only; this intentionally does not decode untrusted media.
fn matches_magic(extension: &str, bytes: &[u8]) -> bool {
    match extension {
        "png" => {
            bytes.len() >= 24
                && bytes.starts_with(b"\x89PNG\r\n\x1a\n")
                && bytes.get(12..16) == Some(b"IHDR")
        }
        "jpg" | "jpeg" => bytes.len() >= 4 && bytes.starts_with(b"\xff\xd8\xff"),
        "gif" => {
            bytes.len() >= 13 && (bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a"))
        }
        "webp" => {
            bytes.len() >= 20
                && bytes.starts_with(b"RIFF")
                && bytes.get(8..12) == Some(b"WEBP")
                && matches!(bytes.get(12..16), Some(b"VP8 " | b"VP8L" | b"VP8X"))
        }
        "wav" => {
            bytes.len() >= 36 && bytes.starts_with(b"RIFF") && bytes.get(8..12) == Some(b"WAVE")
        }
        "flac" => bytes.len() >= 42 && bytes.starts_with(b"fLaC") && bytes[4] & 0x7f == 0,
        "mp3" => valid_mp3_start(bytes),
        "ogg" | "opus" => valid_ogg_audio(bytes, extension == "opus"),
        "m4a" => valid_ftyp(bytes, &[b"M4A ", b"M4B "]),
        "mp4" => valid_ftyp(
            bytes,
            &[
                b"isom", b"iso2", b"iso3", b"iso4", b"iso5", b"iso6", b"mp41", b"mp42", b"avc1",
                b"dash", b"M4V ",
            ],
        ),
        "mov" => valid_ftyp(bytes, &[b"qt  "]),
        "webm" => {
            bytes.starts_with(b"\x1a\x45\xdf\xa3")
                && bytes[..bytes.len().min(4096)]
                    .windows(7)
                    .any(|w| w == b"\x42\x82\x84webm")
        }
        _ => false,
    }
}

fn valid_ftyp(bytes: &[u8], brands: &[&[u8; 4]]) -> bool {
    if bytes.len() < 16 || bytes.get(4..8) != Some(b"ftyp") {
        return false;
    }
    let length = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
    length >= 16
        && length <= bytes.len()
        && (length - 16).is_multiple_of(4)
        && brands.iter().any(|brand| &bytes[8..12] == *brand)
}

fn valid_mp3_start(bytes: &[u8]) -> bool {
    let frame = if bytes.starts_with(b"ID3") {
        if bytes.len() < 10
            || !(2..=4).contains(&bytes[3])
            || bytes[4] == 0xff
            || bytes[6..10].iter().any(|b| b & 0x80 != 0)
        {
            return false;
        }
        let size = bytes[6..10]
            .iter()
            .fold(0usize, |size, byte| (size << 7) | usize::from(*byte));
        let footer = if bytes[3] == 4 && bytes[5] & 0x10 != 0 {
            10
        } else {
            0
        };
        let Some(frame) = bytes.get(10 + size + footer..) else {
            return false;
        };
        frame
    } else {
        bytes
    };
    frame.len() >= 4
        && frame[0] == 0xff
        && frame[1] & 0xe0 == 0xe0
        && frame[1] & 0x18 != 0x08
        && frame[1] & 0x06 != 0
        && frame[2] & 0xf0 != 0
        && frame[2] & 0xf0 != 0xf0
        && frame[2] & 0x0c != 0x0c
}

fn valid_ogg_audio(bytes: &[u8], opus_only: bool) -> bool {
    if bytes.len() < 28 || !bytes.starts_with(b"OggS") || bytes[4] != 0 || bytes[5] & 2 == 0 {
        return false;
    }
    let segments = usize::from(bytes[26]);
    if segments == 0 {
        return false;
    }
    let Some(packet) = bytes.get(27 + segments..) else {
        return false;
    };
    (packet.len() >= 19 && packet.starts_with(b"OpusHead"))
        || (!opus_only && packet.len() >= 30 && packet.starts_with(b"\x01vorbis"))
}

/// Compact, bounded JSON representation; ciphertext is never an integer array.
pub mod serde_base64 {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let encoded = String::deserialize(deserializer)?;
        if encoded.len() > (super::CHUNK_SIZE + super::TAG_SIZE).div_ceil(3) * 4 {
            return Err(D::Error::custom("media base64 value too long"));
        }
        STANDARD.decode(encoded).map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    const NOW: i64 = 1_800_000_000;

    fn image_bytes(size: usize) -> Vec<u8> {
        assert!(size >= 33);
        let mut bytes = vec![0xa5; size];
        bytes[..8].copy_from_slice(b"\x89PNG\r\n\x1a\n");
        bytes[8..12].copy_from_slice(&13u32.to_be_bytes());
        bytes[12..16].copy_from_slice(b"IHDR");
        bytes[16..20].copy_from_slice(&1u32.to_be_bytes());
        bytes[20..24].copy_from_slice(&1u32.to_be_bytes());
        bytes
    }

    fn prepared(size: usize) -> PreparedMedia {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("picture.png");
        std::fs::write(&path, image_bytes(size)).unwrap();
        prepare_file(&path, &[], NOW).unwrap()
    }

    #[test]
    fn roundtrip_multiple_chunks_json_and_original_source_survives() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("照片 space.PNG");
        let bytes = image_bytes(CHUNK_SIZE + 19);
        std::fs::write(&path, &bytes).unwrap();
        let media = prepare_file(&path, &[], NOW).unwrap();
        assert!(path.exists());
        assert_eq!(media.descriptor.name, "照片_space.png");
        assert_eq!(media.descriptor.kind, MediaKind::Image);
        assert_eq!(media.descriptor.chunks, 2);
        assert_eq!(media.chunks[0].ciphertext.len(), CHUNK_SIZE + TAG_SIZE);
        assert_eq!(media.chunks[1].ciphertext.len(), 19 + TAG_SIZE);
        let json = serde_json::to_value(&media).unwrap();
        assert!(json["chunks"][0]["ciphertext"].is_string());
        assert!(json["descriptor"]["key"].is_string());
        let decoded: PreparedMedia = serde_json::from_value(json).unwrap();
        assert_eq!(decoded, media);
        assert_eq!(
            &*decrypt_complete(&decoded.descriptor, &decoded.chunks, NOW).unwrap(),
            &bytes
        );
    }

    #[test]
    fn ciphertext_key_nonce_and_bound_metadata_tampering_are_rejected() {
        let media = prepared(CHUNK_SIZE * 2);
        let mut bad = media.chunks[0].clone();
        bad.ciphertext[0] ^= 1;
        assert!(decrypt_chunk(&media.descriptor, &bad, NOW).is_err());
        bad = media.chunks[0].clone();
        bad.index = 1;
        assert!(decrypt_chunk(&media.descriptor, &bad, NOW).is_err());
        bad = media.chunks[0].clone();
        bad.ciphertext.pop();
        assert!(decrypt_chunk(&media.descriptor, &bad, NOW).is_err());
        bad = media.chunks[0].clone();
        bad.ciphertext.push(0);
        assert!(decrypt_chunk(&media.descriptor, &bad, NOW).is_err());

        let mut descriptor = media.descriptor.clone();
        descriptor.key[0] ^= 1;
        assert!(decrypt_chunk(&descriptor, &media.chunks[0], NOW).is_err());
        descriptor = media.descriptor.clone();
        descriptor.nonce_prefix[0] ^= 1;
        assert!(decrypt_chunk(&descriptor, &media.chunks[0], NOW).is_err());
        descriptor = media.descriptor.clone();
        descriptor.size -= 1;
        // The first chunk still has the expected length; authentication binds total size.
        assert!(decrypt_chunk(&descriptor, &media.chunks[0], NOW).is_err());
        descriptor = media.descriptor.clone();
        descriptor.created_at += 1;
        descriptor.expires_at += 1;
        bad = media.chunks[0].clone();
        bad.created_at += 1;
        bad.expires_at += 1;
        assert!(decrypt_chunk(&descriptor, &bad, NOW).is_err());
        descriptor = media.descriptor.clone();
        descriptor.id = "f".repeat(64);
        bad = media.chunks[0].clone();
        bad.media_id = descriptor.id.clone();
        assert!(decrypt_chunk(&descriptor, &bad, NOW).is_err());
    }

    #[test]
    fn complete_file_requires_order_exact_set_and_digest() {
        let media = prepared(CHUNK_SIZE * 2 + 3);
        let mut chunks = media.chunks.clone();
        chunks.swap(0, 1);
        assert!(decrypt_complete(&media.descriptor, &chunks, NOW).is_err());
        chunks = media.chunks.clone();
        chunks[1] = chunks[0].clone();
        assert!(decrypt_complete(&media.descriptor, &chunks, NOW).is_err());
        assert!(decrypt_complete(&media.descriptor, &media.chunks[..2], NOW).is_err());
        chunks = media.chunks.clone();
        chunks.push(chunks[0].clone());
        assert!(decrypt_complete(&media.descriptor, &chunks, NOW).is_err());
        let mut descriptor = media.descriptor.clone();
        descriptor.sha256 = "0".repeat(64);
        assert!(decrypt_complete(&descriptor, &media.chunks, NOW).is_err());
    }

    #[test]
    fn expiry_is_exactly_72_hours_and_cannot_be_extended_in_transit() {
        let media = prepared(64);
        let expiry = NOW + MESSAGE_TTL;
        assert!(decrypt_complete(&media.descriptor, &media.chunks, expiry - 1).is_ok());
        assert!(media.descriptor.validate(expiry).is_err());
        assert!(media.chunks[0].validate(expiry).is_err());
        assert!(decrypt_chunk(&media.descriptor, &media.chunks[0], expiry).is_err());
        assert!(media.descriptor.validate(NOW - 301).is_err());
        assert!(media.descriptor.validate(NOW - 300).is_ok());
        let mut descriptor = media.descriptor.clone();
        descriptor.expires_at += 1;
        assert!(descriptor.validate(NOW).is_err());
        descriptor.created_at = i64::MIN;
        descriptor.expires_at = i64::MAX;
        assert!(descriptor.validate(NOW).is_err());
    }

    #[test]
    fn encryption_owns_a_fresh_nonce_space_for_each_file() {
        let first = prepared(CHUNK_SIZE * 2);
        let second = prepared(CHUNK_SIZE * 2);
        assert_ne!(first.descriptor.id, second.descriptor.id);
        assert_ne!(first.descriptor.key, second.descriptor.key);
        assert_ne!(
            first.descriptor.nonce_prefix,
            second.descriptor.nonce_prefix
        );
        assert_ne!(first.descriptor.read_token, second.descriptor.read_token);
        assert_ne!(first.chunks[0].ciphertext, second.chunks[0].ciphertext);
        let zero = nonce(&first.descriptor, 0);
        let one = nonce(&first.descriptor, 1);
        assert_eq!(&zero[..16], &one[..16]);
        assert_ne!(zero, one);
        assert_eq!(&one[16..], &1u64.to_be_bytes());
        let mut substituted = second.chunks[0].clone();
        substituted.media_id = first.descriptor.id.clone();
        assert!(decrypt_chunk(&first.descriptor, &substituted, NOW).is_err());
    }

    #[test]
    fn debug_output_redacts_decryption_keys_and_read_capabilities() {
        let mut media = prepared(64);
        media.descriptor.key = vec![0x5a; 32];
        media.descriptor.nonce_prefix = vec![0x37; 16];
        media.descriptor.read_token = "ab".repeat(32);
        let debug = format!("{media:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(&format!("{:?}", media.descriptor.key)));
        assert!(!debug.contains(&format!("{:?}", media.descriptor.nonce_prefix)));
        assert!(!debug.contains(&media.descriptor.read_token));
    }

    #[test]
    fn chunk_and_file_size_limits_include_the_exact_twenty_mib_boundary() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("limit.png");
        let mut file = File::create(&path).unwrap();
        file.write_all(&image_bytes(33)).unwrap();
        file.set_len(MAX_MEDIA_BYTES as u64).unwrap();
        drop(file);
        let media = prepare_file(&path, &[], NOW).unwrap();
        assert_eq!(media.descriptor.size, MAX_MEDIA_BYTES as u64);
        assert_eq!(media.chunks.len(), MAX_MEDIA_CHUNKS as usize);
        assert_eq!(
            media.chunks.last().unwrap().ciphertext.len(),
            CHUNK_SIZE + TAG_SIZE
        );
        assert!(decrypt_complete(&media.descriptor, &media.chunks, NOW).is_ok());
        File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(MAX_MEDIA_BYTES as u64 + 1)
            .unwrap();
        assert!(prepare_file(&path, &[], NOW).is_err());
        std::fs::write(&path, b"").unwrap();
        assert!(prepare_file(&path, &[], NOW).is_err());
        let mut descriptor = media.descriptor.clone();
        descriptor.size = 0;
        assert!(descriptor.validate(NOW).is_err());
        descriptor.size = MAX_MEDIA_BYTES as u64 + 1;
        assert!(descriptor.validate(NOW).is_err());
        let mut chunk = media.chunks[0].clone();
        chunk.index = MAX_MEDIA_CHUNKS;
        assert!(chunk.validate(NOW).is_err());
        chunk.index = 0;
        chunk.ciphertext.resize(CHUNK_SIZE + TAG_SIZE + 1, 0);
        assert!(chunk.validate(NOW).is_err());
        chunk.ciphertext.resize(TAG_SIZE, 0);
        assert!(chunk.validate(NOW).is_err());
    }

    #[test]
    fn filenames_tickets_and_signatures_are_checked_before_opening_media() {
        let media = prepared(64);
        for name in [
            "../image.png",
            "C:\\image.png",
            "CON.png",
            "COM¹.png",
            "image.exe",
            "image.png.exe",
            "image\u{202e}.png",
            "image.PNG",
            "image?.png",
        ] {
            let mut descriptor = media.descriptor.clone();
            descriptor.name = name.into();
            assert!(descriptor.validate(NOW).is_err(), "accepted {name}");
        }
        let mut descriptor = media.descriptor.clone();
        descriptor.kind = MediaKind::Video;
        assert!(descriptor.validate(NOW).is_err());
        descriptor = media.descriptor.clone();
        descriptor.sources.push("not-a-ticket".into());
        assert!(descriptor.validate(NOW).is_err());
        descriptor.sources = vec![String::new(); 5];
        assert!(descriptor.validate(NOW).is_err());
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("program.png");
        std::fs::write(&path, b"MZ executable contents").unwrap();
        assert!(prepare_file(&path, &[], NOW).is_err());
        let path = directory.path().join("image.exe");
        std::fs::write(&path, image_bytes(64)).unwrap();
        assert!(prepare_file(&path, &[], NOW).is_err());
        assert!(!matches_magic("png", b"\x89PNG\r\n\x1a\n"));
        assert!(!matches_magic("ogg", b"OggS\0random non-audio bytes"));
        assert!(!matches_magic("mp3", b"ID3random non-audio bytes"));
        assert!(!matches_magic("webm", b"\x1a\x45\xdf\xa3not webm"));
    }

    #[test]
    fn media_headers_accept_common_audio_and_video_containers() {
        let mut wav = vec![0; 44];
        wav[..4].copy_from_slice(b"RIFF");
        wav[8..12].copy_from_slice(b"WAVE");
        assert!(matches_magic("wav", &wav));
        let mut mp4 = vec![0; 24];
        mp4[..4].copy_from_slice(&24u32.to_be_bytes());
        mp4[4..8].copy_from_slice(b"ftyp");
        mp4[8..12].copy_from_slice(b"isom");
        assert!(matches_magic("mp4", &mp4));
        assert!(!matches_magic("m4a", &mp4));
        mp4[8..12].copy_from_slice(b"M4A ");
        assert!(matches_magic("m4a", &mp4));
        assert!(matches_magic("mp3", b"\xff\xfb\x90\x64"));
        let mut ogg = vec![0; 28 + 19];
        ogg[..4].copy_from_slice(b"OggS");
        ogg[5] = 2;
        ogg[26] = 1;
        ogg[27] = 19;
        ogg[28..36].copy_from_slice(b"OpusHead");
        assert!(matches_magic("opus", &ogg));
        assert!(matches_magic("ogg", &ogg));
    }
}
