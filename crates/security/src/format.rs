//! Dependency-free structural validation for a deliberately small set of
//! supported file formats.
//!
//! This is not malware detection and not a general-purpose media parser. It
//! only rejects files whose bytes do not match the claimed extension, so an
//! extension allowlist cannot be satisfied by renaming arbitrary bytes. A file
//! that passes validation is still untrusted until an independent scanner
//! returns a clean result.

use std::str;

/// Formats this build can validate structurally without adding a dependency.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileFormat {
    Text,
    Png,
    Gif,
}

impl FileFormat {
    pub fn description(self) -> &'static str {
        match self {
            Self::Text => "UTF-8 text",
            Self::Png => "PNG image structure",
            Self::Gif => "GIF image structure",
        }
    }

    pub fn extensions(self) -> &'static [&'static str] {
        match self {
            Self::Text => &["txt"],
            Self::Png => &["png"],
            Self::Gif => &["gif"],
        }
    }

    /// Short uppercase label for encrypted attachment metadata. This is not a
    /// MIME type and makes no safety claim.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Text => "TXT",
            Self::Png => "PNG",
            Self::Gif => "GIF",
        }
    }
}

/// Validate that `bytes` match the format claimed by `name`.
///
/// Returns `None` for unknown extensions, path-like names, invalid UTF-8 text,
/// malformed image structure, and any content/extension mismatch. This is a
/// coarse structural check, not a claim that the content is harmless.
pub fn validate_format(name: &str, bytes: &[u8]) -> Option<FileFormat> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name
            .chars()
            .any(|character| character.is_control() || character == '/' || character == '\\')
    {
        return None;
    }
    let extension = name.rsplit_once('.').map(|(_, value)| value)?;
    if extension.is_empty() {
        return None;
    }
    if extension.eq_ignore_ascii_case("txt") {
        validate_text(bytes).then_some(FileFormat::Text)
    } else if extension.eq_ignore_ascii_case("png") {
        validate_png(bytes).then_some(FileFormat::Png)
    } else if extension.eq_ignore_ascii_case("gif") {
        validate_gif(bytes).then_some(FileFormat::Gif)
    } else {
        None
    }
}

fn validate_text(bytes: &[u8]) -> bool {
    let Ok(text) = str::from_utf8(bytes) else {
        return false;
    };
    !text
        .chars()
        .any(|character| character.is_control() && !matches!(character, '\t' | '\n' | '\r'))
}

const PNG_SIGNATURE: [u8; 8] = [137, 80, 78, 71, 13, 10, 26, 10];

fn validate_png(bytes: &[u8]) -> bool {
    if !bytes.starts_with(&PNG_SIGNATURE) {
        return false;
    }
    let mut position = PNG_SIGNATURE.len();
    let mut first = true;
    let mut saw_idat = false;
    let mut saw_iend = false;

    while position < bytes.len() {
        if bytes.len() - position < 12 {
            return false;
        }
        let length = u32::from_be_bytes([
            bytes[position],
            bytes[position + 1],
            bytes[position + 2],
            bytes[position + 3],
        ]) as usize;
        if length > bytes.len() - position - 12 {
            return false;
        }
        let kind = &bytes[position + 4..position + 8];
        if !kind.iter().all(|byte| byte.is_ascii_alphabetic()) {
            return false;
        }
        let data_start = position + 8;
        let crc_start = data_start + length;
        let expected_crc = u32::from_be_bytes([
            bytes[crc_start],
            bytes[crc_start + 1],
            bytes[crc_start + 2],
            bytes[crc_start + 3],
        ]);
        if crc32(&bytes[position + 4..crc_start]) != expected_crc {
            return false;
        }
        let data = &bytes[data_start..crc_start];

        if first {
            if kind != &b"IHDR"[..] || data.len() != 13 {
                return false;
            }
            let width = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
            let height = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
            if width == 0 || height == 0 || data[10] != 0 || data[11] != 0 || data[12] > 1 {
                return false;
            }
            if !valid_png_color_type(data[8], data[9]) {
                return false;
            }
            first = false;
        } else {
            if kind == &b"IHDR"[..] {
                return false;
            }
            if kind[0].is_ascii_uppercase()
                && kind != &b"PLTE"[..]
                && kind != &b"IDAT"[..]
                && kind != &b"IEND"[..]
            {
                return false;
            }
            if kind == &b"IDAT"[..] {
                saw_idat = true;
            }
            if kind == &b"IEND"[..] {
                if !data.is_empty() {
                    return false;
                }
                saw_iend = true;
                position = crc_start + 4;
                if position != bytes.len() {
                    return false;
                }
                break;
            }
        }
        position = crc_start + 4;
    }

    !first && saw_idat && saw_iend
}

fn valid_png_color_type(bit_depth: u8, color_type: u8) -> bool {
    match color_type {
        0 => matches!(bit_depth, 1 | 2 | 4 | 8 | 16),
        2 | 4 => matches!(bit_depth, 8 | 16),
        3 => matches!(bit_depth, 1 | 2 | 4 | 8),
        6 => matches!(bit_depth, 8 | 16),
        _ => false,
    }
}

const fn crc_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut index = 0usize;
    while index < 256 {
        let mut value = index as u32;
        let mut bit = 0usize;
        while bit < 8 {
            value = if value & 1 != 0 {
                0xedb8_8320 ^ (value >> 1)
            } else {
                value >> 1
            };
            bit += 1;
        }
        table[index] = value;
        index += 1;
    }
    table
}

static CRC_TABLE: [u32; 256] = crc_table();

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for byte in bytes {
        let index = ((crc ^ u32::from(*byte)) & 0xff) as usize;
        crc = CRC_TABLE[index] ^ (crc >> 8);
    }
    !crc
}

fn validate_gif(bytes: &[u8]) -> bool {
    if bytes.len() < 13 || (!bytes.starts_with(b"GIF87a") && !bytes.starts_with(b"GIF89a")) {
        return false;
    }
    let width = u16::from_le_bytes([bytes[6], bytes[7]]);
    let height = u16::from_le_bytes([bytes[8], bytes[9]]);
    if width == 0 || height == 0 {
        return false;
    }
    let packed = bytes[10];
    let mut position = 13usize;
    if packed & 0x80 != 0 && !skip_color_table(bytes, &mut position, packed & 0x07) {
        return false;
    }

    let mut saw_image = false;
    loop {
        if position >= bytes.len() {
            return false;
        }
        match bytes[position] {
            0x3b => return position + 1 == bytes.len() && saw_image,
            0x21 => {
                position += 1;
                if position >= bytes.len() {
                    return false;
                }
                position += 1;
                if !skip_sub_blocks(bytes, &mut position) {
                    return false;
                }
            }
            0x2c => {
                if bytes.len() - position < 10 {
                    return false;
                }
                let image_width = u16::from_le_bytes([bytes[position + 5], bytes[position + 6]]);
                let image_height = u16::from_le_bytes([bytes[position + 7], bytes[position + 8]]);
                if image_width == 0 || image_height == 0 {
                    return false;
                }
                let local_packed = bytes[position + 9];
                position += 10;
                if local_packed & 0x80 != 0
                    && !skip_color_table(bytes, &mut position, local_packed & 0x07)
                {
                    return false;
                }
                if position >= bytes.len() || !(2..=8).contains(&bytes[position]) {
                    return false;
                }
                position += 1;
                if !skip_sub_blocks(bytes, &mut position) {
                    return false;
                }
                saw_image = true;
            }
            _ => return false,
        }
    }
}

fn skip_color_table(bytes: &[u8], position: &mut usize, size_code: u8) -> bool {
    let size = 3usize << (size_code + 1);
    if bytes.len() - *position < size {
        return false;
    }
    *position += size;
    true
}

fn skip_sub_blocks(bytes: &[u8], position: &mut usize) -> bool {
    loop {
        if *position >= bytes.len() {
            return false;
        }
        let size = bytes[*position] as usize;
        *position += 1;
        if size == 0 {
            return true;
        }
        if bytes.len() - *position < size {
            return false;
        }
        *position += size;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn png_chunk(kind: &[u8; 4], data: &[u8]) -> Vec<u8> {
        let mut chunk = Vec::with_capacity(12 + data.len());
        chunk.extend_from_slice(&(data.len() as u32).to_be_bytes());
        chunk.extend_from_slice(kind);
        chunk.extend_from_slice(data);
        let mut crc_input = kind.to_vec();
        crc_input.extend_from_slice(data);
        chunk.extend_from_slice(&crc32(&crc_input).to_be_bytes());
        chunk
    }

    fn valid_png() -> Vec<u8> {
        let mut bytes = PNG_SIGNATURE.to_vec();
        let mut ihdr = Vec::new();
        ihdr.extend_from_slice(&1u32.to_be_bytes());
        ihdr.extend_from_slice(&1u32.to_be_bytes());
        ihdr.extend_from_slice(&[8, 2, 0, 0, 0]);
        bytes.extend_from_slice(&png_chunk(b"IHDR", &ihdr));
        bytes.extend_from_slice(&png_chunk(b"IDAT", &[]));
        bytes.extend_from_slice(&png_chunk(b"IEND", &[]));
        bytes
    }

    fn valid_gif() -> Vec<u8> {
        let mut bytes = b"GIF89a".to_vec();
        bytes.extend_from_slice(&[1, 0, 1, 0, 0, 0, 0]);
        bytes.extend_from_slice(&[0x2c, 0, 0, 0, 0, 1, 0, 1, 0, 0, 2, 0, 0x3b]);
        bytes
    }

    #[test]
    fn text_validation_rejects_extension_mismatch_and_control_bytes() {
        assert_eq!(
            validate_format("notes.txt", b"hello\nworld"),
            Some(FileFormat::Text)
        );
        assert_eq!(validate_format("notes.txt", b"GIF89a\x00"), None);
        assert_eq!(validate_format("notes.txt", b"a\0b"), None);
        assert_eq!(validate_format("../notes.txt", b"hello"), None);
        assert_eq!(validate_format("notes.bin", b"hello"), None);
    }

    #[test]
    fn png_validation_checks_signature_chunks_and_crc() {
        let valid = valid_png();
        assert_eq!(validate_format("image.PNG", &valid), Some(FileFormat::Png));

        let mut bad_crc = valid.clone();
        let crc_index = bad_crc.len() - 8;
        bad_crc[crc_index] ^= 1;
        assert_eq!(validate_format("image.png", &bad_crc), None);

        let mut trailing = valid;
        trailing.push(0);
        assert_eq!(validate_format("image.png", &trailing), None);
        assert_eq!(validate_format("image.png", b"not a png"), None);
    }

    #[test]
    fn gif_validation_checks_header_blocks_and_trailer() {
        let valid = valid_gif();
        assert_eq!(validate_format("move.GIF", &valid), Some(FileFormat::Gif));

        let mut truncated = valid.clone();
        truncated.pop();
        assert_eq!(validate_format("move.gif", &truncated), None);

        let mut bad_header = valid;
        bad_header[0] = b'X';
        assert_eq!(validate_format("move.gif", &bad_header), None);
    }
}
