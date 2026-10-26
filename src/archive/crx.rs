use anyhow::{anyhow, Result};
use sha2::{Digest, Sha256};

pub struct CrxHeader {
    pub version: u32,
    pub public_key: Option<Vec<u8>>,
    pub extension_id: Option<String>,
    pub zip_offset: usize,
}

/// Computes the 32-character Chrome extension ID from an RSA/ECDSA public key.
/// Chrome takes the first 128 bits (16 bytes) of the SHA-256 hash of the public key,
/// and maps each 4-bit nibble (0-15) to characters 'a' through 'p'.
pub fn compute_extension_id(public_key: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(public_key);
    let hash = hasher.finalize();

    let mut id = String::with_capacity(32);
    for byte in hash.iter().take(16) {
        let high = (byte >> 4) & 0x0F;
        let low = byte & 0x0F;
        id.push((b'a' + high) as char);
        id.push((b'a' + low) as char);
    }
    id
}

/// Parses a CRX binary header (supports both CRX2 and CRX3)
pub fn parse_crx_header(data: &[u8]) -> Result<CrxHeader> {
    if data.len() < 16 {
        return Err(anyhow!("File is too small to be a valid .crx archive"));
    }

    // Magic: "Cr24" -> 0x43, 0x72, 0x32, 0x34
    if &data[0..4] != b"Cr24" {
        return Err(anyhow!("Invalid CRX magic bytes. Expected 'Cr24'"));
    }

    let version = u32::from_le_bytes(data[4..8].try_into()?);

    match version {
        2 => {
            let pubkey_len = u32::from_le_bytes(data[8..12].try_into()?) as usize;
            let sig_len = u32::from_le_bytes(data[12..16].try_into()?) as usize;
            let header_len = 16 + pubkey_len + sig_len;

            if data.len() < header_len {
                return Err(anyhow!("Corrupt CRX2 header: payload smaller than declared lengths"));
            }

            let public_key = data[16..16 + pubkey_len].to_vec();
            let extension_id = Some(compute_extension_id(&public_key));

            Ok(CrxHeader {
                version: 2,
                public_key: Some(public_key),
                extension_id,
                zip_offset: header_len,
            })
        }
        3 => {
            let header_len = u32::from_le_bytes(data[8..12].try_into()?) as usize;
            let zip_offset = 12 + header_len;

            if data.len() < zip_offset {
                return Err(anyhow!("Corrupt CRX3 header: header length exceeds file size"));
            }

            let header_bytes = &data[12..zip_offset];
            let (public_key, extension_id) = extract_crx3_public_key(header_bytes);

            Ok(CrxHeader {
                version: 3,
                public_key,
                extension_id,
                zip_offset,
            })
        }
        _ => Err(anyhow!("Unsupported CRX version: {}", version)),
    }
}

/// Lightweight extraction of the public key from CRX3 protobuf header without requiring full protoc
fn extract_crx3_public_key(header_bytes: &[u8]) -> (Option<Vec<u8>>, Option<String>) {
    // In CRX3 protobuf header:
    // Field 2 (repeated AsymmetricKeyProof): tag 0x12
    // Inside AsymmetricKeyProof:
    // Field 1 (public_key): tag 0x0a
    // Let's search for standard DER / SubjectPublicKeyInfo header sequence: 0x30, 0x81/0x82...
    // or parse protobuf varints.
    let mut cursor = 0;
    while cursor < header_bytes.len() {
        let tag = header_bytes[cursor];
        cursor += 1;
        let wire_type = tag & 0x07;
        let _field_num = tag >> 3;

        match wire_type {
            0 => {
                // Varint
                while cursor < header_bytes.len() && (header_bytes[cursor] & 0x80) != 0 {
                    cursor += 1;
                }
                cursor += 1;
            }
            2 => {
                // Length-delimited
                let mut len: usize = 0;
                let mut shift = 0;
                while cursor < header_bytes.len() {
                    let b = header_bytes[cursor];
                    cursor += 1;
                    len |= ((b & 0x7F) as usize) << shift;
                    shift += 7;
                    if (b & 0x80) == 0 {
                        break;
                    }
                }
                if cursor + len <= header_bytes.len() {
                    let slice = &header_bytes[cursor..cursor + len];
                    // Check if this looks like a DER encoded RSA or ECDSA public key (starts with 0x30, 0x81 or 0x82)
                    if slice.len() >= 32 && slice[0] == 0x30 {
                        let pubkey = slice.to_vec();
                        let ext_id = compute_extension_id(&pubkey);
                        return (Some(pubkey), Some(ext_id));
                    }
                    // Or search recursively inside
                    if len > 4 {
                        let (inner_pk, inner_id) = extract_crx3_public_key(slice);
                        if inner_pk.is_some() {
                            return (inner_pk, inner_id);
                        }
                    }
                    cursor += len;
                } else {
                    break;
                }
            }
            _ => break,
        }
    }
    (None, None)
}
