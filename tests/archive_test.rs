use crx_gate::archive::crx::{compute_extension_id, parse_crx_header};
use crx_gate::archive::ExtensionPackage;
use std::fs::File;
use std::io::Write;

#[test]
fn test_crx2_binary_parsing() {
    let dummy_pubkey = b"sample_crx2_rsa_public_key_bytes_12345";
    let dummy_sig = b"sample_crx2_signature_bytes_67890";

    let mut binary = Vec::new();
    // Magic "Cr24"
    binary.extend_from_slice(b"Cr24");
    // Version 2 (u32 LE)
    binary.extend_from_slice(&2u32.to_le_bytes());
    // Pubkey length (u32 LE)
    binary.extend_from_slice(&(dummy_pubkey.len() as u32).to_le_bytes());
    // Sig length (u32 LE)
    binary.extend_from_slice(&(dummy_sig.len() as u32).to_le_bytes());
    // Pubkey bytes
    binary.extend_from_slice(dummy_pubkey);
    // Sig bytes
    binary.extend_from_slice(dummy_sig);
    // Trailing ZIP content dummy
    binary.extend_from_slice(b"PK\x03\x04dummy_zip");

    let header = parse_crx_header(&binary).expect("CRX2 header parsing should succeed");
    assert_eq!(header.version, 2);
    assert_eq!(header.public_key.as_deref(), Some(dummy_pubkey.as_slice()));
    assert!(header.extension_id.is_some());
    let ext_id = header.extension_id.unwrap();
    assert_eq!(ext_id.len(), 32);
    assert_eq!(ext_id, compute_extension_id(dummy_pubkey));
    assert_eq!(header.zip_offset, binary.len() - b"PK\x03\x04dummy_zip".len());
}

#[test]
fn test_crx3_binary_parsing() {
    let mut header_bytes = Vec::new();
    // Protobuf field 2: length delimited (wire type 2 -> tag 0x12)
    header_bytes.push(0x12);
    // Field length
    let sub_key = b"\x30\x82\x01sample_crx3_der_rsa_key_bytes_54321";
    header_bytes.push(sub_key.len() as u8);
    header_bytes.extend_from_slice(sub_key);

    let mut binary = Vec::new();
    binary.extend_from_slice(b"Cr24");
    // Version 3
    binary.extend_from_slice(&3u32.to_le_bytes());
    // Header length
    binary.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
    // Header bytes
    binary.extend_from_slice(&header_bytes);
    // Zip bytes
    binary.extend_from_slice(b"PK\x03\x04dummy_zip");

    let header = parse_crx_header(&binary).expect("CRX3 header parsing should succeed");
    assert_eq!(header.version, 3);
    assert!(header.extension_id.is_some());
    assert_eq!(header.extension_id.as_ref().unwrap().len(), 32);
    assert_eq!(header.zip_offset, 12 + header_bytes.len());
}

#[test]
fn test_corrupt_crx_handling() {
    // 1. Truncated
    let too_small = b"Cr24";
    assert!(parse_crx_header(too_small).is_err());

    // 2. Invalid magic
    let bad_magic = b"ABCD\x03\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00";
    assert!(parse_crx_header(bad_magic).is_err());

    // 3. Header length exceeds file length
    let mut header_overflow = Vec::new();
    header_overflow.extend_from_slice(b"Cr24");
    header_overflow.extend_from_slice(&3u32.to_le_bytes());
    header_overflow.extend_from_slice(&999999u32.to_le_bytes());
    header_overflow.extend_from_slice(b"short");
    assert!(parse_crx_header(&header_overflow).is_err());
}

#[test]
fn test_zip_slip_protection() {
    let temp_zip_path = "tests/fixtures/slip_test.zip";
    {
        let file = File::create(temp_zip_path).unwrap();
        let mut zip_writer = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);

        // Valid manifest
        zip_writer.start_file("manifest.json", options).unwrap();
        zip_writer.write_all(b"{\"manifest_version\": 3, \"name\": \"Slip Test\", \"version\": \"1.0.0\"}").unwrap();

        // Malicious entry attempting directory escape
        zip_writer.start_file("../../evil.js", options).unwrap();
        zip_writer.write_all(b"malicious();").unwrap();

        zip_writer.finish().unwrap();
    }

    let pkg = ExtensionPackage::load(temp_zip_path).expect("Should load zip package");
    assert_eq!(pkg.has_file("manifest.json"), true);
    // Malicious zip slip entry must be sanitized/discarded
    assert_eq!(pkg.has_file("../../evil.js"), false);
    assert_eq!(pkg.has_file("evil.js"), false);

    let _ = std::fs::remove_file(temp_zip_path);
}

#[test]
fn test_missing_manifest_returns_clean_error() {
    let temp_zip_path = "tests/fixtures/no_manifest.zip";
    {
        let file = File::create(temp_zip_path).unwrap();
        let mut zip_writer = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);

        zip_writer.start_file("random_file.txt", options).unwrap();
        zip_writer.write_all(b"hello world").unwrap();
        zip_writer.finish().unwrap();
    }

    let err = ExtensionPackage::load(temp_zip_path);
    assert!(err.is_err(), "Package without manifest.json must fail");
    let err_msg = err.unwrap_err().to_string();
    assert!(err_msg.contains("manifest.json"));

    let _ = std::fs::remove_file(temp_zip_path);
}
