pub mod crx;

use anyhow::{anyhow, Context, Result};
use std::collections::HashMap;
use std::fs;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackageType {
    Directory,
    Crx { version: u32 },
    Zip,
}

#[derive(Debug, Clone)]
pub struct ExtensionPackage {
    pub root_path: PathBuf,
    pub package_type: PackageType,
    pub extension_id: Option<String>,
    pub files: HashMap<String, Vec<u8>>,
    pub total_size: usize,
}

impl ExtensionPackage {
    /// Loads an extension from an unpacked directory, a .crx file, or a .zip archive.
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        if !path.exists() {
            return Err(anyhow!("Target path does not exist: {}", path.display()));
        }

        if path.is_dir() {
            Self::load_from_directory(path)
        } else {
            let data = fs::read(path).with_context(|| format!("Failed to read file: {}", path.display()))?;
            if data.starts_with(b"Cr24") {
                Self::load_from_crx(path, &data)
            } else if data.starts_with(b"PK\x03\x04") || data.starts_with(b"PK\x05\x06") {
                Self::load_from_zip(path, &data)
            } else {
                Err(anyhow!(
                    "Unrecognized file format for '{}'. Must be an unpacked directory, .crx, or .zip archive.",
                    path.display()
                ))
            }
        }
    }

    fn load_from_directory(dir_path: &Path) -> Result<Self> {
        let mut files = HashMap::new();
        let mut total_size = 0;

        for entry in WalkDir::new(dir_path).into_iter().filter_map(|e| e.ok()) {
            if entry.file_type().is_file() {
                let rel_path = entry
                    .path()
                    .strip_prefix(dir_path)
                    .unwrap_or_else(|_| entry.path())
                    .to_string_lossy()
                    .replace('\\', "/");

                // Skip .git and typical non-extension metadata
                if rel_path.starts_with(".git/") || rel_path.starts_with("node_modules/") {
                    continue;
                }

                let content = fs::read(entry.path())
                    .with_context(|| format!("Failed reading file: {}", entry.path().display()))?;
                total_size += content.len();
                files.insert(rel_path, content);
            }
        }

        if !files.contains_key("manifest.json") {
            return Err(anyhow!(
                "Directory does not contain a 'manifest.json' at root: {}",
                dir_path.display()
            ));
        }

        Ok(ExtensionPackage {
            root_path: dir_path.to_path_buf(),
            package_type: PackageType::Directory,
            extension_id: None,
            files,
            total_size,
        })
    }

    fn load_from_crx(file_path: &Path, data: &[u8]) -> Result<Self> {
        let crx_header = crx::parse_crx_header(data)?;
        let zip_data = &data[crx_header.zip_offset..];
        let files = Self::extract_zip_entries(zip_data)?;
        let total_size = files.values().map(|v| v.len()).sum();

        if !files.contains_key("manifest.json") {
            return Err(anyhow!(
                "CRX archive does not contain a root 'manifest.json': {}",
                file_path.display()
            ));
        }

        Ok(ExtensionPackage {
            root_path: file_path.to_path_buf(),
            package_type: PackageType::Crx {
                version: crx_header.version,
            },
            extension_id: crx_header.extension_id,
            files,
            total_size,
        })
    }

    fn load_from_zip(file_path: &Path, data: &[u8]) -> Result<Self> {
        let files = Self::extract_zip_entries(data)?;
        let total_size = files.values().map(|v| v.len()).sum();

        if !files.contains_key("manifest.json") {
            return Err(anyhow!(
                "ZIP archive does not contain a root 'manifest.json': {}",
                file_path.display()
            ));
        }

        Ok(ExtensionPackage {
            root_path: file_path.to_path_buf(),
            package_type: PackageType::Zip,
            extension_id: None,
            files,
            total_size,
        })
    }

    fn extract_zip_entries(data: &[u8]) -> Result<HashMap<String, Vec<u8>>> {
        let reader = Cursor::new(data);
        let mut archive = zip::ZipArchive::new(reader)?;
        let mut files = HashMap::new();

        const MAX_TOTAL_UNCOMPRESSED_BYTES: usize = 200 * 1024 * 1024; // 200MB safety limit against zip bombs
        let mut uncompressed_bytes_read = 0;

        for i in 0..archive.len() {
            let mut file = archive.by_index(i)?;
            if file.is_dir() {
                continue;
            }

            let raw_name = file.name().replace('\\', "/");
            // Sanitize zip slip path traversal
            if raw_name.contains("../") || raw_name.starts_with('/') {
                continue;
            }

            let mut contents = Vec::with_capacity(file.size() as usize);
            file.read_to_end(&mut contents)?;
            uncompressed_bytes_read += contents.len();

            if uncompressed_bytes_read > MAX_TOTAL_UNCOMPRESSED_BYTES {
                return Err(anyhow!("Archive exceeds maximum uncompressed size safety threshold (zip bomb protection)"));
            }

            files.insert(raw_name, contents);
        }

        Ok(files)
    }

    pub fn read_file(&self, path: &str) -> Option<&[u8]> {
        let clean = path.trim_start_matches('/').replace('\\', "/");
        self.files.get(&clean).map(|v| v.as_slice())
    }

    pub fn read_text(&self, path: &str) -> Option<String> {
        self.read_file(path)
            .and_then(|bytes| String::from_utf8(bytes.to_vec()).ok())
    }

    pub fn has_file(&self, path: &str) -> bool {
        let clean = path.trim_start_matches('/').replace('\\', "/");
        self.files.contains_key(&clean)
    }

    pub fn js_files(&self) -> Vec<(&str, &str)> {
        self.files
            .iter()
            .filter(|(path, _)| {
                path.ends_with(".js")
                    || path.ends_with(".mjs")
                    || path.ends_with(".ts")
            })
            .filter_map(|(path, bytes)| {
                std::str::from_utf8(bytes).ok().map(|content| (path.as_str(), content))
            })
            .collect()
    }

    pub fn html_files(&self) -> Vec<(&str, &str)> {
        self.files
            .iter()
            .filter(|(path, _)| path.ends_with(".html") || path.ends_with(".htm"))
            .filter_map(|(path, bytes)| {
                std::str::from_utf8(bytes).ok().map(|content| (path.as_str(), content))
            })
            .collect()
    }

    pub fn json_files(&self) -> Vec<(&str, &str)> {
        self.files
            .iter()
            .filter(|(path, _)| path.ends_with(".json"))
            .filter_map(|(path, bytes)| {
                std::str::from_utf8(bytes).ok().map(|content| (path.as_str(), content))
            })
            .collect()
    }
}
