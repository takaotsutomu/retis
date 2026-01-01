//! Persistent node identity for distributed tracing.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::PathBuf;

use anyhow::{Context, Result};
use log::{debug, info};
use uuid::Uuid;

const NODE_ID_PATH: &str = "/etc/retis/node_id";

/// Manages persistent node identity
#[derive(Clone)]
pub struct NodeIdentity {
    node_id: Uuid,
    name: Option<String>,
    hostname: String,
}

impl NodeIdentity {
    /// Load or create a persistent node identity.
    ///
    /// The node ID is stored in `/etc/retis/node_id`.
    pub fn load_or_create(name: Option<String>) -> Result<Self> {
        let hostname = gethostname::gethostname().to_string_lossy().to_string();

        let path = PathBuf::from(NODE_ID_PATH);
        if path.exists() {
            if let Ok(node_id) = Self::load_from_file(&path) {
                debug!("Loaded node ID from {}", path.display());
                return Ok(Self {
                    node_id,
                    name,
                    hostname,
                });
            }
        }

        let node_id = Uuid::new_v4();
        info!("Generated new node ID: {}", node_id);

        Self::save_to_file(&path, &node_id)?;
        info!("Saved node ID to {}", path.display());

        Ok(Self {
            node_id,
            name,
            hostname,
        })
    }

    fn load_from_file(path: &PathBuf) -> Result<Uuid> {
        let mut file =
            File::open(path).with_context(|| format!("Failed to open {}", path.display()))?;

        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .with_context(|| format!("Failed to read {}", path.display()))?;

        let uuid_str = contents.trim();
        Uuid::parse_str(uuid_str)
            .with_context(|| format!("Invalid UUID in {}: '{}'", path.display(), uuid_str))
    }

    fn save_to_file(path: &PathBuf, node_id: &Uuid) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create directory {}", parent.display()))?;
        }

        let mut file =
            File::create(path).with_context(|| format!("Failed to create {}", path.display()))?;

        writeln!(file, "{}", node_id)
            .with_context(|| format!("Failed to write to {}", path.display()))?;

        Ok(())
    }

    pub fn uuid(&self) -> Uuid {
        self.node_id
    }

    /// Get the node ID as raw bytes.
    pub fn as_bytes(&self) -> [u8; 16] {
        *self.node_id.as_bytes()
    }

    /// Returns the user-provided name if set, otherwise the hostname.
    pub fn display_name(&self) -> &str {
        self.name.as_deref().unwrap_or(&self.hostname)
    }

    pub fn hostname(&self) -> &str {
        &self.hostname
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn save_and_load() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("node_id");

        let original_id = Uuid::new_v4();
        NodeIdentity::save_to_file(&path, &original_id).unwrap();

        let loaded_id = NodeIdentity::load_from_file(&path).unwrap();
        assert_eq!(original_id, loaded_id);
    }

    #[test]
    fn load_invalid_uuid() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("node_id");

        fs::write(&path, "not-a-valid-uuid\n").unwrap();

        let result = NodeIdentity::load_from_file(&path);
        assert!(result.is_err());
    }

    #[test]
    fn display_name() {
        // With custom name
        let identity = NodeIdentity {
            node_id: Uuid::new_v4(),
            name: Some("my-node".to_string()),
            hostname: "hostname123".to_string(),
        };
        assert_eq!(identity.display_name(), "my-node");

        // Falls back to hostname
        let identity = NodeIdentity {
            node_id: Uuid::new_v4(),
            name: None,
            hostname: "hostname123".to_string(),
        };
        assert_eq!(identity.display_name(), "hostname123");
    }
}
