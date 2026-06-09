//! Key share storage under `./.secrets/<key_id>/<peer_id>.json`.

use std::fs;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use base64::Engine;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use serde::{Deserialize, Serialize};
use sl_dkls23::keygen::Keyshare;

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum KeyMaterial {
    /// Plain ECDSA private key (t = 1, n = 1).
    Singleton { private_key_hex: String },
    /// DKLs23 threshold key share.
    Threshold { keyshare_b64: String },
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ShareFile {
    pub key_id: String,
    pub peer_id: String,
    pub t: u8,
    pub n: u8,
    /// Compressed SEC1 public key, hex encoded (33 bytes).
    pub public_key_hex: String,
    #[serde(flatten)]
    pub material: KeyMaterial,
}

impl ShareFile {
    pub fn is_singleton(&self) -> bool {
        matches!(self.material, KeyMaterial::Singleton { .. })
    }

    pub fn keyshare(&self) -> Result<Keyshare> {
        match &self.material {
            KeyMaterial::Threshold { keyshare_b64 } => {
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(keyshare_b64)
                    .context("invalid base64 in keyshare")?;
                Keyshare::from_bytes(&bytes).context("invalid keyshare buffer")
            }
            KeyMaterial::Singleton { .. } => bail!("key {} is a singleton key", self.key_id),
        }
    }

    pub fn signing_key(&self) -> Result<k256::ecdsa::SigningKey> {
        match &self.material {
            KeyMaterial::Singleton { private_key_hex } => {
                let bytes = hex::decode(private_key_hex).context("invalid private key hex")?;
                k256::ecdsa::SigningKey::from_slice(&bytes).context("invalid private key")
            }
            KeyMaterial::Threshold { .. } => {
                bail!("key {} is a threshold key, not a singleton", self.key_id)
            }
        }
    }
}

/// Root directory for key material. Defaults to `./.secrets`; can be
/// overridden with `DKLS23CTL_SECRETS_DIR` (used by tests and QA scripts).
pub fn secrets_dir() -> PathBuf {
    match std::env::var_os("DKLS23CTL_SECRETS_DIR") {
        Some(dir) => PathBuf::from(dir),
        None => PathBuf::from("./.secrets"),
    }
}

pub fn share_path(key_id: &str, peer_id: &str) -> PathBuf {
    secrets_dir().join(key_id).join(format!("{peer_id}.json"))
}

pub fn exists(key_id: &str, peer_id: &str) -> bool {
    share_path(key_id, peer_id).exists()
}

pub fn save(share: &ShareFile) -> Result<PathBuf> {
    let path = share_path(&share.key_id, &share.peer_id);
    let dir = path.parent().unwrap();
    fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let data = serde_json::to_string_pretty(share)?;
    fs::write(&path, data).with_context(|| format!("writing {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(path)
}

pub fn load(key_id: &str, peer_id: &str) -> Result<ShareFile> {
    let path = share_path(key_id, peer_id);
    let data = fs::read_to_string(&path)
        .with_context(|| format!("no key share at {}", path.display()))?;
    let share: ShareFile =
        serde_json::from_str(&data).with_context(|| format!("parsing {}", path.display()))?;
    Ok(share)
}

pub fn load_opt(key_id: &str, peer_id: &str) -> Result<Option<ShareFile>> {
    if exists(key_id, peer_id) {
        Ok(Some(load(key_id, peer_id)?))
    } else {
        Ok(None)
    }
}

pub fn delete(key_id: &str, peer_id: &str) -> Result<()> {
    let path = share_path(key_id, peer_id);
    fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
    Ok(())
}

/// Find the public key for a key id by reading any stored share file.
pub fn public_key_hex(key_id: &str) -> Result<String> {
    let dir = secrets_dir().join(key_id);
    let entries = fs::read_dir(&dir)
        .with_context(|| format!("no shares for key id {key_id} under {}", dir.display()))?;
    for entry in entries {
        let entry = entry?;
        if entry.path().extension().is_some_and(|e| e == "json") {
            let data = fs::read_to_string(entry.path())?;
            let share: ShareFile = serde_json::from_str(&data)
                .with_context(|| format!("parsing {}", entry.path().display()))?;
            return Ok(share.public_key_hex);
        }
    }
    bail!("no share files found for key id {key_id}");
}

pub fn pubkey_hex_of(point: &k256::ProjectivePoint) -> String {
    hex::encode(point.to_affine().to_encoded_point(true).as_bytes())
}

pub fn keyshare_b64(share: &Keyshare) -> String {
    base64::engine::general_purpose::STANDARD.encode(share.as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn singleton_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("DKLS23CTL_SECRETS_DIR", dir.path());

        let sk = k256::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let pk = hex::encode(sk.verifying_key().to_encoded_point(true).as_bytes());
        let share = ShareFile {
            key_id: "k1".into(),
            peer_id: "p1".into(),
            t: 1,
            n: 1,
            public_key_hex: pk.clone(),
            material: KeyMaterial::Singleton {
                private_key_hex: hex::encode(sk.to_bytes()),
            },
        };
        save(&share).unwrap();
        let loaded = load("k1", "p1").unwrap();
        assert!(loaded.is_singleton());
        assert_eq!(loaded.public_key_hex, pk);
        assert_eq!(
            loaded.signing_key().unwrap().to_bytes(),
            sk.to_bytes()
        );
        assert_eq!(public_key_hex("k1").unwrap(), pk);

        delete("k1", "p1").unwrap();
        assert!(!exists("k1", "p1"));
    }
}
