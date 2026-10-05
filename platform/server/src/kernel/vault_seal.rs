//! AES-256-GCM seal for the in-process secret vault.
//!
//! KEK: `{CONNECTOR_DATA_DIR}/keys/vault.kek` (32 bytes, mode 0600).
//! Blob: `{CONNECTOR_DATA_DIR}/vault/secrets.bin` (`CVLT` + 12-byte nonce + ciphertext).

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use connector_engine::secret_store::SecretStore;
use std::fs;
use std::path::PathBuf;

const MAGIC: &[u8; 4] = b"CVLT";

fn data_dir() -> PathBuf {
    crate::kernel::nsfs::data_dir()
}

fn kek_path() -> PathBuf {
    data_dir().join("keys").join("vault.kek")
}

fn blob_path() -> PathBuf {
    data_dir().join("vault").join("secrets.bin")
}

fn chmod_0600(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
}

fn load_or_create_kek() -> Result<[u8; 32], String> {
    let path = kek_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("vault_kek_dir: {e}"))?;
    }
    if path.is_file() {
        let raw = fs::read(&path).map_err(|e| format!("vault_kek_read: {e}"))?;
        if raw.len() != 32 {
            return Err("vault_kek_invalid_len".into());
        }
        let mut k = [0u8; 32];
        k.copy_from_slice(&raw);
        chmod_0600(&path);
        return Ok(k);
    }
    let k: [u8; 32] = rand::random();
    fs::write(&path, k).map_err(|e| format!("vault_kek_write: {e}"))?;
    chmod_0600(&path);
    Ok(k)
}

fn seal(plain: &[u8]) -> Result<Vec<u8>, String> {
    let kek = load_or_create_kek()?;
    let cipher = Aes256Gcm::new_from_slice(&kek).map_err(|e| e.to_string())?;
    let nonce_bytes: [u8; 12] = rand::random();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, plain)
        .map_err(|e| format!("vault_seal: {e}"))?;
    let mut out = Vec::with_capacity(4 + 12 + ct.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn unseal(blob: &[u8]) -> Result<Vec<u8>, String> {
    if blob.len() < 16 || &blob[..4] != MAGIC {
        return Err("vault_blob_invalid".into());
    }
    let kek = load_or_create_kek()?;
    let cipher = Aes256Gcm::new_from_slice(&kek).map_err(|e| e.to_string())?;
    let nonce = Nonce::from_slice(&blob[4..16]);
    cipher
        .decrypt(nonce, &blob[16..])
        .map_err(|e| format!("vault_unseal: {e}"))
}

pub fn persist(store: &SecretStore) -> Result<(), String> {
    let json = store.to_persist_json();
    let plain = serde_json::to_vec(&json).map_err(|e| e.to_string())?;
    let sealed = seal(&plain)?;
    let path = blob_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("vault_dir: {e}"))?;
    }
    let tmp = path.with_extension("bin.tmp");
    fs::write(&tmp, &sealed).map_err(|e| format!("vault_write: {e}"))?;
    chmod_0600(&tmp);
    fs::rename(&tmp, &path).map_err(|e| format!("vault_rename: {e}"))?;
    chmod_0600(&path);
    Ok(())
}

pub fn load_store() -> Result<SecretStore, String> {
    let path = blob_path();
    if !path.is_file() {
        return Ok(SecretStore::new());
    }
    let blob = fs::read(&path).map_err(|e| format!("vault_read: {e}"))?;
    let plain = unseal(&blob)?;
    let v: serde_json::Value = serde_json::from_slice(&plain).map_err(|e| e.to_string())?;
    SecretStore::from_persist_json(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_seal() {
        let dir = std::env::temp_dir().join(format!(
            "connector-vault-test-{}",
            std::process::id()
        ));
        let _ = fs::create_dir_all(&dir);
        let prev = std::env::var("CONNECTOR_DATA_DIR").ok();
        std::env::set_var("CONNECTOR_DATA_DIR", &dir);
        let mut store = SecretStore::new();
        store
            .store_secret("k1", "agent_a", "super-secret", None, 1, "t")
            .unwrap();
        persist(&store).unwrap();
        let mut loaded = load_store().unwrap();
        let handle = loaded.issue_handle("k1", "agent_a").unwrap();
        assert_eq!(
            loaded.resolve_handle(&handle.handle_id, 1).unwrap(),
            "super-secret"
        );
        let _ = fs::remove_dir_all(&dir);
        match prev {
            Some(v) => std::env::set_var("CONNECTOR_DATA_DIR", v),
            None => std::env::remove_var("CONNECTOR_DATA_DIR"),
        }
    }
}
