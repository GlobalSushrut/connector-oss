//! In-process Hub index + package storage (Phase 4.3 MVP).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;

/// One published version of a plugin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HubPackageVersion {
    pub plugin_id: String,
    pub version: String,
    pub sha256: String,
    pub size: u64,
    pub rel_path: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub yanked: bool,
    /// Truncated README extracted from the `.cpkg` archive at publish time.
    #[serde(default)]
    pub readme_preview: Option<String>,
    /// Paths inside the archive (e.g. `screenshots/shot1.png`).
    #[serde(default)]
    pub screenshot_paths: Vec<String>,
    #[serde(default)]
    pub install_count: u64,
    #[serde(default)]
    pub avg_rating: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HubIndex {
    pub schema: u32,
    pub packages: Vec<HubPackageVersion>,
}

pub struct HubState {
    pub data_dir: PathBuf,
    index: RwLock<HubIndex>,
}

impl HubState {
    pub async fn load_or_empty(data_dir: PathBuf) -> Arc<Self> {
        let index_path = data_dir.join("index.json");
        let index = if index_path.exists() {
            let raw = tokio::fs::read_to_string(&index_path).await.unwrap_or_default();
            serde_json::from_str(&raw).unwrap_or_else(|_| HubIndex {
                schema: 1,
                packages: vec![],
            })
        } else {
            HubIndex {
                schema: 1,
                packages: vec![],
            }
        };
        Arc::new(Self {
            data_dir,
            index: RwLock::new(index),
        })
    }

    async fn persist(&self, idx: &HubIndex) -> std::io::Result<()> {
        let index_path = self.data_dir.join("index.json");
        if let Some(parent) = index_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let tmp = index_path.with_extension("json.tmp");
        tokio::fs::write(&tmp, serde_json::to_vec_pretty(idx)?).await?;
        tokio::fs::rename(&tmp, &index_path).await?;
        Ok(())
    }

    pub async fn search(&self, q: Option<&str>) -> Vec<HubPackageVersion> {
        let idx = self.index.read().await;
        let q_l = q.map(|s| s.to_ascii_lowercase());
        idx.packages
            .iter()
            .filter(|p| !p.yanked)
            .filter(|p| {
                q_l.as_ref().map_or(true, |qq| {
                    p.plugin_id.to_ascii_lowercase().contains(qq)
                        || p
                            .tags
                            .iter()
                            .any(|t| t.to_ascii_lowercase().contains(qq))
                        || p
                            .capabilities
                            .iter()
                            .any(|c| c.to_ascii_lowercase().contains(qq))
                })
            })
            .cloned()
            .collect()
    }

    pub async fn publish_cpkg(
        &self,
        bytes: &[u8],
        publish_token: Option<&str>,
        expected_token: Option<&str>,
    ) -> Result<HubPackageVersion, String> {
        match (expected_token, publish_token) {
            (Some(exp), Some(got)) if exp != got => {
                return Err("unauthorized: invalid publish token".into());
            }
            (Some(_), None) => {
                return Err("unauthorized: CONNECTOR_HUB_PUBLISH_TOKEN is set on the hub; send Authorization: Bearer <token>".into());
            }
            _ => {}
        }

        let bundle = connector_cpkg::read_cpkg(bytes).map_err(|e| e.to_string())?;
        bundle.manifest.validate().map_err(|e| e.to_string())?;
        let readme_preview = readme_preview_from_bundle(&bundle);
        let screenshot_paths = screenshot_paths_from_bundle(&bundle);
        let plugin_id = bundle.manifest.plugin.id.clone();
        let version = bundle.manifest.plugin.version.clone();

        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let sha256 = hex::encode(hasher.finalize());

        let safe = safe_plugin_filename(&plugin_id, &version);
        let rel_path = format!("packages/{safe}.cpkg");
        let abs = self.data_dir.join(&rel_path);
        if let Some(parent) = abs.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| e.to_string())?;
        }
        tokio::fs::write(&abs, bytes)
            .await
            .map_err(|e| e.to_string())?;

        let mut idx = self.index.write().await;
        let prev_install = idx
            .packages
            .iter()
            .find(|p| p.plugin_id == plugin_id && p.version == version)
            .map(|p| p.install_count)
            .unwrap_or(0);
        let row = HubPackageVersion {
            plugin_id: plugin_id.clone(),
            version: version.clone(),
            sha256,
            size: bytes.len() as u64,
            rel_path: rel_path.clone(),
            tags: Vec::new(),
            capabilities: bundle.manifest.capabilities.required.clone(),
            yanked: false,
            readme_preview,
            screenshot_paths,
            install_count: prev_install,
            avg_rating: idx
                .packages
                .iter()
                .find(|p| p.plugin_id == plugin_id && p.version == version)
                .and_then(|p| p.avg_rating),
        };

        idx.packages.retain(|p| !(p.plugin_id == plugin_id && p.version == version));
        idx.packages.push(row.clone());
        self.persist(&idx).await.map_err(|e| e.to_string())?;
        Ok(row)
    }

    pub async fn yank(&self, plugin_id: &str, version: &str) -> Result<(), String> {
        let mut idx = self.index.write().await;
        let mut hit = false;
        for p in &mut idx.packages {
            if p.plugin_id == plugin_id && p.version == version {
                p.yanked = true;
                hit = true;
            }
        }
        if !hit {
            return Err("package version not found".into());
        }
        self.persist(&idx).await.map_err(|e| e.to_string())
    }

    pub async fn get_version_bytes(
        &self,
        plugin_id: &str,
        version: &str,
    ) -> Result<Vec<u8>, String> {
        let idx = self.index.read().await;
        let row = idx
            .packages
            .iter()
            .find(|p| p.plugin_id == plugin_id && p.version == version && !p.yanked)
            .ok_or_else(|| "package not found".to_string())?;
        let abs = self.data_dir.join(&row.rel_path);
        tokio::fs::read(&abs).await.map_err(|e| e.to_string())
    }

    pub async fn latest_version(&self, plugin_id: &str) -> Option<String> {
        let idx = self.index.read().await;
        let mut best: Option<semver::Version> = None;
        let mut best_s: Option<String> = None;
        for p in &idx.packages {
            if p.plugin_id != plugin_id || p.yanked {
                continue;
            }
            if let Ok(v) = semver::Version::parse(&p.version) {
                if best.as_ref().map_or(true, |b| v > *b) {
                    best = Some(v);
                    best_s = Some(p.version.clone());
                }
            }
        }
        best_s
    }

    pub async fn record_package_download(&self, plugin_id: &str, version: &str) {
        let mut idx = self.index.write().await;
        let mut hit = false;
        for p in &mut idx.packages {
            if p.plugin_id == plugin_id && p.version == version && !p.yanked {
                p.install_count = p.install_count.saturating_add(1);
                hit = true;
                break;
            }
        }
        if hit {
            let _ = self.persist(&idx).await;
        }
    }
}

fn readme_preview_from_bundle(bundle: &connector_cpkg::CpkgBundle) -> Option<String> {
    for (path, bytes) in &bundle.files {
        if path.eq_ignore_ascii_case("README.md") {
            let s = String::from_utf8_lossy(bytes);
            return Some(s.chars().take(8000).collect());
        }
    }
    None
}

fn screenshot_paths_from_bundle(bundle: &connector_cpkg::CpkgBundle) -> Vec<String> {
    let mut out: Vec<String> = bundle
        .files
        .keys()
        .filter(|k| {
            let l = k.to_ascii_lowercase();
            l.starts_with("screenshots/")
                && (l.ends_with(".png")
                    || l.ends_with(".jpg")
                    || l.ends_with(".jpeg")
                    || l.ends_with(".webp"))
        })
        .cloned()
        .collect();
    out.sort();
    out
}

fn safe_plugin_filename(plugin_id: &str, version: &str) -> String {
    let mut s = format!("{}__{}", plugin_id.replace('/', "__"), version);
    for ch in &['/', '\\', ':', ' '] {
        s = s.replace(*ch, "_");
    }
    s
}

pub fn hub_data_dir() -> PathBuf {
    std::env::var("CONNECTOR_HUB_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| Path::new("./data/hub").to_path_buf())
}
