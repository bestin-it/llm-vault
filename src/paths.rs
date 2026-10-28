//! Per-OS locations and local (non-secret) app settings.
//!
//! Windows: %APPDATA%\bestin-it\LLM Vault\config, %LOCALAPPDATA%\bestin-it\LLM Vault\data
//! macOS:   ~/Library/Application Support/com.bestin-it.LLM-Vault
//! Linux:   ~/.config/llm-vault, ~/.local/share/llm-vault
//! Portable mode: a file named `portable` next to the executable keeps everything in ./data.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct Paths {
    pub config_dir: PathBuf,
    pub data_dir: PathBuf,
}

impl Paths {
    pub fn detect() -> Self {
        if let Ok(home) = std::env::var("LLMVAULT_HOME") {
            let p = PathBuf::from(home);
            return Paths { config_dir: p.clone(), data_dir: p };
        }
        if let Some(dir) = std::env::current_exe().ok().and_then(|e| e.parent().map(Path::to_path_buf)) {
            if dir.join("portable").exists() {
                let p = dir.join("data");
                return Paths { config_dir: p.clone(), data_dir: p };
            }
        }
        match directories::ProjectDirs::from("com", "bestin-it", "LLM Vault") {
            Some(d) => Paths { config_dir: d.config_dir().to_path_buf(), data_dir: d.data_local_dir().to_path_buf() },
            None => {
                let p = PathBuf::from(".llmvault");
                Paths { config_dir: p.clone(), data_dir: p }
            }
        }
    }

    pub fn for_dir(dir: &Path) -> Self {
        Paths { config_dir: dir.to_path_buf(), data_dir: dir.to_path_buf() }
    }

    pub fn settings_file(&self) -> PathBuf {
        self.config_dir.join("settings.json")
    }
    pub fn audit_db(&self) -> PathBuf {
        self.data_dir.join("audit.db")
    }
    pub fn default_vault(&self) -> PathBuf {
        self.data_dir.join("LLM Vault.kdbx")
    }
}

/// Local UI settings. Contains no secrets; security-relevant gateway settings live inside
/// the encrypted vault.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AppSettings {
    pub last_vault: Option<PathBuf>,
    pub recent_vaults: Vec<PathBuf>,
    pub last_keyfile: Option<PathBuf>,
    pub dark_mode: bool,
}

impl AppSettings {
    pub fn load(paths: &Paths) -> Self {
        std::fs::read_to_string(paths.settings_file()).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
    }

    pub fn save(&self, paths: &Paths) {
        let _ = std::fs::create_dir_all(&paths.config_dir);
        if let Ok(s) = serde_json::to_string_pretty(self) {
            let _ = std::fs::write(paths.settings_file(), s);
        }
    }

    pub fn remember_vault(&mut self, path: &Path) {
        self.last_vault = Some(path.to_path_buf());
        self.recent_vaults.retain(|p| p != path);
        self.recent_vaults.insert(0, path.to_path_buf());
        self.recent_vaults.truncate(8);
    }
}
