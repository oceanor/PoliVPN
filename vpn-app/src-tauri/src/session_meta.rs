//! Metadati di sessione in `AppLocalData` (username, ricorda credenziali), separati dalla keychain.

use tauri::path::BaseDirectory;
use tauri::{AppHandle, Manager};

const FILE_NAME: &str = "session_meta.json";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SessionMeta {
    pub username: String,
    pub remember_credentials: bool,
}

pub fn write(app: &AppHandle, username: &str, remember_credentials: bool) -> Result<(), String> {
    let path = app
        .path()
        .resolve(FILE_NAME, BaseDirectory::AppLocalData)
        .map_err(|e| e.to_string())?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let meta = SessionMeta {
        username: username.to_string(),
        remember_credentials,
    };
    let json = serde_json::to_string_pretty(&meta).map_err(|e| e.to_string())?;
    std::fs::write(&path, json).map_err(|e| e.to_string())
}

pub fn read(app: &AppHandle) -> Result<Option<SessionMeta>, String> {
    let path = app
        .path()
        .resolve(FILE_NAME, BaseDirectory::AppLocalData)
        .map_err(|e| e.to_string())?;
    if !path.is_file() {
        return Ok(None);
    }
    let s = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
    serde_json::from_str(&s).map_err(|e| e.to_string())
}

pub fn clear(app: &AppHandle) {
    let Ok(path) = app.path().resolve(FILE_NAME, BaseDirectory::AppLocalData) else {
        return;
    };
    let _ = std::fs::remove_file(path);
}
