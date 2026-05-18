//! Snapshot su disco dopo connessione: stato «connesso» e riferimento a route/DNS/NRPT Windows.
//! Al riavvio il tunnel TLS/TUN non è attivo; servono comunque teardown e pulsante «Disconnetti» coerenti.

use serde::{Deserialize, Serialize};
use tauri::path::BaseDirectory;
use tauri::{AppHandle, Manager};

#[cfg(windows)]
use crate::AppState;

const FILE_NAME: &str = "vpn_session_snapshot.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteSnap {
    pub prefix_cidr: String,
    pub iface_alias: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsSnap {
    pub iface_alias: String,
    pub had_servers: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NrptSnap {
    pub namespace: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowsNetSnapshot {
    pub routes: Vec<RouteSnap>,
    pub dns: Option<DnsSnap>,
    pub nrpt: Vec<NrptSnap>,
    pub wan_host: Option<RouteSnap>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VpnSessionSnapshot {
    pub v: u32,
    pub active: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub windows: Option<WindowsNetSnapshot>,
}

fn path(app: &AppHandle) -> Result<std::path::PathBuf, String> {
    app.path()
        .resolve(FILE_NAME, BaseDirectory::AppLocalData)
        .map_err(|e| e.to_string())
}

pub fn clear(app: &AppHandle) -> Result<(), String> {
    let p = path(app)?;
    if p.is_file() {
        std::fs::remove_file(&p).map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[cfg(windows)]
pub async fn write_active_session(app: &AppHandle, state: &AppState) -> Result<(), String> {
    let routes: Vec<RouteSnap> = state
        .installed_routes
        .lock()
        .await
        .iter()
        .map(|r| RouteSnap {
            prefix_cidr: r.prefix_cidr.clone(),
            iface_alias: r.iface_alias.clone(),
        })
        .collect();
    let dns = state.applied_dns.lock().await.as_ref().map(|d| DnsSnap {
        iface_alias: d.iface_alias.clone(),
        had_servers: d.had_servers,
    });
    let nrpt: Vec<NrptSnap> = state
        .nrpt_rules
        .lock()
        .await
        .iter()
        .map(|n| NrptSnap {
            namespace: n.namespace.clone(),
        })
        .collect();
    let wan_host = state
        .wan_host_route
        .lock()
        .await
        .as_ref()
        .map(|r| RouteSnap {
            prefix_cidr: r.prefix_cidr.clone(),
            iface_alias: r.iface_alias.clone(),
        });

    let snap = VpnSessionSnapshot {
        v: 1,
        active: true,
        windows: Some(WindowsNetSnapshot {
            routes,
            dns,
            nrpt,
            wan_host,
        }),
    };

    let p = path(app)?;
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let json = serde_json::to_string_pretty(&snap).map_err(|e| e.to_string())?;
    std::fs::write(&p, json).map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(not(windows))]
pub async fn write_active_session(_app: &AppHandle, _state: &AppState) -> Result<(), String> {
    Ok(())
}

pub fn read(app: &AppHandle) -> Result<Option<VpnSessionSnapshot>, String> {
    let p = path(app)?;
    if !p.is_file() {
        return Ok(None);
    }
    let s = std::fs::read_to_string(&p).map_err(|e| e.to_string())?;
    serde_json::from_str(&s).map_err(|e| e.to_string())
}

#[cfg(windows)]
pub async fn restore_into_state(app: &AppHandle, state: &AppState) -> Result<bool, String> {
    let Some(mut snap) = read(app)? else {
        return Ok(false);
    };
    if !snap.active {
        let _ = clear(app);
        return Ok(false);
    }
    let Some(w) = snap.windows.take() else {
        let _ = clear(app);
        return Ok(false);
    };

    *state.installed_routes.lock().await = w
        .routes
        .into_iter()
        .map(|r| vpn_core::net_windows::InstalledRoute {
            prefix_cidr: r.prefix_cidr,
            iface_alias: r.iface_alias,
        })
        .collect();
    *state.applied_dns.lock().await = w.dns.map(|d| vpn_core::net_windows::InstalledDns {
        iface_alias: d.iface_alias,
        had_servers: d.had_servers,
    });
    *state.nrpt_rules.lock().await = w
        .nrpt
        .into_iter()
        .map(|n| vpn_core::net_windows::NrptRule {
            namespace: n.namespace,
        })
        .collect();
    *state.wan_host_route.lock().await = w.wan_host.map(|r| vpn_core::net_windows::InstalledRoute {
        prefix_cidr: r.prefix_cidr,
        iface_alias: r.iface_alias,
    });
    Ok(true)
}

#[cfg(not(windows))]
pub async fn restore_into_state(_app: &AppHandle, _state: &AppState) -> Result<bool, String> {
    Ok(false)
}
