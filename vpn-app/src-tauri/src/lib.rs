mod keyring;
mod session_meta;
mod vpn_session_snapshot;

use std::sync::Arc;
use tauri::path::BaseDirectory;
use tauri::{Emitter, Manager, State, WebviewUrl, WebviewWindowBuilder};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use vpn_core::auth::{normalize_gateway_host, FortiVpnAuth, VpnGateway};

#[derive(Clone, Debug, serde::Serialize)]
pub enum VpnStatus {
    Disconnected,
    Authenticating,
    Connecting,
    Connected,
    Disconnecting,
    Error(String),
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct LogEntry {
    pub timestamp: String,
    pub message: String,
}

/// Valori cablati **in compilazione** (variabili d’ambiente `POLIVPN_*` durante `cargo tauri build`).
#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallDefaults {
    pub gateway: Option<String>,
    pub port: Option<u16>,
    pub title: String,
}

/// `POLIVPN_VPN_TYPE` / `VPN_TYPE` in compilazione: `SPLIT` → tunnel split (serve `<addr>` nell’XML); altrimenti full-tunnel.
fn compile_time_vpn_full_tunnel() -> bool {
    match option_env!("POLIVPN_VPN_TYPE") {
        None => true,
        Some(s) => !matches!(s.trim().to_ascii_lowercase().as_str(), "split"),
    }
}

/// Sottotitolo sotto il logo; default **Connessione VPN** se `POLIVPN_TITLE` / `TITLE` assente o vuoto.
fn compile_time_brand_title() -> &'static str {
    const DEFAULT: &str = "Connessione VPN";
    match option_env!("POLIVPN_TITLE") {
        Some(s) => {
            let t = s.trim();
            if t.is_empty() {
                DEFAULT
            } else {
                t
            }
        }
        None => DEFAULT,
    }
}

#[tauri::command]
fn get_install_defaults() -> InstallDefaults {
    let gateway = option_env!("POLIVPN_DEFAULT_GATEWAY")
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(normalize_gateway_host);

    let port = option_env!("POLIVPN_DEFAULT_PORT").and_then(|s| s.trim().parse().ok());

    InstallDefaults {
        gateway,
        port,
        title: compile_time_brand_title().to_string(),
    }
}

#[tauri::command]
fn app_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

pub struct AppState {
    pub status: Arc<Mutex<VpnStatus>>,
    pub log_buffer: Arc<Mutex<Vec<LogEntry>>>,
    /// Token usato dal task [`vpn_core::io::IoLoop`]; alla disconnessione viene segnato.
    pub disconnect_token: Arc<Mutex<Option<CancellationToken>>>,
    pub io_handle: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
    #[cfg(windows)]
    pub installed_routes: Arc<Mutex<Vec<vpn_core::net_windows::InstalledRoute>>>,
    #[cfg(windows)]
    pub applied_dns: Arc<Mutex<Option<vpn_core::net_windows::InstalledDns>>>,
    #[cfg(windows)]
    pub nrpt_rules: Arc<Mutex<Vec<vpn_core::net_windows::NrptRule>>>,
    /// Route `/32` del server VPN sulla WAN (full-tunnel); viene rimossa per ultima sul teardown route.
    #[cfg(windows)]
    pub wan_host_route: Arc<Mutex<Option<vpn_core::net_windows::InstalledRoute>>>,
}

/// Tag stringa (`Disconnected`, `Authenticating`, …) inviato al frontend: il modulo confronta questo valore; un enum serializzato via Serde sarebbe oggetto, non stringa.
fn vpn_status_tag(status: &VpnStatus) -> &'static str {
    match status {
        VpnStatus::Disconnected => "Disconnected",
        VpnStatus::Authenticating => "Authenticating",
        VpnStatus::Connecting => "Connecting",
        VpnStatus::Connected => "Connected",
        VpnStatus::Disconnecting => "Disconnecting",
        VpnStatus::Error(_) => "Error",
    }
}

fn emit_status(app: &tauri::AppHandle, status: &VpnStatus) -> Result<(), String> {
    app.emit("vpn-status-changed", vpn_status_tag(status))
        .map_err(|e| e.to_string())
}

async fn store_and_emit_log(
    app: &tauri::AppHandle,
    buffer: &Arc<Mutex<Vec<LogEntry>>>,
    message: String,
) -> Result<(), String> {
    let timestamp = chrono::Local::now().format("%H:%M:%S").to_string();

    {
        let mut buf = buffer.lock().await;
        buf.push(LogEntry {
            timestamp: timestamp.clone(),
            message: message.clone(),
        });
        if buf.len() > 1000 {
            buf.remove(0);
        }
    }

    let entry = serde_json::json!({ "timestamp": timestamp, "message": message });
    app.emit("vpn-log", entry).map_err(|e| e.to_string())
}

/// Interrompe task I/O sul tunnel cancellando [`CancellationToken`] e [`JoinHandle`]; la risorsa TUN viene abbandonata dentro il task.
async fn teardown_io_task(state: &AppState) {
    if let Some(tok) = state.disconnect_token.lock().await.take() {
        tok.cancel();
    }
    if let Some(h) = state.io_handle.lock().await.take() {
        h.abort();
    }
}

/// Rimuove NRPT/DNS/route Windows installate dall’ultima sessione (`polivpn`).
#[cfg(windows)]
async fn teardown_windows_routes_dns_nrpt(app: &tauri::AppHandle, state: &AppState) {
    for rule in state.nrpt_rules.lock().await.drain(..) {
        if let Err(e) = vpn_core::net_windows::nrpt_remove(&rule) {
            store_and_emit_log(
                app,
                &state.log_buffer,
                format!("NRPT remove {}: {}", rule.namespace, e),
            )
            .await
            .ok();
        }
    }
    if let Some(applied) = state.applied_dns.lock().await.take() {
        if let Err(e) = vpn_core::net_windows::clear_dns(&applied) {
            store_and_emit_log(
                app,
                &state.log_buffer,
                format!("Clear DNS «{}»: {}", applied.iface_alias, e),
            )
            .await
            .ok();
        }
    }
    for route in state.installed_routes.lock().await.drain(..) {
        if let Err(e) = vpn_core::net_windows::del_split_route(&route) {
            store_and_emit_log(
                app,
                &state.log_buffer,
                format!("Del route {}: {}", route.prefix_cidr, e),
            )
            .await
            .ok();
        }
    }
    if let Some(pin) = state.wan_host_route.lock().await.take() {
        if let Err(e) = vpn_core::net_windows::del_split_route(&pin) {
            store_and_emit_log(
                app,
                &state.log_buffer,
                format!(
                    "Del route pin VPN sulla WAN ({}/{}): {}",
                    pin.prefix_cidr, pin.iface_alias, e
                ),
            )
            .await
            .ok();
        }
    }
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConnectPayload {
    gateway: String,
    port: u16,
    username: String,
    password: String,
    realm: String,
    remember_credentials: bool,
}

#[tauri::command]
async fn connect(
    state: State<'_, AppState>,
    app: tauri::AppHandle,
    payload: ConnectPayload,
) -> Result<(), String> {
    let ConnectPayload {
        gateway,
        port,
        username,
        password,
        realm,
        remember_credentials,
    } = payload;

    let result = async {
    let gateway = normalize_gateway_host(&gateway);

    #[cfg(windows)]
    teardown_windows_routes_dns_nrpt(&app, &state).await;

    teardown_io_task(&state).await;

    *state.status.lock().await = VpnStatus::Authenticating;
    emit_status(&app, &VpnStatus::Authenticating)?;

    store_and_emit_log(&app, &state.log_buffer, format!("Connessione a {}:{}...", gateway, port)).await?;

    let auth = FortiVpnAuth::new(VpnGateway {
        host: gateway.clone(),
        port,
    })
    .map_err(|e| format!("Failed to create client: {}", e))?;

    store_and_emit_log(&app, &state.log_buffer, "Autenticazione in corso...".into()).await?;

    let cookie = auth
        .login(&username, &password, &realm)
        .await
        .map_err(|e| {
            let msg = format!("Autenticazione fallita: {}", e);
            // `map_err` non può essere `async`: registrazione log e emissione evento isolate in `spawn`.
            let ts = chrono::Local::now().format("%H:%M:%S").to_string();
            let entry = LogEntry {
                timestamp: ts.clone(),
                message: msg.clone(),
            };
            let buf = state.log_buffer.clone();
            tokio::spawn(async move {
                let mut b = buf.lock().await;
                b.push(entry);
                if b.len() > 1000 {
                    b.remove(0);
                }
            });
            app.emit(
                "vpn-log",
                serde_json::json!({ "timestamp": ts, "message": msg.clone() }),
            )
            .ok();
            msg
        })?;

    store_and_emit_log(
        &app,
        &state.log_buffer,
        format!(
            "Autenticazione riuscita. Cookie: {}...",
            &cookie[..20.min(cookie.len())]
        ),
    ).await?;

    if !remember_credentials {
        session_meta::clear(&app);
    }

    *state.status.lock().await = VpnStatus::Connecting;
    emit_status(&app, &VpnStatus::Connecting)?;

    store_and_emit_log(&app, &state.log_buffer, "Richiesta allocazione VPN...".into()).await?;
    auth.request_vpn_allocation(&cookie)
        .await
        .map_err(|e| format!("Allocazione VPN fallita: {}", e))?;

    store_and_emit_log(&app, &state.log_buffer, "Scaricamento configurazione VPN...".into()).await?;

    let (diag_tx, mut diag_rx) = tokio::sync::mpsc::unbounded_channel();
    vpn_core::diag::set_sender(Some(diag_tx));
    let _diag_log_worker = {
        let app = app.clone();
        let buf = state.log_buffer.clone();
        tokio::spawn(async move {
            while let Some(msg) = diag_rx.recv().await {
                let _ = store_and_emit_log(&app, &buf, msg).await;
            }
        })
    };
    let _vpn_diag = vpn_core::diag::HookGuard::new();

    let vpn_config = {
        let mut tls_xml = vpn_core::tls::connect_insecure_tls(&gateway, port)
            .await
            .map_err(|e| format!("TLS dati (XML) fallita: {}", e))?;

        vpn_core::tls_http::fetch_vpn_config_xml(&mut tls_xml, &gateway, port, &cookie)
            .await
            .map_err(|e| format!("Config sulla sessione TLS: {}", e))?
    };

    store_and_emit_log(&app, &state.log_buffer, format!("IP assegnato: {}", vpn_config.assigned_ip)).await?;
    for dns in &vpn_config.dns_servers {
        store_and_emit_log(&app, &state.log_buffer, format!("DNS server: {}", dns)).await?;
    }

    store_and_emit_log(&app, &state.log_buffer, "Avvio tunnel...".into()).await?;

    let mut tls_stream = vpn_core::tls::connect_insecure_tls(&gateway, port)
        .await
        .map_err(|e| format!("TLS tunnel (dopo XML) fallita: {}", e))?;

    let mut tunnel_pending =
        vpn_core::tls_http::send_sslvpn_tunnel_get(&mut tls_stream, &cookie)
            .await
            .map_err(|e| format!("Tunnel start failed: {}", e))?;

    let mut ppp = vpn_core::ppp::PppSession::new();

    ppp.negotiate_lcp(&mut tls_stream, &mut tunnel_pending)
        .await
        .map_err(|e| format!("LCP failed: {}", e))?;

    let assigned_ip = ppp
        .negotiate_ipcp(&mut tls_stream, &mut tunnel_pending, &vpn_config.assigned_ip)
        .await
        .map_err(|e| format!("IPCP failed: {}", e))?;

    store_and_emit_log(&app, &state.log_buffer, format!("PPP ok. Local IP: {}", assigned_ip)).await?;

    store_and_emit_log(
        &app,
        &state.log_buffer,
        "Creazione scheda di rete virtuale (TUN)...".into(),
    )
    .await?;

    let tun = vpn_core::tun::TunDevice::create(&assigned_ip)
        .map_err(|e| format!("TUN creation failed: {}", e))?;

    store_and_emit_log(&app, &state.log_buffer, format!("TUN {} created", tun.name())).await?;

    #[cfg(windows)]
    {
        let alias = vpn_core::net_windows::resolve_iface_alias(tun.name());
        store_and_emit_log(
            &app,
            &state.log_buffer,
            format!("Alias interfaccia Windows (netsh): «{alias}»"),
        )
        .await?;

        state.installed_routes.lock().await.clear();
        *state.applied_dns.lock().await = None;
        state.nrpt_rules.lock().await.clear();

        if compile_time_vpn_full_tunnel() {
            store_and_emit_log(
                &app,
                &state.log_buffer,
                "Modalità full-tunnel IPv4 attiva.".into(),
            )
            .await?;

            let vpn_ip = vpn_core::net_windows::resolve_gateway_ip(&gateway)
                .map_err(|e| format!("Full-tunnel: {e}"))?;
            store_and_emit_log(
                &app,
                &state.log_buffer,
                format!(
                    "Server VPN risolto: {vpn_ip} (route /32 sulla WAN per evitare loop TLS)."
                ),
            )
            .await?;

            let wan = vpn_core::net_windows::read_wan_default(&[
                "Wintun Userspace Tunnel",
                "Wintun",
                "PoliVPN",
            ])
            .map_err(|e| format!("Full-tunnel (default WAN): {e}"))?;
            store_and_emit_log(
                &app,
                &state.log_buffer,
                format!(
                    "WAN per pin del server: alias «{}», next-hop «{}», if_index {}.",
                    wan.alias, wan.next_hop, wan.if_index,
                ),
            )
            .await?;

            let pin = vpn_core::net_windows::add_host_route_via_wan(&vpn_ip, &wan)
                .map_err(|e| format!("Full-tunnel (route host verso WAN): {e}"))?;
            *state.wan_host_route.lock().await = Some(pin);

            let halfs = vpn_core::net_windows::add_default_via_tunnel(&alias, &assigned_ip).map_err(
                |e| format!("Full-tunnel (half-default sulla TUN): {e}"),
            )?;
            let n_half = halfs.len();
            state.installed_routes.lock().await.extend(halfs);
            store_and_emit_log(
                &app,
                &state.log_buffer,
                format!(
                    "Full-tunnel: {n_half} route (0.0.0.0/1 + 128.0.0.0/1) su «{alias}» nexthop {assigned_ip}.",
                ),
            )
            .await?;

            if !vpn_config.dns_servers.is_empty() {
                match vpn_core::net_windows::apply_dns(&alias, &vpn_config.dns_servers) {
                    Ok(applied) => {
                        *state.applied_dns.lock().await = Some(applied);
                        store_and_emit_log(
                            &app,
                            &state.log_buffer,
                            format!(
                                "DNS applicati sulla TUN ({alias}): {:?}",
                                vpn_config.dns_servers,
                            ),
                        )
                        .await?;
                    }
                    Err(e) => {
                        store_and_emit_log(
                            &app,
                            &state.log_buffer,
                            format!("Full-tunnel: apply DNS fallito (continuo): {e}"),
                        )
                        .await?;
                    }
                }

                match vpn_core::net_windows::nrpt_add(".", &vpn_config.dns_servers) {
                    Ok(rule) if !rule.namespace.is_empty() => {
                        store_and_emit_log(
                            &app,
                            &state.log_buffer,
                            format!(
                                "NRPT catch-all («.») → server DNS {:?}",
                                vpn_config.dns_servers,
                            ),
                        )
                        .await?;
                        state.nrpt_rules.lock().await.push(rule);
                    }
                    Err(e) => {
                        store_and_emit_log(
                            &app,
                            &state.log_buffer,
                            format!("Full-tunnel: NRPT catch-all fallito: {e}"),
                        )
                        .await?;
                    }
                    _ => {}
                }
            } else {
                store_and_emit_log(
                    &app,
                    &state.log_buffer,
                    "WARN full-tunnel senza DNS nell’XML: risoluzione DNS e navigazione potrebbero fallire.".into(),
                )
                .await?;
            }
        } else {
            let mut ok_routes = 0usize;
            for (net, mask) in &vpn_config.split_routes {
                match vpn_core::net_windows::add_split_route(&alias, net, mask, &assigned_ip) {
                    Ok(r) => {
                        state.installed_routes.lock().await.push(r);
                        ok_routes += 1;
                    }
                    Err(e) => {
                        store_and_emit_log(
                            &app,
                            &state.log_buffer,
                            format!("Route {net} mask {mask}: {e}"),
                        )
                        .await?;
                    }
                }
            }
            if vpn_config.split_routes.is_empty() {
                store_and_emit_log(
                    &app,
                    &state.log_buffer,
                    "Nessuna route split dall’XML: il traffico LAN non verrà reindirizzato (chiedere al firewall di pubblicare gli <addr>)."
                        .into(),
                )
                .await?;
            } else if ok_routes > 0 {
                store_and_emit_log(
                    &app,
                    &state.log_buffer,
                    format!(
                        "Aggiunte {ok_routes}/{} route split su «{alias}» (nexthop {assigned_ip}).",
                        vpn_config.split_routes.len(),
                    ),
                )
                .await?;
            }

            if !vpn_config.dns_servers.is_empty() {
                match vpn_core::net_windows::apply_dns(&alias, &vpn_config.dns_servers) {
                    Ok(applied) => {
                        *state.applied_dns.lock().await = Some(applied);
                        store_and_emit_log(
                            &app,
                            &state.log_buffer,
                            format!(
                                "DNS applicati sulla TUN ({alias}): {:?}",
                                vpn_config.dns_servers,
                            ),
                        )
                        .await?;
                    }
                    Err(e) => {
                        store_and_emit_log(
                            &app,
                            &state.log_buffer,
                            format!("Apply DNS fallito (continuo senza DNS su TUN): {e}"),
                        )
                        .await?;
                    }
                }
            }

            if let Some(suffix) = vpn_config.dns_suffix.as_deref().filter(|s| !s.is_empty()) {
                if !vpn_config.dns_servers.is_empty() {
                    match vpn_core::net_windows::nrpt_add(suffix, &vpn_config.dns_servers) {
                        Ok(rule) if !rule.namespace.is_empty() => {
                            store_and_emit_log(
                                &app,
                                &state.log_buffer,
                                format!(
                                    "NRPT ({}) → server DNS {:?}",
                                    rule.namespace,
                                    vpn_config.dns_servers,
                                ),
                            )
                            .await?;
                            state.nrpt_rules.lock().await.push(rule);
                        }
                        Err(e) => {
                            store_and_emit_log(
                                &app,
                                &state.log_buffer,
                                format!("NRPT suffix «{suffix}» fallito: {e}"),
                            )
                            .await?;
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    #[cfg(not(windows))]
    if !vpn_config.split_routes.is_empty() {
        store_and_emit_log(
            &app,
            &state.log_buffer,
            "Route split: su questa piattaforma usa vpn-cli / vpn-helper manualmente.".into(),
        )
        .await?;
    }

    store_and_emit_log(
        &app,
        &state.log_buffer,
        "Avvio scambio traffico IP nel tunnel...".into(),
    )
    .await?;

    let cancel = CancellationToken::new();
    *state.disconnect_token.lock().await = Some(cancel.clone());

    let handle = tokio::spawn(async move {
        let io = vpn_core::io::IoLoop::new();
        let _ =
            io.run_with_cancel(&tun, &mut tls_stream, tunnel_pending, cancel)
                .await;
    });

    *state.io_handle.lock().await = Some(handle);

    *state.status.lock().await = VpnStatus::Connected;
    emit_status(&app, &VpnStatus::Connected)?;
    store_and_emit_log(&app, &state.log_buffer, "VPN connessa!".into()).await?;

    if remember_credentials {
        match keyring::save_credentials(&gateway, port, &username, &password) {
            Ok(()) => {
                if let Err(e) = session_meta::write(&app, &username, true) {
                    store_and_emit_log(
                        &app,
                        &state.log_buffer,
                        format!("Metadati «ricorda» non salvati: {}", e),
                    )
                    .await?;
                }
            }
            Err(e) => {
                store_and_emit_log(
                    &app,
                    &state.log_buffer,
                    format!("VPN connessa, ma salvataggio portachiavi fallito: {e}"),
                )
                .await?;
            }
        }
    }

    if let Err(e) = vpn_session_snapshot::write_active_session(&app, &state).await {
        store_and_emit_log(
            &app,
            &state.log_buffer,
            format!("Salvataggio stato sessione su disco fallito: {e}"),
        )
        .await?;
    }

    Ok(())
    }
    .await;

    if result.is_err() {
        let _ = vpn_session_snapshot::clear(&app);
        #[cfg(windows)]
        teardown_windows_routes_dns_nrpt(&app, &state).await;
        teardown_io_task(&state).await;
        *state.status.lock().await = VpnStatus::Disconnected;
        emit_status(&app, &VpnStatus::Disconnected)?;
    }

    result
}

async fn run_user_disconnect(app: &tauri::AppHandle, state: &AppState) -> Result<(), String> {
    *state.status.lock().await = VpnStatus::Disconnecting;
    emit_status(app, &VpnStatus::Disconnecting)?;

    store_and_emit_log(
        app,
        &state.log_buffer,
        "Disconnessione in corso...".into(),
    )
    .await?;

    #[cfg(windows)]
    teardown_windows_routes_dns_nrpt(app, state).await;

    teardown_io_task(state).await;

    *state.disconnect_token.lock().await = None;
    *state.io_handle.lock().await = None;

    *state.status.lock().await = VpnStatus::Disconnected;
    emit_status(app, &VpnStatus::Disconnected)?;
    store_and_emit_log(app, &state.log_buffer, "VPN disconnessa.".into()).await?;

    vpn_session_snapshot::clear(app)?;

    Ok(())
}

#[tauri::command]
async fn disconnect(
    state: State<'_, AppState>,
    app: tauri::AppHandle,
) -> Result<(), String> {
    run_user_disconnect(&app, &state).await
}

#[tauri::command]
async fn get_status_plain(state: State<'_, AppState>) -> Result<String, String> {
    Ok(vpn_status_tag(&*state.status.lock().await).to_string())
}

#[tauri::command]
async fn get_logs(state: State<'_, AppState>) -> Result<Vec<LogEntry>, String> {
    Ok(state.log_buffer.lock().await.clone())
}

#[tauri::command]
async fn append_client_log(
    state: State<'_, AppState>,
    app: tauri::AppHandle,
    message: String,
) -> Result<(), String> {
    store_and_emit_log(&app, &state.log_buffer, message).await
}

#[tauri::command]
async fn open_logs_window(app: tauri::AppHandle) -> Result<(), String> {
    if let Some(window) = app.get_webview_window("logs") {
        window.show().map_err(|e| e.to_string())?;
        window.set_focus().map_err(|e| e.to_string())?;
        return Ok(());
    }

    WebviewWindowBuilder::new(&app, "logs", WebviewUrl::App("logs.html".into()))
        .title("PoliVPN - Logs")
        .inner_size(480.0, 400.0)
        .resizable(true)
        .build()
        .map_err(|e| format!("Failed to create logs window: {}", e))?;

    Ok(())
}

#[tauri::command]
async fn save_credentials(
    gateway: String,
    port: u16,
    username: String,
    password: String,
) -> Result<(), String> {
    keyring::save_credentials(&gateway, port, &username, &password)
}

/// Metadati `session_meta.json` combinati alle credenziali nel portachiavi di sistema.
#[tauri::command]
async fn get_saved_credentials(app: tauri::AppHandle) -> Result<Option<serde_json::Value>, String> {
    let Some(meta) = session_meta::read(&app)? else {
        return Ok(None);
    };
    if !meta.remember_credentials {
        return Ok(None);
    }
    let Some(creds) = keyring::get_credentials(&meta.username)? else {
        return Ok(None);
    };
    let gateway = creds
        .get("gateway")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let port = creds
        .get("port")
        .and_then(|v| v.as_u64())
        .map(|n| n as u16)
        .or_else(|| {
            creds
                .get("port")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse().ok())
        });
    let password = creds
        .get("password")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let mut out = serde_json::Map::new();
    out.insert("username".to_string(), serde_json::json!(meta.username));
    out.insert("gateway".to_string(), serde_json::json!(gateway));
    if let Some(p) = port {
        out.insert("port".to_string(), serde_json::json!(p));
    }
    out.insert("password".to_string(), serde_json::json!(password));
    out.insert(
        "rememberCredentials".to_string(),
        serde_json::json!(meta.remember_credentials),
    );
    Ok(Some(serde_json::Value::Object(out)))
}

#[tauri::command]
fn exit_app(app: tauri::AppHandle) {
    app.exit(0);
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tracing_subscriber::fmt()
        .with_env_filter("vpn_core=debug,polivpn_app=info")
        .init();

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(AppState {
            status: Arc::new(Mutex::new(VpnStatus::Disconnected)),
            log_buffer: Arc::new(Mutex::new(Vec::new())),
            disconnect_token: Arc::new(Mutex::new(None)),
            io_handle: Arc::new(Mutex::new(None)),
            #[cfg(windows)]
            installed_routes: Arc::new(Mutex::new(Vec::new())),
            #[cfg(windows)]
            applied_dns: Arc::new(Mutex::new(None)),
            #[cfg(windows)]
            nrpt_rules: Arc::new(Mutex::new(Vec::new())),
            #[cfg(windows)]
            wan_host_route: Arc::new(Mutex::new(None)),
        })
        .setup(|app| {
            #[cfg(windows)]
            {
                match app
                    .path()
                    .resolve("resources/wintun.dll", BaseDirectory::Resource)
                {
                    Ok(path) if path.is_file() => {
                        if vpn_core::tun::set_wintun_dll_path(&path) {
                            tracing::info!("wintun.dll da {:?}", path);
                        } else {
                            tracing::warn!("set_wintun_dll_path: già impostato o file non valido");
                        }
                    }
                    Ok(path) => tracing::warn!(
                        "wintun.dll non trovato in Resource ({:?}), uso ricerca DLL predefinita",
                        path
                    ),
                    Err(e) => tracing::warn!(
                        "impossibile risolvere wintun.dll in Resource: {}",
                        e
                    ),
                }
            }

            let handle = app.handle().clone();
            let state = app.state::<AppState>();
            tauri::async_runtime::block_on(async {
                match vpn_session_snapshot::restore_into_state(&handle, &state).await {
                    Ok(true) => {
                        *state.status.lock().await = VpnStatus::Connected;
                        let _ = emit_status(&handle, &VpnStatus::Connected);
                        let _ = store_and_emit_log(
                            &handle,
                            &state.log_buffer,
                            "Sessione precedente: la VPN risultava connessa. Dopo la chiusura dell’app il tunnel non è più attivo — usa «Disconnetti» per ripulire route/DNS oppure riconnettiti.".into(),
                        )
                        .await;
                    }
                    Ok(false) => {}
                    Err(e) => tracing::warn!("vpn_session_snapshot ripristino: {}", e),
                }
            });

            Ok(())
        })
        .on_window_event(|window, event| {
            if window.label() != "main" {
                return;
            }
            let tauri::WindowEvent::CloseRequested { api, .. } = event else {
                return;
            };
            let app = window.app_handle().clone();
            let still_connected = tauri::async_runtime::block_on(async {
                matches!(
                    *app.state::<AppState>().status.lock().await,
                    VpnStatus::Connected
                )
            });
            if !still_connected {
                return;
            }
            api.prevent_close();
            let _ = app.emit("vpn-close-while-connected", ());
        })
        .invoke_handler(tauri::generate_handler![
            connect,
            disconnect,
            get_status_plain,
            get_logs,
            append_client_log,
            open_logs_window,
            save_credentials,
            get_saved_credentials,
            get_install_defaults,
            app_version,
            exit_app,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
