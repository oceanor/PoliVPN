pub mod auth;
pub mod config_xml;
pub(crate) mod error_chain;
pub mod diag;
pub mod io;
pub mod ppp;
pub mod ppp_proto;
pub mod routes;
pub mod tls;
pub mod tls_http;
pub mod tun;

#[cfg(windows)]
pub mod net_windows;

/// MRU PPP / MTU TUN predefiniti (conservative per PPPoE + TLS + tunnel PPP).
pub const DEFAULT_TUNNEL_MTU: u16 = 1300;

/// Legge [`DEFAULT_TUNNEL_MTU`] oppure override `POLIVPN_TUNNEL_MTU` (576–1500).
pub fn tunnel_mtu_from_env() -> u16 {
    std::env::var("POLIVPN_TUNNEL_MTU")
        .ok()
        .and_then(|v| v.trim().parse::<u16>().ok())
        .filter(|m| (576..=1500).contains(m))
        .unwrap_or(DEFAULT_TUNNEL_MTU)
}

use thiserror::Error;

#[derive(Error, Debug)]
pub enum VpnError {
    #[error("Authentication error: {0}")]
    Auth(#[from] auth::AuthError),
    #[error("TLS error: {0}")]
    Tls(String),
    #[error("TUN device error: {0}")]
    Tun(String),
    #[error("PPP negotiation error: {0}")]
    Ppp(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Route configuration error: {0}")]
    Route(String),
}
