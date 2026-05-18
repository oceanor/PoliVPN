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
