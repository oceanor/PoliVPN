use socket2::{SockRef, TcpKeepalive};
use std::time::Duration;

use tokio::net::TcpStream;
use native_tls::TlsConnector;
use tokio_native_tls::TlsStream;

pub fn insecure_tls_connector() -> Result<TlsConnector, String> {
    let connector = TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("Failed to create TLS connector: {}", e))?;
    Ok(connector)
}

pub async fn connect_insecure_tls(
    host: &str,
    port: u16,
) -> Result<TlsStream<TcpStream>, String> {
    tracing::debug!("TLS: connessione TCP a {}:{}...", host, port);
    let tcp = TcpStream::connect(format!("{}:{}", host, port))
        .await
        .map_err(|e| format!("TCP connect failed: {}", e))?;

    if let Err(e) = tcp.set_nodelay(true) {
        tracing::warn!("TCP_NODELAY non applicato: {}", e);
    }
    let ka = TcpKeepalive::new()
        .with_time(Duration::from_secs(30))
        .with_interval(Duration::from_secs(10));
    if let Err(e) = SockRef::from(&tcp).set_tcp_keepalive(&ka) {
        tracing::warn!("TCP keepalive non applicato: {}", e);
    }

    tracing::debug!("TLS: handshake verso host «{}»...", host);
    let connector = insecure_tls_connector()?;
    let tls_stream = tokio_native_tls::TlsConnector::from(connector)
        .connect(host, tcp)
        .await
        .map_err(|e| format!("TLS handshake failed: {}", e))?;

    tracing::debug!("TLS: handshake completato.");
    Ok(tls_stream)
}
