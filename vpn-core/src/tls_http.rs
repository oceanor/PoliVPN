//! HTTP/1.1 minimale su [`TlsStream`]. Il GET XML può usare una TLS che viene poi chiusa;
//! il GET `/remote/sslvpn-tunnel` usa una **seconda** connessione TLS dedicata al tunnel.

use std::collections::HashMap;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use tokio_native_tls::TlsStream;

use crate::auth::{preview_config_body, response_looks_like_html_portal, VpnConfig};
use crate::diag;

const UA: &str = "Mozilla/5.0 SV1";
const READ_TIMEOUT: Duration = Duration::from_secs(45);
const TUNNEL_HDR_TIMEOUT: Duration = Duration::from_secs(45);
/// Dopo `GET sslvpn-tunnel` molti gateway Fortinet non inviano byte finché il client non inizia il PPP; peek breve per non bloccare 45 s.
const TUNNEL_FIRST_PEEK_TIMEOUT: Duration = Duration::from_millis(1500);
const TUNNEL_RAW_READ_TIMEOUT: Duration = Duration::from_millis(1500);
/// Letturi consecutive in timeout mentre il prefisso è ancora `NeedMoreBytes` prima di accettare il buffer e passare al PPP.
const TUNNEL_NEED_MORE_MAX_STALLS: u32 = 10;

/// Elimina `Nome=` senza valore dopo `=` — nella Cookie alcuni gateway mandano `SVPNNETWORKCOOKIE=;` che può rompere la richiesta tunnel.
fn sanitize_cookie_header(cookie: &str) -> String {
    let joined = cookie
        .split(';')
        .filter_map(|seg| {
            let seg = seg.trim();
            if seg.is_empty() {
                return None;
            }
            let (name, rest) = match seg.split_once('=') {
                Some(p) => p,
                None => return Some(seg.to_string()),
            };
            let val = rest.trim();
            if val.is_empty() {
                return None;
            }
            Some(format!("{}={}", name.trim(), val))
        })
        .collect::<Vec<_>>()
        .join("; ");
    if joined.is_empty() {
        cookie.trim().to_string()
    } else {
        joined
    }
}

fn find_headers_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
}

fn parse_status_line(headers_blob: &[u8]) -> Result<u16, String> {
    let line_end = headers_blob
        .windows(2)
        .position(|w| w == b"\r\n")
        .ok_or_else(|| "risposta HTTP senza fine riga".to_string())?;
    let line = std::str::from_utf8(&headers_blob[..line_end])
        .map_err(|e| format!("status non UTF-8: {}", e))?;
    let mut parts = line.split_whitespace();
    let _http = parts.next().ok_or_else(|| "status HTTP vuoto".to_string())?;
    let code = parts
        .next()
        .ok_or_else(|| "manca codice stato HTTP".to_string())?
        .parse::<u16>()
        .map_err(|_| "codice stato HTTP non numerico".to_string())?;
    Ok(code)
}

fn parse_headers(headers_blob: &[u8]) -> Result<(u16, HashMap<String, String>), String> {
    let status = parse_status_line(headers_blob)?;
    let text = std::str::from_utf8(headers_blob).map_err(|e| e.to_string())?;
    let mut map = HashMap::new();
    for line in text.split("\r\n").skip(1) {
        if line.is_empty() {
            break;
        }
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        map.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
    }
    Ok((status, map))
}

fn normalize_redirect_path(loc: &str, _host: &str, _port: u16) -> Result<String, String> {
    let loc = loc.trim();
    if loc.starts_with('/') {
        return Ok(loc.to_string());
    }
    let lower = loc.to_ascii_lowercase();
    let skip = if lower.starts_with("https://") {
        8
    } else if lower.starts_with("http://") {
        7
    } else {
        return Err(format!("Location non supportata: {}", loc));
    };
    let after_scheme = &loc[skip..];
    let path_start = after_scheme
        .find('/')
        .ok_or_else(|| format!("Location senza path: {}", loc))?;
    Ok(after_scheme[path_start..].to_string())
}

fn build_get_api(host_port: &str, path_query: &str, cookie: &str, referer: &str) -> String {
    // Ogni riga deve iniziare subito dopo `\r\n`: mai indentare le continuazioni (Rust incluirebbe SP/TAB → OBS-fold HTTP).
    format!(
        "GET {pq} HTTP/1.1\r\n\
Host: {hp}\r\n\
User-Agent: {ua}\r\n\
Accept: */*\r\n\
Accept-Encoding: identity\r\n\
Pragma: no-cache\r\n\
Cache-Control: no-store, no-cache, must-revalidate\r\n\
If-Modified-Since: Sat, 1 Jan 2000 00:00:00 GMT\r\n\
Cookie: {ck}\r\n\
Referer: {rf}\r\n\
Connection: keep-alive\r\n\
\r\n",
        pq = path_query,
        hp = host_port,
        ua = UA,
        ck = cookie,
        rf = referer,
    )
}

async fn read_exact_bytes(
    stream: &mut TlsStream<TcpStream>,
    mut buf: Vec<u8>,
    total: usize,
) -> Result<Vec<u8>, String> {
    let mut tmp = [0u8; 8192];
    while buf.len() < total {
        let need = total - buf.len();
        let n = timeout(READ_TIMEOUT, stream.read(&mut tmp))
            .await
            .map_err(|_| "timeout corpo HTTP".to_string())?
            .map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("EOF durante lettura corpo HTTP".into());
        }
        let take = need.min(n);
        buf.extend_from_slice(&tmp[..take]);
    }
    buf.truncate(total);
    Ok(buf)
}

async fn read_http_body(
    stream: &mut TlsStream<TcpStream>,
    headers: &HashMap<String, String>,
    mut initial: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let te = headers
        .get("transfer-encoding")
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();
    if te.contains("chunked") {
        return read_chunked_body(stream, initial).await;
    }
    if let Some(cl) = headers.get("content-length") {
        let n: usize = cl
            .trim()
            .parse()
            .map_err(|_| format!("Content-Length invalido: {}", cl))?;
        if initial.len() >= n {
            initial.truncate(n);
            return Ok(initial);
        }
        return read_exact_bytes(stream, initial, n).await;
    }

    // Nessun Content-Length: corto timeout per eventuali byte finali (Fortinet di solito invia CL).
    tracing::debug!(
        "TLS-HTTP: risposta senza Content-Length/chunked — consumo byte residui breve.",
    );
    let mut out = initial;
    let mut tmp = [0u8; 2048];
    for _ in 0..50 {
        match timeout(Duration::from_millis(500), stream.read(&mut tmp)).await {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(n)) => out.extend_from_slice(&tmp[..n]),
            Ok(Err(e)) => return Err(e.to_string()),
        }
        if out.len() > 512 * 1024 {
            break;
        }
    }
    Ok(out)
}

async fn read_chunked_body(
    stream: &mut TlsStream<TcpStream>,
    mut pending: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut tmp = [0u8; 8192];

    loop {
        while !pending.windows(2).any(|w| w == b"\r\n") {
            let n = timeout(READ_TIMEOUT, stream.read(&mut tmp))
                .await
                .map_err(|_| "timeout chunked".to_string())?
                .map_err(|e| e.to_string())?;
            if n == 0 {
                return Err("EOF in chunked size line".into());
            }
            pending.extend_from_slice(&tmp[..n]);
            if pending.len() > 512 * 1024 {
                return Err("chunked buffer eccessivo".into());
            }
        }
        let pos = pending
            .windows(2)
            .position(|w| w == b"\r\n")
            .unwrap();
        let size_line = std::str::from_utf8(&pending[..pos])
            .map_err(|e| e.to_string())?;
        let hex_part = size_line.split(';').next().unwrap_or(size_line).trim();
        let chunk_len =
            usize::from_str_radix(hex_part, 16).map_err(|_| format!("chunk size: {}", hex_part))?;
        pending.drain(..pos + 2);

        if chunk_len == 0 {
            if pending.len() >= 2 && pending.starts_with(b"\r\n") {
                pending.drain(..2);
            }
            break;
        }

        while pending.len() < chunk_len {
            let n = timeout(READ_TIMEOUT, stream.read(&mut tmp))
                .await
                .map_err(|_| "timeout chunk data".to_string())?
                .map_err(|e| e.to_string())?;
            if n == 0 {
                return Err("EOF dentro chunk".into());
            }
            pending.extend_from_slice(&tmp[..n]);
        }
        out.extend_from_slice(&pending[..chunk_len]);
        pending.drain(..chunk_len);
        if pending.len() >= 2 && pending.starts_with(b"\r\n") {
            pending.drain(..2);
        } else {
            while pending.len() < 2 {
                let n = timeout(READ_TIMEOUT, stream.read(&mut tmp))
                    .await
                    .map_err(|_| "timeout dopo chunk".to_string())?
                    .map_err(|e| e.to_string())?;
                if n == 0 {
                    return Err("EOF dopo chunk".into());
                }
                pending.extend_from_slice(&tmp[..n]);
            }
            if !pending.starts_with(b"\r\n") {
                return Err("chunk framing CRLF mancante".into());
            }
            pending.drain(..2);
        }
    }

    Ok(out)
}

async fn tls_get_full_response(
    stream: &mut TlsStream<TcpStream>,
    request: &str,
) -> Result<(u16, HashMap<String, String>, Vec<u8>), String> {
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    stream.flush().await.map_err(|e| e.to_string())?;

    let mut buf = Vec::new();
    let hdr_end = loop {
        if let Some(end) = find_headers_end(&buf) {
            break end;
        }
        let mut tmp = [0u8; 8192];
        let n = timeout(READ_TIMEOUT, stream.read(&mut tmp))
            .await
            .map_err(|_| "timeout header HTTP".to_string())?
            .map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("EOF durante header HTTP".into());
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() > 512 * 1024 {
            return Err("header HTTP troppo grandi".into());
        }
    };

    let (status, headers) = parse_headers(&buf[..hdr_end])?;
    let body_start = hdr_end;
    let initial_body = buf[body_start..].to_vec();
    let body = read_http_body(stream, &headers, initial_body).await?;
    Ok((status, headers, body))
}

/// Scarica la configurazione VPN sulla **stessa** sessione TLS usata poi per il traffico tunnel.
pub async fn fetch_vpn_config_xml(
    stream: &mut TlsStream<TcpStream>,
    host: &str,
    port: u16,
    cookie_header: &str,
) -> Result<VpnConfig, String> {
    let host_port = format!("{}:{}", host, port);
    let referer = format!("https://{}/remote/fortisslvpn", host_port);
    let paths_try = [
        "/remote/fortisslvpn_xml?dual_stack=1",
        "/remote/fortisslvpn_xml",
    ];

    let mut last_err = String::new();

    for path_template in paths_try {
        let mut path = path_template.to_string();
        for _ in 0..12 {
            tracing::debug!(
                "TLS-HTTP: GET {} (Host: {}) sulla sessione dati…",
                path, host_port
            );
            let req = build_get_api(&host_port, &path, cookie_header, &referer);
            let (status, headers, body) = tls_get_full_response(stream, &req).await?;

            if status == 200 {
                let conn = headers
                    .get("connection")
                    .map(String::as_str)
                    .unwrap_or("(assente)");
                tracing::debug!("TLS-HTTP: risposta XML — Connection: {conn}");
            }

            if matches!(status, 301 | 302 | 303 | 307 | 308) {
                let loc = headers
                    .get("location")
                    .ok_or_else(|| format!("redirect HTTP {} senza Location", status))?;
                path = normalize_redirect_path(loc, host, port)?;
                tracing::debug!("TLS-HTTP: redirect {} → {}", status, path);
                continue;
            }

            if status != 200 {
                let body_preview = String::from_utf8_lossy(&body[..body.len().min(256)]);
                last_err = format!("{} HTTP {} — {}", path, status, body_preview);
                break;
            }

            let xml_text = String::from_utf8_lossy(&body);
            let body_trim = xml_text.trim();

            if response_looks_like_html_portal(body_trim) {
                last_err = format!(
                    "{} — HTML portale — {}",
                    path,
                    preview_config_body(body_trim)
                );
                break;
            }

            match crate::config_xml::parse_vpn_config_xml(body_trim) {
                Ok(cfg) => {
                    diag::emit(format!(
                        "Configurazione VPN ricevuta (IP {}).",
                        cfg.assigned_ip
                    ));
                    return Ok(cfg);
                }
                Err(e) => {
                    last_err = format!(
                        "{} — {} — {}",
                        path,
                        e,
                        preview_config_body(body_trim)
                    );
                    break;
                }
            }
        }
    }

    Err(format!(
        "Config VPN sulla sessione TLS dati non valida. {}",
        last_err
    ))
}

/// Su molti gateway Fortinet, se il tunnel va a buon fine **non** arriva una risposta HTTP con header;
/// il flusso passa subito ai dati PPP/tunnel. Solo in caso di errore il gateway risponde con HTTP.
#[derive(Clone, Copy, PartialEq, Eq)]
enum TunnelPostGetKind {
    NeedMoreBytes,
    HttpResponse,
    RawTunnelData,
}

fn classify_tunnel_post_get(buf: &[u8]) -> TunnelPostGetKind {
    if buf.is_empty() {
        return TunnelPostGetKind::NeedMoreBytes;
    }
    // Incapsulamento Fortinet: marker `PP` a offset 2–3 (vedi `ppp_proto::pop_tunnel_frame`).
    if buf.len() >= 6 && buf[2] == 0x50 && buf[3] == 0x50 {
        return TunnelPostGetKind::RawTunnelData;
    }
    let first = buf[0];
    if first != b'H' && first != b'h' {
        return TunnelPostGetKind::RawTunnelData;
    }
    if buf.len() < 5 {
        return TunnelPostGetKind::NeedMoreBytes;
    }
    if buf[..5].eq_ignore_ascii_case(b"HTTP/") {
        TunnelPostGetKind::HttpResponse
    } else {
        TunnelPostGetKind::RawTunnelData
    }
}

async fn read_until_tunnel_http_headers_end(
    stream: &mut TlsStream<TcpStream>,
    buf: &mut Vec<u8>,
    tmp: &mut [u8],
) -> Result<usize, String> {
    loop {
        if let Some(end) = find_headers_end(buf) {
            return Ok(end);
        }
        let n = timeout(TUNNEL_HDR_TIMEOUT, stream.read(tmp))
            .await
            .map_err(|_| {
                format!(
                    "Tunnel: timeout header HTTP dopo GET sslvpn-tunnel ({} s).",
                    TUNNEL_HDR_TIMEOUT.as_secs()
                )
            })?
            .map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("Tunnel: EOF prima della fine degli header HTTP".into());
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() > 512 * 1024 {
            return Err("Tunnel: header HTTP troppo grandi".into());
        }
    }
}

/// GET tunnel Fortinet minimale (Host virtuale SSL‑VPN `sslvpn`, solo cookie SVPN nel header).
fn build_sslvpn_tunnel_get(cookie: &str) -> String {
    format!(
        "GET /remote/sslvpn-tunnel HTTP/1.1\r\n\
Host: sslvpn\r\n\
Cookie: {ck}\r\n\
\r\n",
        ck = cookie,
    )
}

/// Invia GET tunnel e restituisce i byte già disponibili per PPP (dopo eventuali header HTTP se il gateway li invia).
pub async fn send_sslvpn_tunnel_get(
    stream: &mut TlsStream<TcpStream>,
    cookie: &str,
) -> Result<Vec<u8>, String> {
    let cookie = sanitize_cookie_header(cookie);
    let req = build_sslvpn_tunnel_get(&cookie);
    tracing::debug!(
        "TLS-HTTP: GET /remote/sslvpn-tunnel (TLS dedicata al tunnel, dopo la sessione XML).",
    );
    stream
        .write_all(req.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    stream.flush().await.map_err(|e| e.to_string())?;

    tracing::debug!("TLS-HTTP: in attesa dei primi byte dal gateway dopo GET tunnel…");

    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    let mut need_more_stalls: u32 = 0;

    loop {
        match classify_tunnel_post_get(&buf) {
            TunnelPostGetKind::RawTunnelData => {
                tracing::debug!(
                    "TLS-HTTP: dati tunnel senza risposta HTTP (comportamento Fortinet) — {} byte.",
                    buf.len()
                );
                return Ok(buf);
            }
            TunnelPostGetKind::HttpResponse => {
                tracing::debug!(
                    "TLS-HTTP: risposta HTTP dopo GET tunnel — parsing header (di solito errore gateway).",
                );
                let end = read_until_tunnel_http_headers_end(stream, &mut buf, &mut tmp).await?;
                let status_line_end = buf
                    .windows(2)
                    .position(|w| w == b"\r\n")
                    .unwrap_or(0);
                let status_line =
                    String::from_utf8_lossy(&buf[..status_line_end.min(buf.len())]).to_string();
                let ok = status_line.starts_with("HTTP/1.1 200")
                    || status_line.starts_with("HTTP/1.0 200");
                if !ok {
                    let peek = String::from_utf8_lossy(&buf[..buf.len().min(400)]);
                    return Err(format!(
                        "Tunnel HTTP non OK: {} — {}",
                        status_line.trim(),
                        peek
                    ));
                }
                let remainder = buf[end..].to_vec();
                tracing::debug!(
                    "TLS-HTTP: tunnel HTTP 200 — {} byte PPP dopo header.",
                    remainder.len()
                );
                return Ok(remainder);
            }
            TunnelPostGetKind::NeedMoreBytes => {
                let peek_timeout = if buf.is_empty() {
                    TUNNEL_FIRST_PEEK_TIMEOUT
                } else {
                    TUNNEL_RAW_READ_TIMEOUT
                };

                match timeout(peek_timeout, stream.read(&mut tmp)).await {
                    Err(_) => {
                        if buf.is_empty() {
                            tracing::debug!(
                                "TLS-HTTP: nessun byte iniziale dal gateway — avvio PPP attivo (LCP Conf-Req dal client).",
                            );
                            return Ok(Vec::new());
                        }
                        need_more_stalls = need_more_stalls.saturating_add(1);
                        if need_more_stalls >= TUNNEL_NEED_MORE_MAX_STALLS {
                            tracing::debug!(
                                "TLS-HTTP: prefisso ancora ambiguo dopo {} tentativi brevi — {} byte, passo al PPP.",
                                TUNNEL_NEED_MORE_MAX_STALLS,
                                buf.len()
                            );
                            return Ok(buf);
                        }
                        continue;
                    }
                    Ok(Ok(0)) => {
                        if buf.is_empty() {
                            return Err("Tunnel: connessione chiusa senza risposta".into());
                        }
                        tracing::debug!(
                            "TLS-HTTP: EOF dopo {} byte (prefisso incompleto?) — uso come dati tunnel.",
                            buf.len()
                        );
                        return Ok(buf);
                    }
                    Ok(Ok(n)) => {
                        need_more_stalls = 0;
                        buf.extend_from_slice(&tmp[..n]);
                        if buf.len() > 512 * 1024 {
                            return Err("Tunnel: risposta gateway troppo grande".into());
                        }
                    }
                    Ok(Err(e)) => return Err(e.to_string()),
                }
            }
        }
    }
}
