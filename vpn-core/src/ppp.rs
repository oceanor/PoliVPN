use rand::Rng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use tokio_native_tls::TlsStream;

use crate::diag;
use crate::ppp_proto::*;

const PPP_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// RFC 1661: stesso Identifier e campo Length della Configure-Request del peer; si cambia solo il code in ACK.
fn lcp_configure_ack_from_peer(peer_req: &[u8]) -> Option<Vec<u8>> {
    if peer_req.len() < 4 {
        return None;
    }
    let total_len = u16::from_be_bytes([peer_req[2], peer_req[3]]) as usize;
    if total_len < 4 || peer_req.len() < total_len {
        return None;
    }
    let mut out = Vec::with_capacity(total_len);
    out.push(proto::LCP_CONF_ACK);
    out.push(peer_req[1]);
    out.extend_from_slice(&peer_req[2..total_len]);
    Some(out)
}

fn ipcp_configure_ack_from_peer(peer_req: &[u8]) -> Option<Vec<u8>> {
    if peer_req.len() < 4 {
        return None;
    }
    let total_len = u16::from_be_bytes([peer_req[2], peer_req[3]]) as usize;
    if total_len < 4 || peer_req.len() < total_len {
        return None;
    }
    let mut out = Vec::with_capacity(total_len);
    out.push(proto::IPCP_CONF_ACK);
    out.push(peer_req[1]);
    out.extend_from_slice(&peer_req[2..total_len]);
    Some(out)
}

/// Restituisce l'HDLC frame contenuto nel prossimo frame tunnel; il protocol PPP
/// va estratto poi via [`parse_hdlc_frame`].
async fn read_next_tunnel_frame(
    stream: &mut TlsStream<TcpStream>,
    pending: &mut Vec<u8>,
) -> Result<Vec<u8>, String> {
    loop {
        if let Some(inner) = pop_tunnel_frame(pending) {
            tracing::trace!(
                target: "vpn_core::ppp",
                "PPP: frame tunnel completo — payload HDLC {} byte",
                inner.len()
            );
            return Ok(inner);
        }
        let mut buf = [0u8; 8192];
        let n = timeout(PPP_READ_TIMEOUT, stream.read(&mut buf))
            .await
            .map_err(|_| {
                "PPP: nessun frame dal gateway entro 30 s (LCP/IPCP)".to_string()
            })?
            .map_err(|e| format!("PPP stream read error: {}", e))?;
        if n == 0 {
            tracing::debug!(
                "PPP: EOF da TLS con {} byte ancora nel buffer (frame troncato?).",
                pending.len()
            );
            return Err("PPP: connessione chiusa".into());
        }
        pending.extend_from_slice(&buf[..n]);
        if pending.len() > 512 * 1024 {
            return Err("PPP: buffer di lettura eccessivo".into());
        }
    }
}

pub struct PppSession {
    local_magic: u32,
    remote_magic: u32,
    lcp_identifier: u8,
    ipcp_identifier: u8,
    mru: u16,
}

impl PppSession {
    pub fn new(mru: u16) -> Self {
        let mut rng = rand::thread_rng();
        Self {
            local_magic: rng.gen(),
            remote_magic: 0,
            lcp_identifier: 1,
            ipcp_identifier: 1,
            mru,
        }
    }

    pub async fn negotiate_lcp(
        &mut self,
        stream: &mut TlsStream<TcpStream>,
        pending: &mut Vec<u8>,
    ) -> Result<(), String> {
        // Client PPP che apre il negoziato LCP inviando per primo Configure-Request; il gateway risponde.
        let req = self.build_lcp_configure_request();
        let hdlc_req = build_hdlc_frame(proto::LCP, &req);
        let frame_req = encode_tunnel_frame(&hdlc_req);
        stream
            .write_all(&frame_req)
            .await
            .map_err(|e| format!("LCP write error: {}", e))?;
        stream
            .flush()
            .await
            .map_err(|e| format!("LCP flush error: {}", e))?;
        let sent_id = self.lcp_identifier;
        self.lcp_identifier = self.lcp_identifier.wrapping_add(1);
        tracing::debug!(
            "LCP: nostro Configure-Request iniziale inviato (id={}, magic_locale={:#x}).",
            sent_id, self.local_magic
        );

        let mut acked_peer_configure_request = false;
        let mut received_ack_for_ours = false;

        loop {
            let hdlc = read_next_tunnel_frame(stream, pending).await?;
            let Some((ppp_proto, pkt)) = parse_hdlc_frame(&hdlc) else {
                tracing::debug!(
                    "LCP: HDLC non parsabile ({} byte), continuo.",
                    hdlc.len()
                );
                continue;
            };
            if ppp_proto != proto::LCP {
                tracing::debug!(
                    "LCP: ignoro frame ppp_proto=0x{:04x} (atteso LCP=0x{:04x})",
                    ppp_proto,
                    proto::LCP
                );
                continue;
            }
            if pkt.len() < 4 {
                tracing::debug!(
                    "LCP: pacchetto troppo corto ({} byte).",
                    pkt.len()
                );
                continue;
            }
            let code = pkt[0];
            match code {
                proto::LCP_CONF_REQ => {
                    let total_len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
                    if total_len < 4 || pkt.len() < total_len {
                        tracing::debug!(
                            "LCP: Configure-Request troncato (dichiarati {} byte, ho {}).",
                            total_len,
                            pkt.len()
                        );
                        continue;
                    }
                    let peer = &pkt[..total_len];
                    let opts = peer.get(4..total_len).unwrap_or(&[]);
                    self.remote_magic = extract_magic_number(opts);

                    tracing::debug!(
                        "LCP: Configure-Request peer — lunghezza {} byte, magic_peer={:#x}",
                        total_len, self.remote_magic
                    );

                    let Some(ack_body) = lcp_configure_ack_from_peer(peer) else {
                        tracing::debug!("LCP: impossibile costruire Configure-Ack (pacchetto invalido).");
                        continue;
                    };
                    let hdlc_ack = build_hdlc_frame(proto::LCP, &ack_body);
                    let frame_ack = encode_tunnel_frame(&hdlc_ack);
                    stream
                        .write_all(&frame_ack)
                        .await
                        .map_err(|e| format!("LCP write error: {}", e))?;
                    tracing::debug!("LCP: Configure-Ack inviato.");
                    acked_peer_configure_request = true;
                    if received_ack_for_ours {
                        diag::emit("PPP/LCP completato.");
                        return Ok(());
                    }
                }
                proto::LCP_CONF_ACK => {
                    tracing::debug!("LCP: Configure-Ack ricevuto dal peer.");
                    received_ack_for_ours = true;
                    if acked_peer_configure_request {
                        diag::emit("PPP/LCP completato.");
                        return Ok(());
                    }
                }
                other => {
                    tracing::debug!(
                        "LCP: codice PPP non gestito in questa fase: {}.",
                        other
                    );
                }
            }
        }
    }

    pub async fn negotiate_ipcp(
        &mut self,
        stream: &mut TlsStream<TcpStream>,
        pending: &mut Vec<u8>,
        assigned_ip: &str,
    ) -> Result<String, String> {
        let mut confirmed_ip = String::new();
        let mut state = PppState::WaitRequest;

        tracing::debug!(
            "IPCP: negoziazione avviata (IP dalla XML: {}).",
            assigned_ip
        );

        while state != PppState::Done {
            match state {
                PppState::WaitRequest => {
                    let hdlc = read_next_tunnel_frame(stream, pending).await?;
                    let Some((ppp_proto, payload)) = parse_hdlc_frame(&hdlc) else {
                        tracing::debug!(
                            "IPCP: HDLC non parsabile ({} byte).",
                            hdlc.len()
                        );
                        continue;
                    };
                    if ppp_proto != proto::IPCP {
                        tracing::debug!(
                            "IPCP: ignoro frame ppp_proto=0x{:04x} (atteso IPCP=0x{:04x})",
                            ppp_proto,
                            proto::IPCP
                        );
                        continue;
                    }
                    if payload.len() < 4 {
                        tracing::debug!(
                            "IPCP: pacchetto troppo corto ({} byte).",
                            payload.len()
                        );
                        continue;
                    }
                    let code = payload[0];
                    match code {
                        proto::IPCP_CONF_REQ => {
                            let total_len = u16::from_be_bytes([payload[2], payload[3]]) as usize;
                            if total_len < 4 || payload.len() < total_len {
                                tracing::debug!(
                                    "IPCP: Configure-Request troncato (attesi {} byte, ho {}).",
                                    total_len,
                                    payload.len()
                                );
                                continue;
                            }
                            let peer = &payload[..total_len];
                            let Some(ack_body) = ipcp_configure_ack_from_peer(peer) else {
                                tracing::debug!("IPCP: impossibile costruire Configure-Ack.");
                                continue;
                            };
                            tracing::debug!(
                                "IPCP: Configure-Request peer ({} byte), invio Ack.",
                                total_len
                            );
                            let hdlc_ack = build_hdlc_frame(proto::IPCP, &ack_body);
                            let frame_ack = encode_tunnel_frame(&hdlc_ack);
                            stream.write_all(&frame_ack).await.map_err(|e| {
                                format!("IPCP write error: {}", e)
                            })?;

                            state = PppState::SendRequest;
                        }
                        proto::IPCP_CONF_NAK => {
                            tracing::debug!("IPCP: Configure-Nak ricevuto.");
                            let total_len = u16::from_be_bytes([payload[2], payload[3]]) as usize;
                            let tail_end = total_len.min(payload.len());
                            let opts = payload.get(4..tail_end).unwrap_or(&[]);
                            if let Some(ip) = extract_ipcp_ip(opts) {
                                tracing::debug!("IPCP: Nak propone IP {}.", ip);
                                confirmed_ip = ip;
                            }
                            let ip_use = if confirmed_ip.is_empty() {
                                assigned_ip.to_string()
                            } else {
                                confirmed_ip.clone()
                            };
                            let req = self.build_ipcp_configure_request(&ip_use);
                            let hdlc = build_hdlc_frame(proto::IPCP, &req);
                            let frame = encode_tunnel_frame(&hdlc);
                            stream.write_all(&frame).await.map_err(|e| {
                                format!("IPCP write error: {}", e)
                            })?;
                            self.ipcp_identifier = self.ipcp_identifier.wrapping_add(1);
                            state = PppState::WaitRequest;
                        }
                        proto::IPCP_CONF_ACK => {
                            diag::emit("PPP/IPCP completato.");
                            state = PppState::Done;
                        }
                        other => {
                            tracing::debug!("IPCP: codice PPP non gestito: {}.", other);
                        }
                    }
                }
                PppState::SendRequest => {
                    let ip: String = if confirmed_ip.is_empty() {
                        assigned_ip.to_string()
                    } else {
                        confirmed_ip.clone()
                    };
                    tracing::debug!(
                        "IPCP: invio nostro Configure-Request con IP {}.",
                        ip
                    );
                    let req = self.build_ipcp_configure_request(&ip);
                    let hdlc = build_hdlc_frame(proto::IPCP, &req);
                    let frame = encode_tunnel_frame(&hdlc);
                    stream
                        .write_all(&frame)
                        .await
                        .map_err(|e| format!("IPCP write error: {}", e))?;
                    self.ipcp_identifier = self.ipcp_identifier.wrapping_add(1);
                    state = PppState::WaitRequest;
                }
                PppState::Done => {}
            }
        }

        Ok(if confirmed_ip.is_empty() {
            assigned_ip.to_string()
        } else {
            confirmed_ip
        })
    }

    fn build_lcp_configure_request(&self) -> Vec<u8> {
        let id = self.lcp_identifier;
        let mru = self.mru;
        let mut payload = vec![
            proto::LCP_OPT_MRU,
            4,
            (mru >> 8) as u8,
            (mru & 0xFF) as u8,
            proto::LCP_OPT_MAGIC_NUMBER,
            6,
            (self.local_magic >> 24) as u8,
            (self.local_magic >> 16) as u8,
            (self.local_magic >> 8) as u8,
            (self.local_magic & 0xFF) as u8,
        ];
        let header = build_lcp_header(proto::LCP_CONF_REQ, id, payload.len() as u16);
        let mut full = header;
        full.append(&mut payload);
        full
    }

    fn build_ipcp_configure_request(&self, ip: &str) -> Vec<u8> {
        let id = self.ipcp_identifier;
        let ip_bytes = parse_ipv4(ip);
        let mut payload = vec![proto::IPCP_OPT_IP_ADDRESS, 6];
        payload.extend_from_slice(&ip_bytes);
        let header = build_ipcp_header(proto::IPCP_CONF_REQ, id, payload.len() as u16);
        let mut full = header;
        full.append(&mut payload);
        full
    }
}

fn extract_magic_number(opts: &[u8]) -> u32 {
    let mut i = 0;
    while i + 1 < opts.len() {
        let opt_type = opts[i];
        let opt_len = opts[i + 1] as usize;
        if opt_len == 0 || i + opt_len > opts.len() {
            break;
        }
        if opt_type == proto::LCP_OPT_MAGIC_NUMBER && opt_len >= 6 {
            return u32::from_be_bytes([opts[i + 2], opts[i + 3], opts[i + 4], opts[i + 5]]);
        }
        i += opt_len;
    }
    0
}

fn extract_ipcp_ip(opts: &[u8]) -> Option<String> {
    let mut i = 0;
    while i + 1 < opts.len() {
        let opt_type = opts[i];
        let opt_len = opts[i + 1] as usize;
        if opt_len == 0 || i + opt_len > opts.len() {
            break;
        }
        if opt_type == proto::IPCP_OPT_IP_ADDRESS && opt_len >= 6 {
            return Some(format!(
                "{}.{}.{}.{}",
                opts[i + 2],
                opts[i + 3],
                opts[i + 4],
                opts[i + 5]
            ));
        }
        i += opt_len;
    }
    None
}

fn parse_ipv4(ip: &str) -> [u8; 4] {
    let parts: Vec<u8> = ip.split('.').filter_map(|p| p.parse().ok()).collect();
    let mut bytes = [0u8; 4];
    for (i, &b) in parts.iter().enumerate().take(4) {
        bytes[i] = b;
    }
    bytes
}

#[derive(PartialEq)]
enum PppState {
    WaitRequest,
    SendRequest,
    Done,
}
