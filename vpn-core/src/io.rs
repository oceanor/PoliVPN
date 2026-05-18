use crate::ppp_proto::*;
use crate::tun::TunDevice;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_native_tls::TlsStream;
use tokio_util::sync::CancellationToken;

const TUN_TLS_BUFFER: usize = 2048;

pub struct IoLoop;

impl IoLoop {
    pub fn new() -> Self {
        Self
    }

    /// `pending_tls`: byte PPP già letti dopo IPCP (stesso problema di framing TCP/TLS del login tunnel).
    pub async fn run(
        &self,
        tun: &TunDevice,
        tls_stream: &mut TlsStream<TcpStream>,
        pending_tls: Vec<u8>,
    ) -> Result<(), String> {
        self.run_with_cancel(
            tun,
            tls_stream,
            pending_tls,
            CancellationToken::new(),
        )
        .await
    }

    /// Come [`Self::run`], ma esce quando `cancel` viene segnato (disconnessione utente).
    pub async fn run_with_cancel(
        &self,
        tun: &TunDevice,
        tls_stream: &mut TlsStream<TcpStream>,
        pending_tls: Vec<u8>,
        cancel: CancellationToken,
    ) -> Result<(), String> {
        let mut tun_buf = vec![0u8; TUN_TLS_BUFFER];
        let mut tls_buf = vec![0u8; TUN_TLS_BUFFER];
        let mut tls_read_buf = pending_tls;

        tracing::debug!(
            "IO: loop dati avviato ({} byte pending sul TLS).",
            tls_read_buf.len()
        );

        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    tracing::info!("IO: cancel ricevuto, chiudo loop dati.");
                    break;
                }
                result = tls_stream.read(&mut tls_buf) => {
                    match result {
                        Ok(0) => {
                            tracing::info!("TLS connection closed by peer");
                            break;
                        }
                        Ok(n) => {
                            tls_read_buf.extend_from_slice(&tls_buf[..n]);

                            while let Some(hdlc_frame) = decode_tunnel_frame(&tls_read_buf) {
                                let consumed = TUNNEL_HEADER_SIZE + hdlc_frame.len();
                                let hdlc_copy = hdlc_frame.to_vec();

                                if let Some((ppp_proto, ip_data)) = parse_hdlc_frame(&hdlc_copy) {
                                    if ppp_proto == proto::PPP_IP {
                                        if let Err(e) = tun.write(ip_data) {
                                            tracing::warn!("TUN write error: {}", e);
                                        }
                                    }
                                }

                                tls_read_buf.drain(..consumed);
                            }
                            continue;
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            continue;
                        }
                        Err(e) => {
                            tracing::error!("TLS read error: {}", e);
                            break;
                        }
                    }
                }
                result = async {
                    tun.read(&mut tun_buf)
                } => {
                    match result {
                        Ok(n) => {
                            let ip_packet = &tun_buf[..n];
                            let ppp_ip_frame = build_hdlc_frame(proto::PPP_IP, ip_packet);
                            let tunnel_frame = encode_tunnel_frame(&ppp_ip_frame);

                            if let Err(e) = tls_stream.write_all(&tunnel_frame).await {
                                tracing::error!("TLS write error: {}", e);
                                break;
                            }
                            if let Err(e) = tls_stream.flush().await {
                                tracing::error!("TLS flush error: {}", e);
                                break;
                            }
                            continue;
                        }
                        Err(ref e) if e.to_string().contains("WouldBlock") => {
                            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                            continue;
                        }
                        Err(e) => {
                            tracing::error!("TUN read error: {}", e);
                            break;
                        }
                    }
                }
            }
        }

        Ok(())
    }
}
