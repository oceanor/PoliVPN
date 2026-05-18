use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use bytes::BytesMut;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufWriter};
use tokio::net::TcpStream;
use tokio::task::JoinError;
use tokio_native_tls::TlsStream;
use tokio_util::sync::CancellationToken;
use tun::{DeviceReader, DeviceWriter};

use crate::diag;
use crate::ppp_proto::*;
use crate::tun::TunDevice;

const TLS_READ_BUF: usize = 64 * 1024;
const TLS_WRITER_BUF: usize = 64 * 1024;
/// Margine sulla MTU per header IP/allineamenti.
const TUN_READ_EXTRA: usize = 64;

pub struct IoLoop;

impl IoLoop {
    pub fn new() -> Self {
        Self
    }

    pub async fn run(
        self,
        tun: TunDevice,
        tls_stream: TlsStream<TcpStream>,
        pending_tls: Vec<u8>,
    ) -> Result<(), String> {
        self.run_with_cancel(tun, tls_stream, pending_tls, CancellationToken::new())
            .await
    }

    /// Due task distinte (TUN→TLS e TLS→TUN): niente blocchi sulla TUN nel runtime Tokio.
    pub async fn run_with_cancel(
        self,
        tun: TunDevice,
        tls_stream: TlsStream<TcpStream>,
        pending_tls: Vec<u8>,
        cancel: CancellationToken,
    ) -> Result<(), String> {
        let mtu = tun.mtu() as usize;
        let tun_read_cap = mtu.saturating_add(TUN_READ_EXTRA).max(TUN_READ_EXTRA);

        let (tun_w, tun_r, tun_name, _) = tun
            .into_split()
            .map_err(|e| format!("split TUN fallito: {}", e))?;

        tracing::debug!(
            target: "vpn_core::io",
            "loop dati «{}»: MTU {} — split TLS/TUN.",
            tun_name,
            mtu
        );

        let (tls_r, tls_w) = tokio::io::split(tls_stream);
        let tls_w = BufWriter::with_capacity(TLS_WRITER_BUF, tls_w);

        let tx_bytes = Arc::new(AtomicU64::new(0));
        let rx_bytes = Arc::new(AtomicU64::new(0));

        let diag_cancel = cancel.clone();
        let diag_join =
            tokio::spawn(throughput_logger(tx_bytes.clone(), rx_bytes.clone(), diag_cancel));

        let rx_cancel = cancel.clone();
        let tx_cancel = cancel.clone();

        let mut rx_join = tokio::spawn(task_tls_to_tun(
            tls_r,
            tun_w,
            pending_tls,
            rx_bytes.clone(),
            rx_cancel,
        ));
        let mut tx_join = tokio::spawn(task_tun_to_tls(
            tun_r,
            tls_w,
            tun_read_cap,
            tx_bytes.clone(),
            tx_cancel,
        ));

        let rx_abort = rx_join.abort_handle();
        let tx_abort = tx_join.abort_handle();

        enum Outcome {
            UserCancel,
            RxDone(Result<Result<(), String>, JoinError>),
            TxDone(Result<Result<(), String>, JoinError>),
        }

        let outcome = tokio::select! {
            biased;
            _ = cancel.cancelled() => Outcome::UserCancel,
            r = std::pin::Pin::new(&mut rx_join) => Outcome::RxDone(r),
            r = std::pin::Pin::new(&mut tx_join) => Outcome::TxDone(r),
        };

        diag_join.abort();
        let _ = flatten_diag_join(diag_join.await);

        let mut first_err = None::<String>;

        match outcome {
            Outcome::UserCancel => {
                rx_abort.abort();
                tx_abort.abort();
                let _ = flatten_void_join(rx_join.await);
                let _ = flatten_void_join(tx_join.await);
            }
            Outcome::RxDone(r) => {
                cancel.cancel();
                tx_abort.abort();
                if let Err(e) = flatten_void_join_named(r, "RX") {
                    first_err = Some(e);
                }
                let _ = flatten_void_join(tx_join.await);
            }
            Outcome::TxDone(r) => {
                cancel.cancel();
                rx_abort.abort();
                if let Err(e) = flatten_void_join_named(r, "TX") {
                    first_err = Some(e);
                }
                let _ = flatten_void_join(rx_join.await);
            }
        }

        match first_err {
            Some(e) => {
                tracing::warn!(target: "vpn_core::io", "loop dati terminato con errore: {}", e);
                Err(e)
            }
            None => Ok(()),
        }
    }
}

fn flatten_diag_join(res: Result<(), JoinError>) -> Result<(), String> {
    match res {
        Ok(()) => Ok(()),
        Err(e) if e.is_cancelled() => Ok(()),
        Err(e) => Err(format!("throughput diag join: {:?}", e)),
    }
}

fn flatten_void_join(res: Result<Result<(), String>, JoinError>) -> Result<(), String> {
    match res {
        Ok(inner) => inner,
        Err(e) if e.is_cancelled() => Ok(()),
        Err(e) => Err(format!("join task I/O annullato: {:?}", e)),
    }
}

fn flatten_void_join_named(
    res: Result<Result<(), String>, JoinError>,
    label: &'static str,
) -> Result<(), String> {
    match res {
        Ok(inner) => inner,
        Err(e) if e.is_cancelled() => Ok(()),
        Err(e) => Err(format!("{label}: {:?}", e)),
    }
}

async fn throughput_logger(tx: Arc<AtomicU64>, rx: Arc<AtomicU64>, cancel: CancellationToken) {
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(5));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut prev_tx = 0u64;
    let mut prev_rx = 0u64;
    let mut t0 = Instant::now();

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            _ = tick.tick() => {
                let now = Instant::now();
                let dt = now.duration_since(t0).as_secs_f64().max(0.001);
                let cur_tx = tx.load(Ordering::Relaxed);
                let cur_rx = rx.load(Ordering::Relaxed);

                let bps_tx = (cur_tx.saturating_sub(prev_tx)) as f64 / dt * 8.0;
                let bps_rx = (cur_rx.saturating_sub(prev_rx)) as f64 / dt * 8.0;

                diag::emit(format!(
                    "[io] throughput: TX {} cumul. {}; RX {} cumul. {}",
                    fmt_bps_bits(bps_tx),
                    fmt_bytes_accum(cur_tx),
                    fmt_bps_bits(bps_rx),
                    fmt_bytes_accum(cur_rx),
                ));

                prev_tx = cur_tx;
                prev_rx = cur_rx;
                t0 = now;
            }
        }
    }
}

fn fmt_bps_bits(bps: f64) -> String {
    if bps >= 1_000_000_000.0 {
        format!("{:.2} Gbit/s", bps / 1_000_000_000.0)
    } else if bps >= 1_000_000.0 {
        format!("{:.2} Mbit/s", bps / 1_000_000.0)
    } else if bps >= 1_000.0 {
        format!("{:.2} kbit/s", bps / 1_000.0)
    } else {
        format!("{:.0} bit/s", bps)
    }
}

fn fmt_bytes_accum(b: u64) -> String {
    let f = b as f64;
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;
    if b as f64 >= GB {
        format!("{:.2} GiB", f / GB)
    } else if b as f64 >= MB {
        format!("{:.2} MiB", f / MB)
    } else if b as f64 >= KB {
        format!("{:.1} KiB", f / KB)
    } else {
        format!("{b} B")
    }
}

async fn task_tun_to_tls(
    mut tun_r: DeviceReader,
    mut tls_w: BufWriter<tokio::io::WriteHalf<TlsStream<TcpStream>>>,
    tun_read_cap: usize,
    counter: Arc<AtomicU64>,
    cancel: CancellationToken,
) -> Result<(), String> {
    let mut buf = vec![0u8; tun_read_cap];

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => return Ok(()),
            r = tun_r.read(&mut buf) => {
                let n = r.map_err(|e| format!("TUN read: {}", e))?;
                if n == 0 {
                    return Ok(());
                }

                let mut tun_total: u64 = n as u64;

                {
                    let hdlc = build_hdlc_frame(proto::PPP_IP, &buf[..n]);
                    let frame = encode_tunnel_frame(&hdlc);
                    tls_w
                        .write_all(&frame)
                        .await
                        .map_err(|e| format!("TLS write: {}", e))?;
                }

                loop {
                    match tokio::time::timeout(
                        std::time::Duration::from_micros(200),
                        tun_r.read(&mut buf),
                    )
                    .await
                    {
                        Err(_) => break,
                        Ok(Err(e)) => return Err(format!("TUN read: {}", e)),
                        Ok(Ok(0)) => break,
                        Ok(Ok(n2)) => {
                            tun_total += n2 as u64;
                            let hdlc = build_hdlc_frame(proto::PPP_IP, &buf[..n2]);
                            let frame = encode_tunnel_frame(&hdlc);
                            tls_w
                                .write_all(&frame)
                                .await
                                .map_err(|e| format!("TLS write: {}", e))?;
                        }
                    }
                }

                tls_w
                    .flush()
                    .await
                    .map_err(|e| format!("TLS flush: {}", e))?;
                counter.fetch_add(tun_total, Ordering::Relaxed);
            }
        }
    }
}

async fn task_tls_to_tun(
    mut tls_r: tokio::io::ReadHalf<TlsStream<TcpStream>>,
    mut tun_w: DeviceWriter,
    initial: Vec<u8>,
    counter: Arc<AtomicU64>,
    cancel: CancellationToken,
) -> Result<(), String> {
    let mut pending =
        BytesMut::with_capacity(TLS_READ_BUF.max(initial.len().saturating_mul(2)));
    pending.extend_from_slice(&initial);
    let mut chunk = vec![0u8; TLS_READ_BUF];

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => return Ok(()),
            r = tls_r.read(&mut chunk) => {
                let n = r.map_err(|e| format!("TLS read: {}", e))?;
                if n == 0 {
                    tracing::info!(target: "vpn_core::io", "TLS chiuso dal peer.");
                    return Ok(());
                }
                pending.extend_from_slice(&chunk[..n]);

                while let Some(hdlc_bm) = pop_tunnel_frame_bm(&mut pending) {
                    if let Some((ppp_proto, ip)) = parse_hdlc_frame(&hdlc_bm) {
                        if ppp_proto == proto::PPP_IP {
                            tun_w
                                .write_all(ip)
                                .await
                                .map_err(|e| format!("TUN write: {}", e))?;
                            counter.fetch_add(ip.len() as u64, Ordering::Relaxed);
                        }
                    }
                }

                if pending.len() > 1024 * 1024 {
                    return Err("IO/RX: reassembly eccede 1 MiB".into());
                }
            }
        }
    }
}
