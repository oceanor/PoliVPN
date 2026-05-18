//! Messaggi di diagnostica: `tracing` + invio **ordinato** alla GUI tramite canale async.

use std::sync::{Mutex, OnceLock};

use tokio::sync::mpsc::UnboundedSender;

static SENDER: OnceLock<Mutex<Option<UnboundedSender<String>>>> = OnceLock::new();

fn mutex() -> &'static Mutex<Option<UnboundedSender<String>>> {
    SENDER.get_or_init(|| Mutex::new(None))
}

pub fn set_sender(tx: Option<UnboundedSender<String>>) {
    if let Ok(mut g) = mutex().lock() {
        *g = tx;
    }
}

pub fn clear_sender() {
    set_sender(None);
}

/// Al drop rimuove il sender globale: il task che consuma il canale termina in ordine.
pub struct HookGuard;

impl HookGuard {
    pub fn new() -> Self {
        Self
    }
}

impl Drop for HookGuard {
    fn drop(&mut self) {
        clear_sender();
    }
}

pub fn emit(msg: impl AsRef<str>) {
    let s = msg.as_ref().to_string();
    tracing::info!(target: "polivpn_diag", "{s}");
    if let Ok(g) = mutex().lock() {
        if let Some(tx) = g.as_ref() {
            let _ = tx.send(s);
        }
    }
}
