use tun::{AbstractDevice, DeviceReader, DeviceWriter};

use crate::diag;
use crate::error_chain::format_error_chain;

#[cfg(windows)]
use std::ffi::OsString;
#[cfg(windows)]
use std::path::Path;
#[cfg(windows)]
use std::sync::OnceLock;
#[cfg(windows)]
use std::time::Duration;

#[cfg(windows)]
static WINTUN_DLL_PATH: OnceLock<OsString> = OnceLock::new();

/// Percorso esplicito di `wintun.dll` su Windows (caricamento via [`wintun_bindings::load_from_path`]).
/// Va impostato all’avvio dell’app con la DLL nelle risorse Tauri (`BaseDirectory::Resource`).
#[cfg(windows)]
pub fn set_wintun_dll_path<P: AsRef<std::path::Path>>(path: P) -> bool {
    let p = path.as_ref();
    if !p.is_file() {
        return false;
    }
    WINTUN_DLL_PATH
        .set(p.as_os_str().to_owned())
        .is_ok()
}

#[cfg(windows)]
fn emit_wintun_path_diagnostics_on_load_failure() {
    match WINTUN_DLL_PATH.get() {
        Some(p) => {
            let path_display = Path::new(p.as_os_str()).display().to_string();
            match std::fs::metadata(Path::new(p.as_os_str())) {
                Ok(m) => {
                    tracing::warn!(
                        target: "vpn_core::tun",
                        "TUN/Wintun: DLL esplicito {} ({} byte)",
                        path_display,
                        m.len(),
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        target: "vpn_core::tun",
                        "TUN/Wintun: DLL esplicito {} (metadata fallita: {})",
                        path_display, e
                    );
                }
            }
        }
        None => {
            tracing::warn!(
                target: "vpn_core::tun",
                "TUN/Wintun: nessun percorso wintun.dll impostato (ricerca predefinita del processo)."
            );
        }
    }
}

pub struct TunDevice {
    device: tun::AsyncDevice,
    name: String,
    mtu: u16,
}

#[cfg(windows)]
fn recoverable_wintun_teardown_error(msg: &str) -> bool {
    let lower = msg.to_ascii_lowercase();
    lower.contains("register rings")
        || lower.contains("wintunstartsession")
        || lower.contains("0x000004df")
        || lower.contains("0x4df")
        || lower.contains("1247")
        || lower.contains("already_initialized")
        || lower.contains("inizializzazione")
}

#[cfg(windows)]
fn append_wintun_recovery_hint(msg: String) -> String {
    format!(
        "{} Suggerimento: chiudi e riapri PoliVPN o disabilita/riabilita la scheda di rete Wintun in Gestione dispositivi se l’errore persiste.",
        msg
    )
}

impl TunDevice {
    pub fn create(ip: &str, mtu: u16) -> Result<Self, String> {
        #[cfg(windows)]
        {
            match Self::try_create(ip, mtu) {
                Ok(d) => Ok(d),
                Err(e) if recoverable_wintun_teardown_error(&e) => {
                    diag::emit(
                        "Creazione TUN: sessione precedente ancora in chiusura, ritento tra breve…",
                    );
                    std::thread::sleep(Duration::from_millis(550));
                    Self::try_create(ip, mtu).map_err(append_wintun_recovery_hint)
                }
                Err(e) => Err(e),
            }
        }
        #[cfg(not(windows))]
        {
            Self::try_create(ip, mtu)
        }
    }

    fn try_create(ip: &str, mtu: u16) -> Result<Self, String> {
        diag::emit(format!(
            "Creazione interfaccia TUN con IP {} (MTU {}) …",
            ip, mtu
        ));
        let mut config = tun::Configuration::default();
        config.address(ip).netmask("255.255.255.255").mtu(mtu).up();

        #[cfg(windows)]
        if let Some(path) = WINTUN_DLL_PATH.get() {
            config.platform_config(|pc| {
                pc.wintun_file(path.clone());
            });
        }

        let device = tun::create_as_async(&config).map_err(|e| {
            #[cfg(windows)]
            emit_wintun_path_diagnostics_on_load_failure();

            format!("Failed to create TUN device: {}", format_error_chain(&e))
        })?;

        let name = device
            .tun_name()
            .map_err(|e| format!("Failed to get TUN name: {:?}", e))?;

        diag::emit(format!("Interfaccia TUN «{}» pronta.", name));

        Ok(Self { device, name, mtu })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn mtu(&self) -> u16 {
        self.mtu
    }

    /// Apre RX/TX Wintun asincrone per gli stati dell’[`crate::io::IoLoop`].
    pub fn into_split(self) -> std::io::Result<(DeviceWriter, DeviceReader, String, u16)> {
        let name = self.name;
        let mtu = self.mtu;
        tracing::debug!(
            target: "vpn_core::tun",
            "TUN device «{}»: split RX/TX (MTU {}).",
            name,
            mtu
        );
        let (w, r) = self.device.split()?;
        Ok((w, r, name, mtu))
    }
}
