use tun::AbstractDevice;

use crate::diag;
use crate::error_chain::format_error_chain;

#[cfg(windows)]
use std::ffi::OsString;
#[cfg(windows)]
use std::path::Path;
#[cfg(windows)]
use std::sync::OnceLock;

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
    device: tun::Device,
    name: String,
}

impl TunDevice {
    pub fn create(ip: &str) -> Result<Self, String> {
        diag::emit(format!("Creazione interfaccia TUN con IP {} …", ip));
        let mut config = tun::Configuration::default();
        config
            .address(ip)
            .netmask("255.255.255.255")
            .mtu(1354)
            .up();

        #[cfg(windows)]
        if let Some(path) = WINTUN_DLL_PATH.get() {
            config.platform_config(|pc| {
                pc.wintun_file(path.clone());
            });
        }

        let device = tun::create(&config).map_err(|e| {
            #[cfg(windows)]
            emit_wintun_path_diagnostics_on_load_failure();

            format!("Failed to create TUN device: {}", format_error_chain(&e))
        })?;

        let name = device.tun_name().map_err(|e| format!("Failed to get TUN name: {:?}", e))?;

        diag::emit(format!("Interfaccia TUN «{}» pronta.", name));

        Ok(Self { device, name })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn read(&self, buf: &mut [u8]) -> Result<usize, String> {
        self.device
            .recv(buf)
            .map_err(|e| format!("TUN read error: {}", e))
    }

    pub fn write(&self, buf: &[u8]) -> Result<usize, String> {
        self.device
            .send(buf)
            .map_err(|e| format!("TUN write error: {}", e))
    }
}

impl Drop for TunDevice {
    fn drop(&mut self) {
        tracing::info!("TUN device {} removed", self.name);
    }
}
