use std::env;
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Default)]
struct PolivpnBuildVars {
    gateway: Option<String>,
    port: Option<String>,
    vpn_type: Option<String>,
    title: Option<String>,
    show_logo: Option<String>,
}

fn main() {
    apply_polivpn_rustc_env_from_env_files();

    let target = env::var("TARGET").unwrap_or_default();
    if target.contains("windows") {
        match ensure_wintun_dll(&target) {
            Ok(()) => {}
            Err(e) => println!(
                "cargo:warning=download wintun.dll fallito ({e}); se la build fallisce, estrai manualmente bin/<arch>/wintun.dll dallo zip ufficiale in resources/wintun.dll"
            ),
        }

        let dll = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("resources/wintun.dll");
        if !dll.is_file() {
            panic!(
                "wintun.dll mancante in {}.\n\
                 Scarica https://www.wintun.net/builds/wintun-0.14.1.zip e copia wintun/bin/<arch>/wintun.dll come resources/wintun.dll (vedi README sul sito Wintun).",
                dll.display()
            );
        }

        let manifest = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <dependency>
    <dependentAssembly>
      <assemblyIdentity
        type="win32"
        name="Microsoft.Windows.Common-Controls"
        version="6.0.0.0"
        processorArchitecture="*"
        publicKeyToken="6595b64144ccf1df"
        language="*"
      />
    </dependentAssembly>
  </dependency>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="requireAdministrator" uiAccess="false" />
      </requestedPrivileges>
    </security>
  </trustInfo>
</assembly>"#;

        let win = tauri_build::WindowsAttributes::new().app_manifest(manifest);
        tauri_build::try_build(tauri_build::Attributes::new().windows_attributes(win))
            .expect("failed to run tauri-build");
    } else {
        tauri_build::build();
    }
}

/// Legge `polivpn.build.env` e poi `.env` dalla radice del repo (una riga chiama l'altra in ordine:
/// valori successivi sovrascrivono). Emette `cargo:rustc-env` per `option_env!` in `lib.rs`.
fn apply_polivpn_rustc_env_from_env_files() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repo_root = manifest_dir.join("../..");

    let paths = [
        repo_root.join("polivpn.build.env"),
        repo_root.join(".env"),
    ];

    let mut merged = PolivpnBuildVars::default();
    for path in &paths {
        println!("cargo:rerun-if-changed={}", path.display());
        if !path.is_file() {
            continue;
        }
        if let Some(parsed) = parse_polivpn_env_file(path) {
            if parsed.gateway.is_some() {
                merged.gateway = parsed.gateway;
            }
            if parsed.port.is_some() {
                merged.port = parsed.port;
            }
            if parsed.vpn_type.is_some() {
                merged.vpn_type = parsed.vpn_type;
            }
            if parsed.title.is_some() {
                merged.title = parsed.title;
            }
            if parsed.show_logo.is_some() {
                merged.show_logo = parsed.show_logo;
            }
        }
    }

    if let Some(v) = merged.gateway {
        println!("cargo:rustc-env=POLIVPN_DEFAULT_GATEWAY={v}");
    }
    if let Some(v) = merged.port {
        println!("cargo:rustc-env=POLIVPN_DEFAULT_PORT={v}");
    }
    if let Some(v) = merged.vpn_type {
        println!("cargo:rustc-env=POLIVPN_VPN_TYPE={v}");
    }
    if let Some(v) = merged.title {
        println!("cargo:rustc-env=POLIVPN_TITLE={v}");
    }
    if let Some(v) = merged.show_logo {
        println!("cargo:rustc-env=POLIVPN_SHOW_LOGO={v}");
    }
}

fn parse_polivpn_env_file(path: &Path) -> Option<PolivpnBuildVars> {
    let contents = fs::read_to_string(path).ok()?;
    let mut out = PolivpnBuildVars::default();

    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (raw_key, raw_val) = line.split_once('=')?;
        let key = raw_key.trim();
        let mut val = raw_val.trim().to_string();
        if val.len() >= 2 {
            let bytes = val.as_bytes();
            let quote = bytes[0];
            if (quote == b'"' || quote == b'\'') && bytes[bytes.len() - 1] == quote {
                val = val[1..val.len() - 1].to_string();
            }
        }
        match key {
            "POLIVPN_DEFAULT_GATEWAY" => {
                if !val.is_empty() {
                    out.gateway = Some(val);
                }
            }
            "POLIVPN_DEFAULT_PORT" => {
                if !val.is_empty() {
                    out.port = Some(val);
                }
            }
            "POLIVPN_VPN_TYPE" | "VPN_TYPE" => {
                if !val.is_empty() {
                    out.vpn_type = Some(val);
                }
            }
            "POLIVPN_TITLE" | "TITLE" => {
                if !val.is_empty() {
                    out.title = Some(val);
                }
            }
            "POLIVPN_SHOW_LOGO" | "SHOW_LOGO" => {
                if !val.is_empty() {
                    out.show_logo = Some(val);
                }
            }
            _ => {}
        }
    }

    if out.gateway.is_none()
        && out.port.is_none()
        && out.vpn_type.is_none()
        && out.title.is_none()
        && out.show_logo.is_none()
    {
        None
    } else {
        Some(out)
    }
}

fn ensure_wintun_dll(target: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("cargo:rerun-if-env-changed=TARGET");

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let resources_dir = manifest_dir.join("resources");
    let dll_path = resources_dir.join("wintun.dll");

    if dll_path.is_file() {
        println!("cargo:rerun-if-changed={}", dll_path.display());
        return Ok(());
    }

    fs::create_dir_all(&resources_dir)?;

    let arch_folder = if target.starts_with("aarch64") {
        "arm64"
    } else if target.starts_with("thumbv7a") {
        "arm"
    } else if target.starts_with("i686") || target.starts_with("i586") {
        "x86"
    } else {
        "amd64"
    };

    let expected_suffix = format!("bin/{arch_folder}/wintun.dll");
    const WINTUN_ZIP_URL: &str = "https://www.wintun.net/builds/wintun-0.14.1.zip";

    let body = download_https(WINTUN_ZIP_URL)?;

    let reader = Cursor::new(body);
    let mut archive = zip::ZipArchive::new(reader)?;

    let mut idx_match = None;
    for i in 0..archive.len() {
        let file = archive.by_index(i)?;
        let name = file.name().replace('\\', "/");
        if name.ends_with(&expected_suffix) {
            idx_match = Some(i);
            break;
        }
    }

    let idx = idx_match.ok_or_else(|| {
        format!("entry */{expected_suffix} non trovata nello zip Wintun")
    })?;

    let mut entry = archive.by_index(idx)?;
    let mut out = fs::File::create(&dll_path)?;
    std::io::copy(&mut entry, &mut out)?;

    println!("cargo:rerun-if-changed={}", dll_path.display());

    Ok(())
}

fn download_https(url: &str) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let tmp = env::temp_dir().join(format!("wintun-fetch-{}.zip", std::process::id()));

    let curl_ok = Command::new("curl")
        .args(["-fsSL", "-o"])
        .arg(&tmp)
        .arg(url)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if !curl_ok {
        let ps = format!(
            "$ProgressPreference='SilentlyContinue'; Invoke-WebRequest -Uri '{}' -UseBasicParsing -OutFile '{}'",
            url,
            tmp.display()
        );
        let ok = Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", &ps])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            return Err(
                "scarica lo zip Wintun con curl o PowerShell non riuscita (nessuna connessione HTTPS)".into(),
            );
        }
    }

    let bytes = fs::read(&tmp)?;
    let _ = fs::remove_file(&tmp);
    Ok(bytes)
}
