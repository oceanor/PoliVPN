use keyring::Entry;

const SERVICE_NAME: &str = "PoliVPN-Fortinet";

pub fn save_credentials(
    gateway: &str,
    port: u16,
    username: &str,
    password: &str,
) -> Result<(), String> {
    let entry = Entry::new(SERVICE_NAME, username).map_err(|e| e.to_string())?;
    let payload = serde_json::json!({
        "gateway": gateway,
        "port": port,
        "password": password,
    });
    entry
        .set_password(&payload.to_string())
        .map_err(|e| e.to_string())
}

pub fn get_credentials(username: &str) -> Result<Option<serde_json::Value>, String> {
    let entry = Entry::new(SERVICE_NAME, username).map_err(|e| e.to_string())?;
    match entry.get_password() {
        Ok(payload) => {
            let creds: serde_json::Value =
                serde_json::from_str(&payload).map_err(|e| e.to_string())?;
            Ok(Some(creds))
        }
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}
