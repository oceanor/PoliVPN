use std::process::Command;

pub struct RouteManager {
    helper_path: String,
}

impl RouteManager {
    pub fn new(helper_path: &str) -> Self {
        Self {
            helper_path: helper_path.to_string(),
        }
    }

    pub fn add_route(&self, network: &str, netmask: &str, gateway: &str) -> Result<(), String> {
        let output = Command::new(&self.helper_path)
            .arg("add-route")
            .arg(network)
            .arg(netmask)
            .arg(gateway)
            .output()
            .map_err(|e| format!("Failed to spawn vpn-helper: {}", e))?;

        if !output.status.success() {
            return Err(String::from_utf8_lossy(&output.stderr).to_string());
        }
        Ok(())
    }

    pub fn del_route(&self, network: &str, netmask: &str) -> Result<(), String> {
        let output = Command::new(&self.helper_path)
            .arg("del-route")
            .arg(network)
            .arg(netmask)
            .output()
            .map_err(|e| format!("Failed to spawn vpn-helper: {}", e))?;

        if !output.status.success() {
            return Err(String::from_utf8_lossy(&output.stderr).to_string());
        }
        Ok(())
    }
}
