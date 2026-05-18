use std::process::Command;

pub fn add_route(network: &str, netmask: &str, gateway: &str) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        let cidr = netmask_to_cidr(netmask);
        let dest = format!("{}/{}", network, cidr);
        let output = Command::new("route")
            .args(["-n", "add", &dest, gateway])
            .output()
            .map_err(|e| format!("Failed to run route add: {}", e))?;

        if !output.status.success() {
            return Err(format!(
                "route add failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }
    }

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let output = Command::new("route")
            .creation_flags(CREATE_NO_WINDOW)
            .args(["add", network, "mask", netmask, gateway])
            .output()
            .map_err(|e| format!("Failed to run route add: {}", e))?;

        if !output.status.success() {
            return Err(format!(
                "route add failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }
    }

    Ok(())
}

pub fn del_route(network: &str, netmask: &str) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        let cidr = netmask_to_cidr(netmask);
        let dest = format!("{}/{}", network, cidr);
        let output = Command::new("route")
            .args(["-n", "delete", &dest])
            .output()
            .map_err(|e| format!("Failed to run route delete: {}", e))?;

        if !output.status.success() {
            eprintln!(
                "Warning: route delete failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let output = Command::new("route")
            .creation_flags(CREATE_NO_WINDOW)
            .args(["delete", network, "mask", netmask])
            .output()
            .map_err(|e| format!("Failed to run route delete: {}", e))?;

        if !output.status.success() {
            eprintln!(
                "Warning: route delete failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    Ok(())
}

#[cfg(target_os = "macos")]
fn netmask_to_cidr(mask: &str) -> u8 {
    mask.split('.')
        .filter_map(|o| o.parse::<u32>().ok())
        .fold(0, |acc, o| acc + o.count_ones() as u8)
}
