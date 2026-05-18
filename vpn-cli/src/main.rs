use clap::Parser;
use tracing_subscriber;

#[derive(Parser)]
#[command(name = "vpn-cli", about = "PoliVPN - Fortinet SSL-VPN CLI Client")]
struct Cli {
    #[arg(short, long)]
    gateway: String,

    #[arg(short = 'P', long, default_value = "443")]
    port: u16,

    #[arg(short, long)]
    username: String,

    #[arg(short = 'p', long)]
    password: String,

    #[arg(short, long, default_value = "")]
    realm: String,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter("vpn_core=debug,vpn_cli=info")
        .init();

    let cli = Cli::parse();

    tracing::info!("Connecting to {}:{}...", cli.gateway, cli.port);

    let gateway = vpn_core::auth::VpnGateway {
        host: cli.gateway,
        port: cli.port,
    };

    let auth = match vpn_core::auth::FortiVpnAuth::new(gateway) {
        Ok(a) => a,
        Err(e) => {
            tracing::error!("Failed to create client: {}", e);
            return;
        }
    };

    tracing::info!("Authenticating as {}...", cli.username);
    let cookie = match auth.login(&cli.username, &cli.password, &cli.realm).await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Login failed: {}", e);
            return;
        }
    };

    tracing::info!("Authenticated. Cookie: {}...", &cookie[..20.min(cookie.len())]);

    tracing::info!("Requesting VPN allocation...");
    if let Err(e) = auth.request_vpn_allocation(&cookie).await {
        tracing::error!("VPN allocation failed: {}", e);
        return;
    }

    tracing::info!("Opening data TLS for XML (session 1)...");
    let config = {
        let mut tls_xml = match vpn_core::tls::connect_insecure_tls(&auth.gateway.host, auth.gateway.port).await {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("TLS connect (XML) failed: {}", e);
                return;
            }
        };

        tracing::info!("Fetching VPN configuration over TLS...");
        match vpn_core::tls_http::fetch_vpn_config_xml(
            &mut tls_xml,
            &auth.gateway.host,
            auth.gateway.port,
            &cookie,
        )
        .await
        {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("Config fetch failed: {}", e);
                return;
            }
        }
    };

    tracing::info!("Assigned IP: {}", config.assigned_ip);
    tracing::info!("DNS servers: {:?}", config.dns_servers);
    tracing::info!("Split routes: {:?}", config.split_routes);

    tracing::info!("Opening TLS connection for tunnel (second session after XML)...");
    let mut tls_stream = match vpn_core::tls::connect_insecure_tls(&auth.gateway.host, auth.gateway.port).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("TLS connect (tunnel) failed: {}", e);
            return;
        }
    };

    tracing::info!("Starting tunnel (GET sslvpn-tunnel on new TLS)...");
    let mut tunnel_pending = match vpn_core::tls_http::send_sslvpn_tunnel_get(&mut tls_stream, &cookie).await {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("Tunnel start failed: {}", e);
            return;
        }
    };

    tracing::info!("Negotiating LCP...");
    let mut ppp = vpn_core::ppp::PppSession::new();
    if let Err(e) = ppp.negotiate_lcp(&mut tls_stream, &mut tunnel_pending).await {
        tracing::error!("LCP negotiation failed: {}", e);
        return;
    }

    tracing::info!("Negotiating IPCP...");
    let assigned_ip =
        match ppp.negotiate_ipcp(&mut tls_stream, &mut tunnel_pending, &config.assigned_ip).await
        {
            Ok(ip) => ip,
            Err(e) => {
                tracing::error!("IPCP negotiation failed: {}", e);
                return;
            }
        };

    tracing::info!("PPP negotiation complete. Local IP: {}", assigned_ip);

    let tun = match vpn_core::tun::TunDevice::create(&assigned_ip) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("TUN device creation failed: {}", e);
            return;
        }
    };

    tracing::info!("TUN device {} created", tun.name());

    #[cfg(windows)]
    if let Some(helper) = std::env::current_exe().ok().and_then(|p| {
        let h = p.parent()?.join("vpn-helper.exe");
        h.is_file().then_some(h)
    }) {
        let rm = vpn_core::routes::RouteManager::new(helper.to_string_lossy().as_ref());
        for (net, mask) in &config.split_routes {
            if let Err(e) = rm.add_route(net, mask, &assigned_ip) {
                tracing::warn!("route {} {}: {}", net, mask, e);
            }
        }
    } else if !config.split_routes.is_empty() {
        tracing::warn!(
            "Split routes not applied: place vpn-helper.exe next to vpn-cli (admin may be required)."
        );
    }

    tracing::info!("VPN connected. Press Ctrl+C to disconnect.");

    let io = vpn_core::io::IoLoop::new();
    if let Err(e) = io.run(&tun, &mut tls_stream, tunnel_pending).await {
        tracing::error!("IO loop error: {}", e);
    }

    tracing::info!("Disconnected.");
}
