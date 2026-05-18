//! Windows routing and DNS helpers via `netsh` / PowerShell (processi senza finestra console).
#![cfg(windows)]

use std::net::{Ipv4Addr, ToSocketAddrs};
use std::process::Command;

use serde::Deserialize;

use crate::diag;

/// Returned after a split route has been successfully installed (`netsh add route`).
#[derive(Clone, Debug)]
pub struct InstalledRoute {
    pub prefix_cidr: String,
    pub iface_alias: String,
}

/// DNS servers applied via `netsh` on an interface.
#[derive(Clone, Debug)]
pub struct InstalledDns {
    pub iface_alias: String,
    pub had_servers: bool,
}

/// NRPT namespace string (typically `.corp.local`); full-tunnel usa `.` catch-all).
#[derive(Clone, Debug)]
pub struct NrptRule {
    pub namespace: String,
}

/// Default IPv4 route verso Internet (WAN) — nexthop, alias e indice interfaccia.
#[derive(Clone, Debug)]
pub struct WanDefault {
    pub next_hop: String,
    pub if_index: u32,
    pub alias: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct WanDefaultJson {
    next_hop: String,
    if_index: u32,
    alias: String,
}

/// Risolve l’host del FortiGate (`vpn.example.it` o IPv4 diretta) in stringa dotted.
pub fn resolve_gateway_ip(host: &str) -> Result<String, String> {
    let h = host.trim();
    if h.parse::<Ipv4Addr>().is_ok() {
        return Ok(h.to_string());
    }
    let mut addrs = (h, 443u16)
        .to_socket_addrs()
        .map_err(|e| format!("Risoluzione DNS gateway «{h}»: {e}"))?;
    let Some(sock) = addrs.next() else {
        return Err(format!("Risoluzione DNS gateway «{h}»: nessun indirizzo"));
    };
    match sock.ip() {
        std::net::IpAddr::V4(v4) => Ok(v4.to_string()),
        std::net::IpAddr::V6(_) => Err(format!(
            "Gateway «{h}» risolve solo in IPv6; serve IPv4 per il ping TLS/route"
        )),
    }
}

/// Prima default IPv4 con next-hop raggiungibile (`!= 0.0.0.0`), ordinata per metrica bassa.
/// Salta gli alias in `skip_aliases` (case-insensitive), es. adattatori Wintun ancora temporaneamente visibili.
pub fn read_wan_default<S: AsRef<str>>(skip_aliases: &[S]) -> Result<WanDefault, String> {
    let mut skip_ps = String::from("@(");
    for (i, s) in skip_aliases.iter().enumerate() {
        let t = escape_ps_single(s.as_ref());
        if i > 0 {
            skip_ps.push(',');
        }
        skip_ps.push('\'');
        skip_ps.push_str(&t);
        skip_ps.push('\'');
    }
    skip_ps.push(')');

    let ps = format!(
        r#"
$skips = {skip_ps}
$cands = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' |
  Where-Object {{ $_.NextHop -and ($_.NextHop -ne '0.0.0.0') }} |
  Sort-Object RouteMetric, InterfaceMetric
foreach ($route in $cands) {{
  $name = $route.InterfaceAlias
  if ([string]::IsNullOrWhiteSpace($name)) {{ continue }}
  $skip = $false
  foreach ($s in $skips) {{
    if ($name -ieq $s) {{ $skip = $true; break }}
  }}
  if ($skip) {{ continue }}
  [pscustomobject]@{{
    NextHop = $route.NextHop
    IfIndex = [int]$route.InterfaceIndex
    Alias = $name
  }} | ConvertTo-Json -Compress
  exit 0
}}
Write-Error 'Nessuna default route IPv4 con gateway valido (WAN).'
exit 1
"#
    );

    let mut cmd = Command::new("powershell");
    cmd.args([
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        &ps,
    ]);
    let json = run_cmd("Rileva interfaccia WAN predefinita (IPv4)", cmd)?;
    let w: WanDefaultJson = serde_json::from_str(json.trim()).map_err(|e| {
        format!("JSON default WAN inatteso ({e}): {}", json.trim().chars().take(200).collect::<String>())
    })?;
    let next_hop = w.next_hop.trim().to_string();
    let alias = w.alias.trim().to_string();
    if next_hop.is_empty() || alias.is_empty() {
        return Err("Default WAN: NextHop o Alias vuoti".into());
    }
    Ok(WanDefault {
        next_hop,
        if_index: w.if_index,
        alias,
    })
}

/// Route host `/32` del server VPN via interfaccia WAN (evita loop TLS quando il default va in TUN).
pub fn add_host_route_via_wan(vpn_server_ip: &str, wan: &WanDefault) -> Result<InstalledRoute, String> {
    let prefix = format!("{}/32", vpn_server_ip.trim());
    let mut cmd = Command::new("netsh");
    cmd.args([
        "interface",
        "ipv4",
        "add",
        "route",
        &format!("prefix={}", prefix),
        &format!("interface={}", wan.alias.trim()),
        &format!("nexthop={}", wan.next_hop.trim()),
        "metric=1",
        "store=active",
    ]);
    let op = format!(
        "Aggiungi route host {prefix} verso WAN («{}»)",
        wan.alias.trim()
    );
    run_cmd(&op, cmd)?;
    Ok(InstalledRoute {
        prefix_cidr: prefix,
        iface_alias: wan.alias.clone(),
    })
}

/// Full-tunnel IPv4: due metà di default via TUN (OpenVPN-style), senza toccare la default WAN.
pub fn add_default_via_tunnel(tun_alias: &str, tunnel_nexthop: &str) -> Result<Vec<InstalledRoute>, String> {
    let mut out = Vec::with_capacity(2);
    for (net, bits) in [("0.0.0.0", 1u8), ("128.0.0.0", 1u8)] {
        let prefix = format!("{net}/{bits}");
        let mut cmd = Command::new("netsh");
        cmd.args([
            "interface",
            "ipv4",
            "add",
            "route",
            &format!("prefix={}", prefix),
            &format!("interface={}", tun_alias.trim()),
            &format!("nexthop={}", tunnel_nexthop.trim()),
            "metric=1",
            "store=active",
        ]);
        let op = format!(
            "Aggiungi route «{prefix}» su interfaccia «{}»",
            tun_alias.trim()
        );
        run_cmd(&op, cmd)?;
        out.push(InstalledRoute {
            prefix_cidr: prefix,
            iface_alias: tun_alias.trim().to_string(),
        });
    }
    Ok(out)
}

fn is_noise_success_stdout(s: &str) -> bool {
    let collapsed: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    let t = collapsed
        .trim_matches(|c| c == '.' || c == '!')
        .to_ascii_lowercase();
    t.is_empty() || t == "ok"
}

fn log_success_stdout(operation: &str, stdout: &str) {
    let t = stdout.trim();
    if t.is_empty() || is_noise_success_stdout(t) {
        return;
    }
    let max = 280usize;
    let mut out = t.chars().take(max).collect::<String>();
    if t.chars().count() > max {
        out.push('…');
    }
    let one_line: String = out.split_whitespace().collect::<Vec<_>>().join(" ");
    diag::emit(format!("[net] {operation}: {one_line}"));
}

pub(crate) fn run_cmd(operation: &str, mut cmd: Command) -> Result<String, String> {
    diag::emit(format!("[net] {}", operation));
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    let output = cmd
        .output()
        .map_err(|e| format!("{operation}: avvio comando fallito: {e}"))?;

    let code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

    if !output.status.success() {
        if is_route_already_exists(&stderr, &stdout) {
            diag::emit(format!(
                "[net] Route già presente (operazione ignorata): {operation}",
            ));
            return Ok(stdout);
        }
        let msg = format!(
            "{operation}: uscita {code} — stderr={} stdout={}",
            if stderr.is_empty() { "<vuoto>" } else { &stderr },
            if stdout.is_empty() { "<vuoto>" } else { &stdout },
        );
        diag::emit(format!("[net] Errore: {msg}"));
        return Err(msg);
    }

    log_success_stdout(operation, &stdout);

    Ok(stdout)
}

fn is_route_already_exists(stderr: &str, stdout: &str) -> bool {
    let s = format!("{} {}", stderr, stdout).to_lowercase();
    s.contains("already exists")
        || s.contains("the object already exists")
        || s.contains("already present")
        || s.contains("esiste già")
        || s.contains("gia esiste")
        || s.contains("oggetto") && s.contains("esiste")
}

fn netmask_to_cidr(mask: &str) -> Result<u8, String> {
    let octets: Vec<u32> = mask
        .split('.')
        .map(|o| {
            o.parse::<u32>()
                .map_err(|e| format!("netmask {mask}: {e}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if octets.len() != 4 {
        return Err(format!("netmask {mask}: richiesti 4 ottetti IPv4"));
    }
    let bits: u32 = octets.iter().fold(0, |acc, o| (acc << 8) | (o & 0xff));
    if bits != 0 && (!bits).wrapping_add(1).count_ones() != 1 {
        return Err(format!("netmask {mask}: non contigua"));
    }
    Ok(bits.count_ones() as u8)
}

fn line_has_connected_state(lower: &str) -> bool {
    lower.split_whitespace().any(|w| w == "connected")
        && !(lower.contains("disconnect") || lower.contains("disconnecting"))
}

fn extract_iface_name_after_state(line: &str) -> Option<String> {
    let lower = line.to_lowercase();
    let pos = lower.find("connected")?;
    let after = line[pos + "connected".len()..].trim().to_owned();
    if after.is_empty() {
        None
    } else {
        Some(after)
    }
}

/// Resolve the `netsh` interface alias for a [`tun::Device::tun_name`] value.
pub fn resolve_iface_alias(tun_name: &str) -> String {
    let mut candidates: Vec<String> = vec![tun_name.trim().to_string()];
    const FALLBACKS: &[&str] = &["PoliVPN", "Wintun Userspace Tunnel", "Wintun"];
    for fb in FALLBACKS {
        if !candidates.iter().any(|c| c.eq_ignore_ascii_case(fb)) {
            candidates.push((*fb).to_string());
        }
    }

    let mut cmd = Command::new("netsh");
    cmd.args(["interface", "ipv4", "show", "interfaces"]);
    let stdout = match run_cmd("Elenco interfacce IPv4 collegate", cmd) {
        Ok(s) => s,
        Err(e) => {
            diag::emit(format!(
                "[net] Avviso: elenco interfacce IPv4 non disponibile ({e}); uso nome TUN «{tun_name}»"
            ));
            return tun_name.to_string();
        }
    };

    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let lower = trimmed.to_lowercase();
        if !line_has_connected_state(&lower) {
            continue;
        }
        if lower.contains(" idx ") || trimmed.starts_with("---") || lower.starts_with("idx ") {
            continue;
        }

        for cand in &candidates {
            if lower.contains(&cand.to_lowercase()) {
                if let Some(alias) = extract_iface_name_after_state(trimmed) {
                    diag::emit(format!(
                        "[net] Interfaccia di rete individuata: «{}» (da tun_name «{}»)",
                        alias, tun_name
                    ));
                    return alias;
                }
            }
        }
    }

    diag::emit(format!(
        "[net] Avviso: nessun alias in netsh per «{}», si usa il nome TUN direttamente",
        tun_name
    ));
    tun_name.to_string()
}

/// Add a pushed split route (`<addr>` from Fortinet XML): `destination/mask → nexthop` on `alias`.
pub fn add_split_route(
    alias: &str,
    net: &str,
    mask: &str,
    nexthop: &str,
) -> Result<InstalledRoute, String> {
    if net.trim() == "0.0.0.0" && netmask_to_cidr(mask.trim()) == Ok(0) {
        diag::emit(
            "[net] Avviso: route predefinita 0.0.0.0/0 dall’XML in split-tunnel; \
             viene applicata comunque — potresti perdere Internet finché sei connesso."
                .to_string(),
        );
    }

    let cidr = netmask_to_cidr(mask.trim())?;
    let prefix = format!("{}/{}", net.trim(), cidr);

    let mut cmd = Command::new("netsh");
    cmd.args([
        "interface",
        "ipv4",
        "add",
        "route",
        &format!("prefix={}", prefix),
        &format!("interface={}", alias),
        &format!("nexthop={}", nexthop.trim()),
        "store=active",
    ]);

    let op = format!(
        "Aggiungi route split «{prefix}» su «{alias}»",
        prefix = prefix,
        alias = alias.trim(),
    );
    run_cmd(&op, cmd)?;

    Ok(InstalledRoute {
        prefix_cidr: prefix,
        iface_alias: alias.to_string(),
    })
}

/// Remove route installed by [`add_split_route`].
pub fn del_split_route(route: &InstalledRoute) -> Result<(), String> {
    let mut cmd = Command::new("netsh");
    cmd.args([
        "interface",
        "ipv4",
        "delete",
        "route",
        &format!("prefix={}", route.prefix_cidr.trim()),
        &format!("interface={}", route.iface_alias.trim()),
    ]);

    let op = format!(
        "Elimina route «{}» da «{}»",
        route.prefix_cidr.trim(),
        route.iface_alias.trim()
    );
    match run_cmd(&op, cmd) {
        Ok(_) => Ok(()),
        Err(e) if is_not_found_failure(&e) => {
            diag::emit(format!(
                "[net] Avviso: route assente o già rimossa durante la pulizia ({e})",
            ));
            Ok(())
        }
        Err(e) => Err(e),
    }
}

fn is_not_found_failure(msg: &str) -> bool {
    let lower = msg.to_lowercase();
    lower.contains("not found")
        || lower.contains("non è stato trovato")
        || lower.contains("non trovato")
        || lower.contains("could not find")
}

/// Static DNS servers on the Wintun interface.
pub fn apply_dns(alias: &str, servers: &[String]) -> Result<InstalledDns, String> {
    if servers.is_empty() {
        return Ok(InstalledDns {
            iface_alias: alias.to_string(),
            had_servers: false,
        });
    }

    let primary = servers[0].trim();
    {
        let mut cmd = Command::new("netsh");
        cmd.args([
            "interface",
            "ipv4",
            "set",
            "dnsservers",
            &format!("name={}", alias),
            "static",
            primary,
            "validate=no",
        ]);
        let op = format!("Imposta DNS primario ({primary}) su «{alias}»");
        run_cmd(&op, cmd)?;
    }

    for (i, srv) in servers.iter().enumerate().skip(1) {
        let s = srv.trim();
        let mut cmd = Command::new("netsh");
        cmd.args([
            "interface",
            "ipv4",
            "add",
            "dnsservers",
            &format!("name={}", alias),
            s,
            &format!("index={}", i + 1),
            "validate=no",
        ]);
        let idx = i + 1;
        let op = format!(
            "Aggiunge server DNS secondario ({s}) su «{alias}» (indice {idx})",
        );
        run_cmd(&op, cmd)?;
    }

    Ok(InstalledDns {
        iface_alias: alias.to_string(),
        had_servers: true,
    })
}

/// Restore DHCP DNS on interface (best effort if interface vanished).
pub fn clear_dns(applied: &InstalledDns) -> Result<(), String> {
    if !applied.had_servers {
        return Ok(());
    }

    let mut cmd = Command::new("netsh");
    cmd.args([
        "interface",
        "ipv4",
        "set",
        "dnsservers",
        &format!("name={}", applied.iface_alias.trim()),
        "source=dhcp",
    ]);

    let op = format!("Ripristina DNS da DHCP su «{}»", applied.iface_alias.trim());
    match run_cmd(&op, cmd) {
        Ok(_) => Ok(()),
        Err(e) if is_not_found_failure(&e) => {
            diag::emit(format!(
                "[net] Avviso: ripristino DNS DHCP su «{}» fallito ({e})",
                applied.iface_alias
            ));
            Ok(())
        }
        Err(e) => Err(e),
    }
}

fn escape_ps_single(s: &str) -> String {
    // Single-quoted PS string literal: escape ' as ''
    s.replace('\'', "''")
}

fn dns_servers_summary_for_log(servers: &[String]) -> String {
    let joined = servers
        .iter()
        .filter_map(|x| {
            let t = x.trim();
            if t.is_empty() {
                None
            } else {
                Some(t)
            }
        })
        .collect::<Vec<_>>()
        .join(", ");
    const MAX: usize = 96;
    if joined.len() <= MAX {
        joined
    } else {
        format!("{}…", joined.chars().take(MAX).collect::<String>())
    }
}

/// NRPT suffix rule: namespace should be `.domain.tld`.
pub fn nrpt_add(namespace: &str, servers: &[String]) -> Result<NrptRule, String> {
    let ns_trim = namespace.trim();
    if ns_trim.is_empty() || servers.is_empty() {
        return Ok(NrptRule {
            namespace: String::new(),
        });
    }

    let ns = if ns_trim.starts_with('.') {
        ns_trim.to_string()
    } else {
        format!(".{}", ns_trim)
    };

    let servers_list: Vec<String> = servers
        .iter()
        .map(|s| format!("'{}'", escape_ps_single(s.trim())))
        .collect();

    let ps = format!(
        "Add-DnsClientNrptRule -Namespace '{}' -NameServers ({}) -DisplayName 'PoliVPN'",
        escape_ps_single(&ns),
        servers_list.join(","),
    );

    let dns = dns_servers_summary_for_log(servers);
    let op = format!("Aggiungi regola NRPT DNS: dominio «{ns}» — server {dns}");

    let mut cmd = Command::new("powershell");
    cmd.args([
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        &ps,
    ]);

    run_cmd(&op, cmd)?;

    Ok(NrptRule { namespace: ns })
}

/// Remove NRPT rules PoliVPN created for [`nrpt_add`].
pub fn nrpt_remove(rule: &NrptRule) -> Result<(), String> {
    if rule.namespace.is_empty() {
        return Ok(());
    }

    let ns_esc = escape_ps_single(&rule.namespace);
    let ps = format!(
        "Get-DnsClientNrptRule | Where-Object {{ $_.Namespace -eq '{}' }} | Remove-DnsClientNrptRule -Force",
        ns_esc,
    );

    let op = format!("Rimuovi regole NRPT DNS: dominio «{}»", rule.namespace.trim());

    let mut cmd = Command::new("powershell");
    cmd.args([
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        &ps,
    ]);

    run_cmd(&op, cmd)?;
    Ok(())
}
