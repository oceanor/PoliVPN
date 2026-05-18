use quick_xml::events::Event;
use quick_xml::Reader;

use crate::auth::VpnConfig;

/// `prefix:tag` oppure `{http://ns}tag` (namespace espanso da quick-xml).
fn xml_local_name(name: &[u8]) -> &[u8] {
    if name.first().copied() == Some(b'{') {
        if let Some(end) = name.iter().position(|&b| b == b'}') {
            if end + 1 < name.len() {
                return &name[end + 1..];
            }
        }
    }
    name.rsplit(|&b| b == b':').next().unwrap_or(name)
}

fn is_assigned_addr_tag(name: &[u8]) -> bool {
    let local = xml_local_name(name);
    local.eq_ignore_ascii_case(b"assigned-addr") || local.eq_ignore_ascii_case(b"assigned_addr")
}

/// Contenitore `<ipv4>...</ipv4>` o foglia `<ipv4 ipv4='...'/>`.
fn is_ipv4_tunnel_tag(name: &[u8]) -> bool {
    xml_local_name(name).eq_ignore_ascii_case(b"ipv4")
}

fn tag_is(name: &[u8], expected: &[u8]) -> bool {
    xml_local_name(name).eq_ignore_ascii_case(expected)
}

fn attribute_assigned_ip(attr_key: &[u8], attr_val: &[u8]) -> Option<String> {
    let lk = xml_local_name(attr_key);
    let candidate = lk.eq_ignore_ascii_case(b"ipv4")
        || lk.eq_ignore_ascii_case(b"ip")
        || lk.eq_ignore_ascii_case(b"address");
    if !candidate {
        return None;
    }
    let s = String::from_utf8_lossy(attr_val).trim().to_string();
    s.parse::<std::net::Ipv4Addr>().ok().map(|_| s)
}

fn parse_ipv4_trimmed(text: &[u8]) -> Option<String> {
    let s = String::from_utf8_lossy(text).trim().to_string();
    s.parse::<std::net::Ipv4Addr>().ok().map(|_| s)
}

fn scan_quoted_ipv4_attr(fragment: &str, attr: &str) -> Option<String> {
    let lower = fragment.to_ascii_lowercase();
    let needle = format!("{}=", attr.to_ascii_lowercase());
    let pos = lower.find(&needle)?;
    let bytes = fragment.as_bytes();
    let mut i = pos + needle.len();
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    let q = *bytes.get(i)?;
    if q != b'"' && q != b'\'' {
        return None;
    }
    i += 1;
    let start = i;
    while i < bytes.len() && bytes[i] != q {
        i += 1;
    }
    if i >= bytes.len() {
        return None;
    }
    let val = std::str::from_utf8(&bytes[start..i]).ok()?.trim();
    val.parse::<std::net::Ipv4Addr>().ok()?;
    Some(val.to_string())
}

fn fallback_assigned_ipv4(xml: &str) -> Option<String> {
    let lower = xml.to_ascii_lowercase();
    for needle in ["assigned-addr", "assigned_addr"] {
        let mut from = 0usize;
        while let Some(rel) = lower[from..].find(needle) {
            let anchor = from + rel;
            let rest = xml.get(anchor..)?;
            let tail_len = rest.find('>').map(|i| i + 480).unwrap_or(480).min(rest.len());
            let chunk = &rest[..tail_len];
            for attr in ["ipv4", "ip", "address"] {
                if let Some(ip) = scan_quoted_ipv4_attr(chunk, attr) {
                    return Some(ip);
                }
            }
            from = anchor + needle.len();
        }
    }
    None
}

fn try_take_ip_from_element_attrs(e: &quick_xml::events::BytesStart<'_>) -> Option<String> {
    for attr in e.attributes().flatten() {
        if let Some(ip) = attribute_assigned_ip(attr.key.as_ref(), attr.value.as_ref()) {
            return Some(ip);
        }
    }
    None
}

pub fn parse_vpn_config_xml(xml: &str) -> Result<VpnConfig, String> {
    let xml = xml.strip_prefix('\u{feff}').unwrap_or(xml);
    let xml = xml.trim_start();

    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut config = VpnConfig {
        assigned_ip: String::new(),
        dns_servers: Vec::new(),
        dns_suffix: None,
        split_routes: Vec::new(),
    };

    let mut buf = Vec::new();
    let mut assigned_nesting: i32 = 0;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Empty(ref e)) => {
                if config.assigned_ip.is_empty() {
                    let name_binding = e.name();
                    let n = name_binding.as_ref();
                    if is_assigned_addr_tag(n) || is_ipv4_tunnel_tag(n) {
                        if let Some(ip) = try_take_ip_from_element_attrs(e) {
                            config.assigned_ip = ip;
                        }
                    }
                }
                match_element_children(e, &mut config)?;
            }
            Ok(Event::Start(ref e)) => {
                let name_binding = e.name();
                let n = name_binding.as_ref();
                if is_assigned_addr_tag(n) {
                    assigned_nesting += 1;
                    if config.assigned_ip.is_empty() {
                        if let Some(ip) = try_take_ip_from_element_attrs(e) {
                            config.assigned_ip = ip;
                        }
                    }
                } else if config.assigned_ip.is_empty() && is_ipv4_tunnel_tag(n) {
                    if let Some(ip) = try_take_ip_from_element_attrs(e) {
                        config.assigned_ip = ip;
                    }
                }
                match_element_children(e, &mut config)?;
            }
            Ok(Event::Text(ref e)) => {
                if assigned_nesting > 0 && config.assigned_ip.is_empty() {
                    if let Some(ip) = parse_ipv4_trimmed(e.as_ref()) {
                        config.assigned_ip = ip;
                    }
                }
            }
            Ok(Event::CData(ref e)) => {
                if assigned_nesting > 0 && config.assigned_ip.is_empty() {
                    if let Some(ip) = parse_ipv4_trimmed(e.as_ref()) {
                        config.assigned_ip = ip;
                    }
                }
            }
            Ok(Event::End(ref e)) => {
                let name_binding = e.name();
                let n = name_binding.as_ref();
                if is_assigned_addr_tag(n) {
                    assigned_nesting = assigned_nesting.saturating_sub(1);
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(format!("XML parse error: {}", e)),
            _ => {}
        }
        buf.clear();
    }

    if config.assigned_ip.is_empty() {
        if let Some(ip) = fallback_assigned_ipv4(xml) {
            config.assigned_ip = ip;
        }
    }

    if config.assigned_ip.is_empty() {
        return Err(
            "No assigned IP in VPN config XML (assigned-addr / ipv4); schema gateway non standard o risposta vuota."
                .into(),
        );
    }

    Ok(config)
}

fn match_element_children(
    e: &quick_xml::events::BytesStart<'_>,
    config: &mut VpnConfig,
) -> Result<(), String> {
    let name_binding = e.name();
    let name = name_binding.as_ref();
    if tag_is(name, b"dns") {
        for attr in e.attributes().flatten() {
            match xml_local_name(attr.key.as_ref()) {
                k if k.eq_ignore_ascii_case(b"ip") => {
                    config
                        .dns_servers
                        .push(String::from_utf8_lossy(&attr.value).to_string());
                }
                k if k.eq_ignore_ascii_case(b"domain") => {
                    config.dns_suffix = Some(String::from_utf8_lossy(&attr.value).to_string());
                }
                _ => {}
            }
        }
    } else if tag_is(name, b"addr") {
        let mut ip = String::new();
        let mut mask = String::new();
        for attr in e.attributes().flatten() {
            match xml_local_name(attr.key.as_ref()) {
                k if k.eq_ignore_ascii_case(b"ip") => {
                    ip = String::from_utf8_lossy(&attr.value).to_string();
                }
                k if k.eq_ignore_ascii_case(b"mask") => {
                    mask = String::from_utf8_lossy(&attr.value).to_string();
                }
                _ => {}
            }
        }
        if !ip.is_empty() && !mask.is_empty() {
            config.split_routes.push((ip, mask));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assigned_ipv4_attribute() {
        let xml = r#"<cfg><assigned-addr ipv4="10.1.2.3"/></cfg>"#;
        let c = parse_vpn_config_xml(xml).unwrap();
        assert_eq!(c.assigned_ip, "10.1.2.3");
    }

    #[test]
    fn sslvpn_tunnel_nested_ipv4_block() {
        let xml = r#"<?xml version='1.0'?><sslvpn-tunnel ver='1'><ipv4><assigned-addr ipv4='192.168.1.6'/></ipv4></sslvpn-tunnel>"#;
        let c = parse_vpn_config_xml(xml).unwrap();
        assert_eq!(c.assigned_ip, "192.168.1.6");
    }

    #[test]
    fn ipv4_leaf_single_tag() {
        let xml = r#"<t><ipv4 ipv4="10.9.9.9"/></t>"#;
        let c = parse_vpn_config_xml(xml).unwrap();
        assert_eq!(c.assigned_ip, "10.9.9.9");
    }

    #[test]
    fn expanded_namespace_brace_name() {
        let tag = b"{http://example.com/ns}assigned-addr";
        assert!(is_assigned_addr_tag(tag));
    }

    #[test]
    fn assigned_ip_attribute_alias() {
        let xml = r#"<ssltunnel><assigned-addr ip='192.168.99.7'/></ssltunnel>"#;
        let c = parse_vpn_config_xml(xml).unwrap();
        assert_eq!(c.assigned_ip, "192.168.99.7");
    }

    #[test]
    fn assigned_text_body() {
        let xml = "<vpn>\n<assigned-addr>\n  172.16.0.44 \n</assigned-addr>\n</vpn>";
        let c = parse_vpn_config_xml(xml).unwrap();
        assert_eq!(c.assigned_ip, "172.16.0.44");
    }

    #[test]
    fn namespaced_prefix_tag() {
        let xml = r#"<r xmlns:f="x"><f:assigned-addr ipv4="10.0.0.2"/></r>"#;
        let c = parse_vpn_config_xml(xml).unwrap();
        assert_eq!(c.assigned_ip, "10.0.0.2");
    }

    #[test]
    fn fallback_scan_raw() {
        let xml = r#"<!-- x --><assigned_addr ipv4="10.10.10.10"/>"#;
        let c = parse_vpn_config_xml(xml).unwrap();
        assert_eq!(c.assigned_ip, "10.10.10.10");
    }

    #[test]
    fn strips_bom() {
        let xml = "\u{feff}<r><assigned-addr ipv4=\"1.2.3.4\"/></r>";
        let c = parse_vpn_config_xml(xml).unwrap();
        assert_eq!(c.assigned_ip, "1.2.3.4");
    }
}
