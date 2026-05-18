pub mod proto {
    pub const PPP_IP: u16 = 0x0021;
    pub const LCP: u16 = 0xC021;
    pub const IPCP: u16 = 0x8021;

    pub const LCP_CONF_REQ: u8 = 0x01;
    pub const LCP_CONF_ACK: u8 = 0x02;
    pub const LCP_CONF_NAK: u8 = 0x03;

    pub const IPCP_CONF_REQ: u8 = 0x01;
    pub const IPCP_CONF_ACK: u8 = 0x02;
    pub const IPCP_CONF_NAK: u8 = 0x03;

    pub const LCP_OPT_MRU: u8 = 0x01;
    pub const LCP_OPT_MAGIC_NUMBER: u8 = 0x05;

    pub const IPCP_OPT_IP_ADDRESS: u8 = 0x03;

    pub const HDLC_ADDR: u8 = 0xFF;
    pub const HDLC_CTRL: u8 = 0x03;

    pub const PPP_FCS_SIZE: usize = 2;
    pub const PPP_OVERHEAD: usize = 4;
}

/// Header tunnel Fortinet SSL‑VPN privo di framing IP esterno:
/// `total_size` (BE u16, payload PPP + 6) | `'P' 'P'` | `ppp_size` (BE u16) | payload HDLC.
/// Nessun byte aggiuntivo prima: il "protocol" PPP è dentro l'HDLC frame (`0xff 0x03 <proto> ...`).
pub const TUNNEL_HEADER_SIZE: usize = 6;

pub fn encode_tunnel_frame(ppp_hdlc_frame: &[u8]) -> Vec<u8> {
    let ppp_size = ppp_hdlc_frame.len() as u16;
    let total_size = ppp_size + TUNNEL_HEADER_SIZE as u16;
    let mut frame = Vec::with_capacity(total_size as usize);
    frame.extend_from_slice(&total_size.to_be_bytes());
    frame.extend_from_slice(&[0x50, 0x50]);
    frame.extend_from_slice(&ppp_size.to_be_bytes());
    frame.extend_from_slice(ppp_hdlc_frame);
    frame
}

pub fn decode_tunnel_frame(data: &[u8]) -> Option<&[u8]> {
    if data.len() < TUNNEL_HEADER_SIZE {
        return None;
    }
    if data[2] != 0x50 || data[3] != 0x50 {
        return None;
    }
    let ppp_size = u16::from_be_bytes([data[4], data[5]]) as usize;
    if data.len() < TUNNEL_HEADER_SIZE + ppp_size {
        return None;
    }
    Some(&data[TUNNEL_HEADER_SIZE..TUNNEL_HEADER_SIZE + ppp_size])
}

/// Estrae un frame tunnel completo dal buffer **consumando** i byte in testa.
/// Serve perché TCP/TLS può frammentare o unire più frame; non si può decodificare solo `read()` singoli.
pub fn pop_tunnel_frame(buf: &mut Vec<u8>) -> Option<Vec<u8>> {
    if buf.len() < TUNNEL_HEADER_SIZE {
        return None;
    }
    if buf[2] != 0x50 || buf[3] != 0x50 {
        return None;
    }
    let ppp_size = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    if buf.len() < TUNNEL_HEADER_SIZE + ppp_size {
        return None;
    }
    let inner = buf[TUNNEL_HEADER_SIZE..TUNNEL_HEADER_SIZE + ppp_size].to_vec();
    buf.drain(..TUNNEL_HEADER_SIZE + ppp_size);
    Some(inner)
}

pub fn build_hdlc_frame(protocol: u16, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(proto::PPP_OVERHEAD + payload.len());
    frame.push(proto::HDLC_ADDR);
    frame.push(proto::HDLC_CTRL);
    frame.extend_from_slice(&protocol.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// Parser tollerante per frame PPP dentro il tunnel Fortinet:
/// - Il gateway invia spesso frame **senza** `0xFF 0x03` (HDLC ACFC implicita): l’header `PP`
///   del tunnel sostituisce l’address/control HDLC quando il gateway usa framing compatto.
/// - Restano accettati anche i frame con prefisso `0xFF 0x03` per compatibilità (es. nostro `build_hdlc_frame`).
///
/// NOTA: Protocol Field Compression (PFC) richiede negoziazione esplicita in LCP e qui non viene mai
/// negoziata; quindi il protocollo è sempre su 2 byte.
pub fn parse_hdlc_frame(frame: &[u8]) -> Option<(u16, &[u8])> {
    if frame.len() < 2 {
        return None;
    }
    let offset = if frame.len() >= 4
        && frame[0] == proto::HDLC_ADDR
        && frame[1] == proto::HDLC_CTRL
    {
        2
    } else {
        0
    };
    if frame.len() < offset + 2 {
        return None;
    }
    let protocol = u16::from_be_bytes([frame[offset], frame[offset + 1]]);
    Some((protocol, &frame[offset + 2..]))
}

pub fn build_lcp_header(code: u8, identifier: u8, payload_len: u16) -> Vec<u8> {
    let length = payload_len + 4;
    vec![code, identifier, (length >> 8) as u8, (length & 0xFF) as u8]
}

pub fn build_ipcp_header(code: u8, identifier: u8, payload_len: u16) -> Vec<u8> {
    build_lcp_header(code, identifier, payload_len)
}
