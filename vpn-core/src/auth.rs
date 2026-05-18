use std::collections::HashMap;

use reqwest::{Client, redirect::Policy};
use reqwest::header::{COOKIE, REFERER, SET_COOKIE};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AuthError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("Authentication failed: {0}")]
    AuthFailed(String),
    #[error("No SVPNCOOKIE in response")]
    NoCookie,
    #[error("Unexpected server response")]
    UnexpectedResponse(String),
}

pub struct VpnGateway {
    pub host: String,
    pub port: u16,
}

/// Rimuove `http://` / `https://` (anche ripetuti), strip del path: evita URL tipo `https://https://host/...`.
pub fn normalize_gateway_host(input: &str) -> String {
    fn strip_leading_schemes(mut s: &str) -> &str {
        loop {
            let t = s.trim_start();
            if t.len() >= 8 && t[..8].eq_ignore_ascii_case("https://") {
                s = &t[8..];
                continue;
            }
            if t.len() >= 7 && t[..7].eq_ignore_ascii_case("http://") {
                s = &t[7..];
                continue;
            }
            break;
        }
        s.trim_start()
    }

    let s = strip_leading_schemes(input.trim());
    let host_only = s.split('/').next().unwrap_or("").trim();
    host_only.trim_end_matches('/').to_string()
}

pub struct VpnConfig {
    pub assigned_ip: String,
    pub dns_servers: Vec<String>,
    pub dns_suffix: Option<String>,
    pub split_routes: Vec<(String, String)>,
}

/// User-Agent usato dall’implementazione sul gateway Fortinet (token `SV1`).
const FORTIVPN_USER_AGENT: &str = "Mozilla/5.0 SV1";

pub struct FortiVpnAuth {
    client: Client,
    pub gateway: VpnGateway,
}

impl FortiVpnAuth {
    fn base_https(&self) -> String {
        format!("https://{}:{}", self.gateway.host, self.gateway.port)
    }

    pub fn new(mut gateway: VpnGateway) -> Result<Self, AuthError> {
        gateway.host = normalize_gateway_host(&gateway.host);
        if gateway.host.is_empty() {
            return Err(AuthError::AuthFailed(
                "Gateway non valido (host vuoto).".into(),
            ));
        }

        let client = Client::builder()
            // FortiGate risponde spesso 302 su GET /remote/fortisslvpn_xml; senza follow il corpo è vuoto.
            .redirect(Policy::limited(10))
            .cookie_store(true)
            .danger_accept_invalid_certs(true)
            .user_agent(FORTIVPN_USER_AGENT)
            .build()?;

        Ok(Self { client, gateway })
    }

    /// Effettua il login e restituisce il valore da passare all’header HTTP `Cookie` sulle richieste successive
    /// (`Set-Cookie` uniti, incluso `SVPNCOOKIE`), perché il jar dei cookie non sempre invia il cookie su `/remote/*`.
    pub async fn login(
        &self,
        username: &str,
        password: &str,
        realm: &str,
    ) -> Result<String, AuthError> {
        // POST compatibile FortiOS portal: parametri AJAX richiesti per stabilire cookie di sessione.
        let body = format!(
            "username={}&credential={}&realm={}&ajax=1&just_logged_in=1",
            urlencoding::encode(username),
            urlencoding::encode(password),
            urlencoding::encode(realm),
        );

        let base = self.base_https();

        // FortiOS 7.4+ può rispondere con JS `top.location="/remote/login"` senza redirect HTTP;
        // GET `/` stabilisce cookie/sessione portale prima del login.
        let root = fortinet_http_headers(self.client.get(format!("{}/", base)))
            .send()
            .await?;
        let root_cookies = cookie_header_from_all_set_cookies(&root);
        let _ = root.text().await?;

        // Cookie di contesto portale su FortiOS recenti / portale SPA.
        let prefetch = fortinet_http_headers(
            self.client.get(format!("{}/remote/login", base)),
        )
        .send()
        .await?;
        let prefetch_cookies = cookie_header_from_all_set_cookies(&prefetch);
        let _ = prefetch.text().await?;

        let url = format!(
            "https://{}:{}/remote/logincheck",
            self.gateway.host, self.gateway.port
        );

        let resp = fortinet_http_headers(
            self
                .client
                .post(&url)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(body),
        )
        .send()
        .await?;

        let merged = cookie_header_from_all_set_cookies(&resp);
        let svpn_pair = extract_svpn_cookie(&resp);

        let text = resp.text().await?;

        if let Some(ret_raw) = extract_param(&text, "ret=") {
            // Fortinet può rispondere `ret=1,redir=/remote/...` senza `&` tra i token.
            let ret = ret_raw
                .split(',')
                .next()
                .map(str::trim)
                .unwrap_or("");

            match ret {
                "1" => {}
                "0" => {
                    return Err(AuthError::AuthFailed(
                        "Credenziali errate".into(),
                    ))
                }
                other => {
                    return Err(AuthError::AuthFailed(format!(
                        "Codice di errore dal gateway: ret={}",
                        other
                    )))
                }
            }
        }

        let cookie_header = merge_cookie_layers_ordered(
            &[root_cookies, prefetch_cookies, merged],
            svpn_pair,
        );

        if cookie_header.contains("SVPNCOOKIE") {
            Ok(cookie_header)
        } else {
            if text.contains("tokeninfo=") || text.contains("ftm_push") {
                Err(AuthError::AuthFailed(
                    "Il gateway richiede 2FA, non supportata da questo client."
                        .into(),
                ))
            } else if text.contains("hostcheck_install") {
                Err(AuthError::AuthFailed(
                    "Il gateway richiede Host Check / FortiClient (hostcheck_install). \
                     Questo client non lo supporta."
                        .into(),
                ))
            } else {
                Err(AuthError::NoCookie)
            }
        }
    }

    /// `cookie_header`: valore header `Cookie` restituito da [`Self::login`] (tutti i `Set-Cookie` uniti).
    pub async fn request_vpn_allocation(&self, cookie_header: &str) -> Result<(), AuthError> {
        let base = self.base_https();
        fortinet_http_headers(
            self.client
                .get(format!("{}/remote/index", base))
                .header(COOKIE, cookie_header)
                .header(REFERER, format!("{}/remote/login", base)),
        )
        .send()
        .await?;
        fortinet_http_headers(
            self.client
                .get(format!("{}/remote/fortisslvpn", base))
                .header(COOKIE, cookie_header)
                .header(REFERER, format!("{}/remote/index", base)),
        )
        .send()
        .await?;
        Ok(())
    }
}

/// Header HTTP ripetuti per le richieste Fortinet portal: anti-cache + Accept neutri.
fn fortinet_http_headers(rb: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    rb.header("Pragma", "no-cache")
        .header(
            "Cache-Control",
            "no-store, no-cache, must-revalidate",
        )
        .header("If-Modified-Since", "Sat, 1 Jan 2000 00:00:00 GMT")
        .header("Accept", "*/*")
        .header("Accept-Encoding", "identity")
}

/// Unisce più layer di cookie in ordine (`/` → `/remote/login` → post-login); gli ultimi vincono su duplicati.
/// `SVPNCOOKIE` viene assicurato se presente negli header della risposta login.
fn merge_cookie_layers_ordered(layers: &[Option<String>], svpn_only: Option<String>) -> String {
    let mut map: HashMap<String, String> = HashMap::new();

    fn ingest(map: &mut HashMap<String, String>, s: &str) {
        for seg in s.split(';') {
            let seg = seg.trim();
            if let Some((name, _)) = seg.split_once('=') {
                let key = name.trim().to_ascii_lowercase();
                map.insert(key, seg.to_string());
            }
        }
    }

    for layer in layers {
        if let Some(ref s) = layer {
            ingest(&mut map, s);
        }
    }
    if let Some(s) = svpn_only {
        map.entry("svpncookie".to_string()).or_insert(s);
    }

    map.into_values().collect::<Vec<_>>().join("; ")
}

fn cookie_header_from_all_set_cookies(resp: &reqwest::Response) -> Option<String> {
    let mut pairs = Vec::new();
    for header in resp.headers().get_all(SET_COOKIE) {
        let value = header.to_str().ok()?;
        let pair = value.split(';').next()?.trim();
        if pair.contains('=') && !pair.is_empty() {
            pairs.push(pair.to_string());
        }
    }
    if pairs.is_empty() {
        None
    } else {
        Some(pairs.join("; "))
    }
}

fn extract_svpn_cookie(resp: &reqwest::Response) -> Option<String> {
    for header in resp.headers().get_all(SET_COOKIE) {
        let value = header.to_str().ok()?;
        if let Some(start) = value.find("SVPNCOOKIE=") {
            let cookie_part = &value[start..];
            let end = cookie_part.find(';').unwrap_or(cookie_part.len());
            return Some(cookie_part[..end].to_string());
        }
    }
    None
}

fn extract_param(body: &str, key: &str) -> Option<String> {
    body.split('&')
        .find(|pair| pair.starts_with(key))
        .map(|pair| pair[key.len()..].to_string())
}

pub(crate) fn response_looks_like_html_portal(body: &str) -> bool {
    let sample: String = body.chars().take(3072).collect::<String>().to_ascii_lowercase();
    sample.contains("<!doctype html")
        || sample.contains("<html")
        || sample.contains("main-app")
}

pub(crate) fn preview_config_body(body: &str) -> String {
    const MAX: usize = 420;
    let collapsed: String = body
        .chars()
        .map(|c| if c.is_control() && c != '\t' { ' ' } else { c })
        .take(MAX)
        .collect::<String>()
        .trim()
        .to_string();
    if collapsed.is_empty() {
        "(corpo vuoto)".into()
    } else {
        collapsed
    }
}
