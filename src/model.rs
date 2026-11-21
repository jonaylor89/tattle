//! Types shared by the daemon, the TUI, the CLI and (as JSON) the Omarchy
//! shell plugin. Everything here is serialized over the control socket, so
//! field names are part of the wire protocol: rename with care.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    Deny,
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Action::Allow => "allow",
            Action::Deny => "deny",
        })
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Hash, Default)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    #[default]
    Out,
    In,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Hash, Default)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    #[default]
    Any,
    Tcp,
    Udp,
}

impl Proto {
    pub fn from_num(n: u8) -> Proto {
        match n {
            6 => Proto::Tcp,
            17 => Proto::Udp,
            _ => Proto::Any,
        }
    }
    pub fn matches(self, actual: Proto) -> bool {
        self == Proto::Any || self == actual
    }
}

impl fmt::Display for Proto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Proto::Any => "any",
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
        })
    }
}

/// A CIDR network, e.g. `10.0.0.0/8` or `2001:db8::/32`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct IpNet {
    pub addr: IpAddr,
    pub prefix: u8,
}

impl IpNet {
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = canonical_ip(ip);
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let bits = self.prefix.min(32) as u32;
                if bits == 0 {
                    return true;
                }
                let mask = u32::MAX << (32 - bits);
                (u32::from(net) & mask) == (u32::from(ip) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let bits = self.prefix.min(128) as u32;
                if bits == 0 {
                    return true;
                }
                let mask = u128::MAX << (128 - bits);
                (u128::from(net) & mask) == (u128::from(ip) & mask)
            }
            _ => false,
        }
    }
}

impl FromStr for IpNet {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (a, p) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let addr: IpAddr = a
            .trim()
            .parse()
            .map_err(|_| format!("invalid IP address: {a}"))?;
        let addr = canonical_ip(addr);
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match p {
            Some(p) => p
                .trim()
                .parse::<u8>()
                .map_err(|_| format!("invalid prefix: {p}"))?,
            None => max,
        };
        if prefix > max {
            return Err(format!("prefix /{prefix} too long"));
        }
        Ok(IpNet { addr, prefix })
    }
}

impl fmt::Display for IpNet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let max = if self.addr.is_ipv4() { 32 } else { 128 };
        if self.prefix == max {
            write!(f, "{}", self.addr)
        } else {
            write!(f, "{}/{}", self.addr, self.prefix)
        }
    }
}

/// IPv4-mapped IPv6 addresses (::ffff:1.2.3.4) are folded to plain IPv4 so a
/// rule written for 1.2.3.4 also covers dual-stack sockets.
pub fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

/// Which remote endpoint a rule covers.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Hash, Default)]
#[serde(tag = "kind", content = "value", rename_all = "lowercase")]
pub enum Remote {
    /// Every server.
    #[default]
    Any,
    /// Exactly this host name.
    Host(String),
    /// This domain and every subdomain of it.
    Domain(String),
    /// An address or CIDR network.
    Ip(String),
    /// Local network: RFC 1918, link-local, ULA, loopback, multicast.
    Local,
}

impl Remote {
    pub fn describe(&self) -> String {
        match self {
            Remote::Any => "any server".into(),
            Remote::Host(h) => h.clone(),
            Remote::Domain(d) => format!("*.{d}"),
            Remote::Ip(n) => n.clone(),
            Remote::Local => "local network".into(),
        }
    }

    /// Parse the compact form used by the CLI and the TUI editor:
    /// `any`, `local`, `*.example.com`, `example.com`, `10.0.0.0/8`.
    pub fn parse(s: &str) -> Result<Remote, String> {
        let s = s.trim();
        if s.is_empty() || s.eq_ignore_ascii_case("any") || s == "*" {
            return Ok(Remote::Any);
        }
        if s.eq_ignore_ascii_case("local") || s.eq_ignore_ascii_case("lan") {
            return Ok(Remote::Local);
        }
        if let Some(d) = s.strip_prefix("*.") {
            return valid_hostname(d).map(Remote::Domain);
        }
        if s.parse::<IpNet>().is_ok() {
            return Ok(Remote::Ip(s.parse::<IpNet>().unwrap().to_string()));
        }
        valid_hostname(s).map(Remote::Host)
    }
}

pub fn valid_hostname(s: &str) -> Result<String, String> {
    let s = s.trim().trim_end_matches('.').to_ascii_lowercase();
    if s.is_empty() || s.len() > 253 {
        return Err("host name must be 1-253 characters".into());
    }
    for label in s.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(format!("invalid host name: {s}"));
        }
        if !label
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(format!("invalid character in host name: {s}"));
        }
    }
    Ok(s)
}

/// Inclusive port range.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct PortRange {
    pub lo: u16,
    pub hi: u16,
}

impl PortRange {
    pub fn single(p: u16) -> Self {
        PortRange { lo: p, hi: p }
    }
    pub fn contains(&self, p: u16) -> bool {
        self.lo <= p && p <= self.hi
    }
    pub fn parse(s: &str) -> Result<Option<PortRange>, String> {
        let s = s.trim();
        if s.is_empty() || s.eq_ignore_ascii_case("any") || s == "*" {
            return Ok(None);
        }
        let (a, b) = s.split_once('-').unwrap_or((s, s));
        let lo: u16 = a.trim().parse().map_err(|_| format!("invalid port: {a}"))?;
        let hi: u16 = b.trim().parse().map_err(|_| format!("invalid port: {b}"))?;
        if lo > hi {
            return Err(format!("port range {lo}-{hi} is reversed"));
        }
        Ok(Some(PortRange { lo, hi }))
    }
}

impl fmt::Display for PortRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.lo == self.hi {
            write!(f, "{}", self.lo)
        } else {
            write!(f, "{}-{}", self.lo, self.hi)
        }
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Lifetime {
    #[default]
    Forever,
    /// Expires when the process with this pid and start time is gone.
    UntilQuit { pid: u32, start_time: u64 },
    /// Expires at this unix timestamp.
    Until { at: u64 },
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
#[serde(rename_all = "lowercase")]
pub enum RuleSource {
    #[default]
    User,
    /// Shipped with tattle so the system keeps working (DNS, DHCP, NTP...).
    Default,
}

/// The process selector meaning "any process".
pub const ANY_PROCESS: &str = "*";

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct Rule {
    #[serde(default)]
    pub id: u64,
    #[serde(default = "yes")]
    pub enabled: bool,
    pub action: Action,
    #[serde(default)]
    pub direction: Direction,
    /// Process identity (see `ProcessInfo::identity`) or `*` for any process.
    pub process: String,
    #[serde(default)]
    pub remote: Remote,
    #[serde(default)]
    pub port: Option<PortRange>,
    #[serde(default)]
    pub proto: Proto,
    /// Restrict to one local user; None means every user.
    #[serde(default)]
    pub uid: Option<u32>,
    #[serde(default)]
    pub lifetime: Lifetime,
    /// Only active while this profile is selected; None means always.
    #[serde(default)]
    pub profile: Option<String>,
    #[serde(default)]
    pub note: String,
    #[serde(default)]
    pub source: RuleSource,
    #[serde(default)]
    pub created: u64,
    #[serde(default)]
    pub hits: u64,
    #[serde(default)]
    pub last_hit: Option<u64>,
}

fn yes() -> bool {
    true
}

impl Rule {
    pub fn new(action: Action, process: impl Into<String>, remote: Remote) -> Rule {
        Rule {
            id: 0,
            enabled: true,
            action,
            direction: Direction::Out,
            process: process.into(),
            remote,
            port: None,
            proto: Proto::Any,
            uid: None,
            lifetime: Lifetime::Forever,
            profile: None,
            note: String::new(),
            source: RuleSource::User,
            created: now(),
            hits: 0,
            last_hit: None,
        }
    }

    pub fn is_any_process(&self) -> bool {
        self.process == ANY_PROCESS
    }

    /// Human summary, e.g. "allow firefox → *.github.com tcp/443".
    pub fn summary(&self) -> String {
        let who = if self.is_any_process() {
            "any process".to_string()
        } else {
            display_name(&self.process)
        };
        let port = match self.port {
            Some(p) if self.proto == Proto::Any => format!(" port {p}"),
            Some(p) => format!(" {}/{}", self.proto, p),
            None if self.proto != Proto::Any => format!(" {}", self.proto),
            None => String::new(),
        };
        let arrow = if self.direction == Direction::Out {
            "→"
        } else {
            "←"
        };
        format!(
            "{} {} {} {}{}",
            self.action,
            who,
            arrow,
            self.remote.describe(),
            port
        )
    }
}

/// Short human name for a process identity: the script for interpreters,
/// otherwise the executable's basename.
pub fn display_name(identity: &str) -> String {
    if identity == ANY_PROCESS {
        return "any process".into();
    }
    let base = |p: &str| p.rsplit('/').next().unwrap_or(p).to_string();
    match identity.split_once(" :: ") {
        // `python3 -m http.server` reads better than "-m http.server".
        Some((exe, script)) if script.starts_with("-m ") => format!("{} {script}", base(exe)),
        Some((_, script)) => base(script),
        None => base(identity),
    }
}

/// What the daemon knows about a process owning a socket.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub user: String,
    /// Absolute path of the executable ("kernel" when no process owns it).
    pub exe: String,
    /// For interpreters, the script being run.
    pub script: Option<String>,
    pub cmdline: Vec<String>,
    pub start_time: u64,
    /// The executable was replaced or removed since the process started.
    pub exe_deleted: bool,
}

impl ProcessInfo {
    /// The key rules match on. Scripts are keyed by interpreter and script so
    /// allowing one Python tool does not allow every Python program.
    pub fn identity(&self) -> String {
        match &self.script {
            Some(s) => format!("{} :: {}", self.exe, s),
            None => self.exe.clone(),
        }
    }
    pub fn name(&self) -> String {
        display_name(&self.identity())
    }
}

pub const KERNEL_IDENTITY: &str = "kernel";

/// One connection attempt as seen by the daemon.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct Connection {
    pub direction: Direction,
    pub proto: Proto,
    pub local_ip: IpAddr,
    pub local_port: u16,
    pub remote_ip: IpAddr,
    pub remote_port: u16,
    /// Host names that resolved to remote_ip, most relevant first.
    pub hostnames: Vec<String>,
    pub process: ProcessInfo,
}

impl Connection {
    pub fn host(&self) -> String {
        self.hostnames
            .first()
            .cloned()
            .unwrap_or_else(|| self.remote_ip.to_string())
    }
    pub fn identity(&self) -> String {
        self.process.identity()
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    /// Ask about every connection no rule covers.
    #[default]
    Alert,
    /// Allow unknown connections silently (still logged).
    SilentAllow,
    /// Deny unknown connections silently.
    SilentDeny,
}

impl Mode {
    pub fn label(self) -> &'static str {
        match self {
            Mode::Alert => "Alert",
            Mode::SilentAllow => "Silent · allow",
            Mode::SilentDeny => "Silent · deny",
        }
    }
}

impl FromStr for Mode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "alert" | "ask" => Ok(Mode::Alert),
            "silent-allow" | "allow" => Ok(Mode::SilentAllow),
            "silent-deny" | "deny" => Ok(Mode::SilentDeny),
            _ => Err(format!(
                "unknown mode '{s}' (alert, silent-allow, silent-deny)"
            )),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct Blocklist {
    pub name: String,
    pub url: String,
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default)]
    pub entries: usize,
    #[serde(default)]
    pub updated: Option<u64>,
    #[serde(default)]
    pub error: Option<String>,
}

/// Runtime-adjustable settings, persisted by the daemon.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(default)]
pub struct Settings {
    /// Master switch. When off, nothing is filtered (but DNS is still learned).
    pub enabled: bool,
    pub mode: Mode,
    /// Seconds an alert waits for an answer before `timeout_action` applies.
    pub prompt_timeout: u64,
    pub timeout_action: Action,
    /// What to do in alert mode when no alert UI is connected (e.g. at boot).
    pub no_ui_action: Action,
    /// Also filter new inbound connections to listening sockets.
    pub inbound: bool,
    pub profiles: Vec<String>,
    pub active_profile: Option<String>,
    pub blocklists: Vec<Blocklist>,
    /// Hours between blocklist refreshes; 0 disables automatic refresh.
    pub blocklist_refresh_hours: u64,
    /// Where the map draws "you". None: the time zone's city.
    pub home: Option<Coord>,
    /// Refresh the downloaded location database monthly.
    pub geo_auto_update: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            enabled: true,
            mode: Mode::Alert,
            prompt_timeout: 60,
            timeout_action: Action::Deny,
            no_ui_action: Action::Allow,
            inbound: false,
            profiles: vec!["Home".into(), "Work".into(), "Public Wi-Fi".into()],
            active_profile: None,
            blocklists: Vec::new(),
            blocklist_refresh_hours: 24,
            home: None,
            geo_auto_update: false,
        }
    }
}

/// An unanswered connection alert.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct Prompt {
    pub id: u64,
    pub conn: Connection,
    pub created: u64,
    pub deadline: u64,
    /// How many connection attempts are waiting on this answer.
    pub attempts: u32,
    /// Suggested registrable domain for the "whole domain" option.
    pub domain: Option<String>,
    /// Well-known name of the port, e.g. "https".
    pub service: Option<String>,
    /// Where the server is, if a location database is installed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub geo: Option<GeoInfo>,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub enum RemoteScope {
    #[default]
    Host,
    Domain,
    Ip,
    Any,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub enum DecisionLifetime {
    Once,
    UntilQuit,
    #[default]
    Forever,
    /// Seconds.
    For(u64),
}

/// The answer to an alert.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct Decision {
    pub action: Action,
    #[serde(default)]
    pub remote: RemoteScope,
    /// Only this port (and protocol) rather than any port.
    #[serde(default = "yes")]
    pub port_only: bool,
    /// The rule covers every process, not just the asking one.
    #[serde(default)]
    pub any_process: bool,
    #[serde(default)]
    pub lifetime: DecisionLifetime,
    /// Save into the active profile instead of globally.
    #[serde(default)]
    pub in_profile: bool,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    Rule,
    Blocklist,
    Prompt,
    Mode,
    NoUi,
    Timeout,
    Disabled,
    Own,
}

/// One logged connection.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct ConnEvent {
    pub ts: u64,
    pub conn: Connection,
    pub action: Action,
    pub reason: Reason,
    pub rule_id: Option<u64>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub struct RemoteStats {
    pub host: String,
    pub ip: String,
    pub ports: Vec<u16>,
    pub proto: Proto,
    pub allowed: u64,
    pub denied: u64,
    pub tx: u64,
    pub rx: u64,
    pub last_seen: u64,
    pub last_action: Option<Action>,
    /// Open connections right now, and bytes per second over the last sample.
    #[serde(default)]
    pub active: u32,
    #[serde(default)]
    pub tx_rate: u64,
    #[serde(default)]
    pub rx_rate: u64,
    /// Where the server is, if a location database is installed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub geo: Option<GeoInfo>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub struct AppStats {
    pub identity: String,
    pub name: String,
    pub exe: String,
    pub last_pid: u32,
    pub user: String,
    pub allowed: u64,
    pub denied: u64,
    pub tx: u64,
    pub rx: u64,
    /// Bytes per second over the last sample window.
    pub tx_rate: u64,
    pub rx_rate: u64,
    pub active: u32,
    pub last_seen: u64,
    pub remotes: Vec<RemoteStats>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub struct Status {
    pub version: String,
    pub pid: u32,
    pub uptime: u64,
    pub settings: Settings,
    pub rules: usize,
    pub pending: usize,
    pub allowed: u64,
    pub denied: u64,
    pub tx_rate: u64,
    pub rx_rate: u64,
    pub tx_total: u64,
    pub rx_total: u64,
    pub ui_clients: usize,
    pub dns_cache: usize,
    pub blocked_domains: usize,
    pub inbound_active: bool,
}

/// Best-effort registrable domain ("eTLD+1") without shipping the whole
/// public suffix list: covers generic TLDs and the common two-level suffixes.
pub fn registrable_domain(host: &str) -> Option<String> {
    if host.parse::<IpAddr>().is_ok() {
        return None;
    }
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2 {
        return None;
    }
    const TWO_LEVEL: &[&str] = &[
        "co.uk",
        "org.uk",
        "ac.uk",
        "gov.uk",
        "me.uk",
        "ltd.uk",
        "plc.uk",
        "net.uk",
        "com.au",
        "net.au",
        "org.au",
        "edu.au",
        "gov.au",
        "co.nz",
        "org.nz",
        "net.nz",
        "co.jp",
        "ne.jp",
        "or.jp",
        "ac.jp",
        "go.jp",
        "co.kr",
        "or.kr",
        "com.br",
        "net.br",
        "org.br",
        "gov.br",
        "com.cn",
        "net.cn",
        "org.cn",
        "gov.cn",
        "com.mx",
        "org.mx",
        "gob.mx",
        "co.in",
        "net.in",
        "org.in",
        "gov.in",
        "co.za",
        "org.za",
        "com.tr",
        "com.tw",
        "org.tw",
        "com.hk",
        "com.sg",
        "com.ar",
        "com.co",
        "com.pl",
        "co.il",
        "org.il",
        "co.id",
        "or.id",
        "com.my",
        "com.ph",
        "com.vn",
        "com.ua",
        "co.th",
        "com.pe",
        "com.sa",
        "com.eg",
        "github.io",
        "gitlab.io",
        "pages.dev",
        "workers.dev",
        "vercel.app",
        "netlify.app",
        "herokuapp.com",
        "fly.dev",
        "cloudfront.net",
        "amazonaws.com",
        "azurewebsites.net",
        "blogspot.com",
        "appspot.com",
        "firebaseapp.com",
        "web.app",
    ];
    let n = labels.len();
    let last2 = format!("{}.{}", labels[n - 2], labels[n - 1]);
    if TWO_LEVEL.contains(&last2.as_str()) {
        if n >= 3 {
            return Some(format!("{}.{}", labels[n - 3], last2));
        }
        return None;
    }
    Some(last2)
}

pub fn service_name(proto: Proto, port: u16) -> Option<&'static str> {
    Some(match (proto, port) {
        (_, 22) => "ssh",
        (_, 25) => "smtp",
        (_, 53) => "dns",
        (Proto::Udp, 67 | 68) => "dhcp",
        (_, 80) => "http",
        (Proto::Udp, 123) => "ntp",
        (_, 143) => "imap",
        (Proto::Tcp, 443) => "https",
        (Proto::Udp, 443) => "quic",
        (_, 465) => "smtps",
        (_, 587) => "submission",
        (_, 853) => "dns-over-tls",
        (_, 993) => "imaps",
        (_, 1194) => "openvpn",
        (Proto::Udp, 3478 | 19302) => "stun",
        (_, 5222) => "xmpp",
        (Proto::Udp, 5353) => "mdns",
        (_, 5432) => "postgres",
        (_, 6379) => "redis",
        (_, 6443) => "kubernetes",
        (_, 8080) => "http-alt",
        (_, 9418) => "git",
        (Proto::Udp, 41641) => "tailscale",
        (Proto::Udp, 51820) => "wireguard",
        _ => return None,
    })
}

/// Is this a local-network address (never routed to the internet)?
pub fn is_local_ip(ip: IpAddr) -> bool {
    match canonical_ip(ip) {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_broadcast()
                // 100.64.0.0/10 carrier-grade NAT (also Tailscale)
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 64)
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            v6.is_loopback()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00 // ULA
                || (s[0] & 0xffc0) == 0xfe80 // link-local
        }
    }
}

pub fn human_bytes(b: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = b as f64;
    let mut i = 0;
    while v >= 1000.0 && i < UNITS.len() - 1 {
        v /= 1000.0;
        i += 1;
    }
    if i == 0 {
        format!("{b} B")
    } else if v < 10.0 {
        format!("{v:.1} {}", UNITS[i])
    } else {
        format!("{v:.0} {}", UNITS[i])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipnet_contains() {
        let n: IpNet = "10.0.0.0/8".parse().unwrap();
        assert!(n.contains("10.1.2.3".parse().unwrap()));
        assert!(!n.contains("11.0.0.1".parse().unwrap()));
        assert!(n.contains("::ffff:10.9.9.9".parse().unwrap()));
        let n6: IpNet = "2001:db8::/32".parse().unwrap();
        assert!(n6.contains("2001:db8:1::1".parse().unwrap()));
        assert!(!n6.contains("2001:db9::1".parse().unwrap()));
        let all: IpNet = "0.0.0.0/0".parse().unwrap();
        assert!(all.contains("8.8.8.8".parse().unwrap()));
        assert!("1.2.3.4/33".parse::<IpNet>().is_err());
    }

    #[test]
    fn remote_parse() {
        assert_eq!(Remote::parse("any").unwrap(), Remote::Any);
        assert_eq!(
            Remote::parse("*.GitHub.com").unwrap(),
            Remote::Domain("github.com".into())
        );
        assert_eq!(
            Remote::parse("api.github.com.").unwrap(),
            Remote::Host("api.github.com".into())
        );
        assert_eq!(
            Remote::parse("1.2.3.0/24").unwrap(),
            Remote::Ip("1.2.3.0/24".into())
        );
        assert_eq!(
            Remote::parse("1.2.3.4").unwrap(),
            Remote::Ip("1.2.3.4".into())
        );
        assert!(Remote::parse("bad host!").is_err());
    }

    #[test]
    fn registrable() {
        assert_eq!(
            registrable_domain("api.github.com").as_deref(),
            Some("github.com")
        );
        assert_eq!(
            registrable_domain("www.bbc.co.uk").as_deref(),
            Some("bbc.co.uk")
        );
        assert_eq!(registrable_domain("co.uk"), None);
        assert_eq!(registrable_domain("1.2.3.4"), None);
        assert_eq!(registrable_domain("localhost"), None);
    }

    #[test]
    fn ports() {
        assert_eq!(PortRange::parse("any").unwrap(), None);
        assert_eq!(
            PortRange::parse("443").unwrap(),
            Some(PortRange::single(443))
        );
        assert_eq!(
            PortRange::parse("1000-2000").unwrap(),
            Some(PortRange { lo: 1000, hi: 2000 })
        );
        assert!(PortRange::parse("2000-1000").is_err());
    }

    #[test]
    fn identity_names() {
        let p = ProcessInfo {
            exe: "/usr/bin/python3.13".into(),
            script: Some("/home/u/bin/sync.py".into()),
            ..Default::default()
        };
        assert_eq!(p.identity(), "/usr/bin/python3.13 :: /home/u/bin/sync.py");
        assert_eq!(p.name(), "sync.py");
        assert_eq!(display_name("/usr/lib/firefox/firefox"), "firefox");
        assert_eq!(
            display_name("/usr/bin/python3 :: -m http.server"),
            "python3 -m http.server"
        );
    }

    #[test]
    fn local_ips() {
        assert!(is_local_ip("192.168.1.1".parse().unwrap()));
        assert!(is_local_ip("fe80::1".parse().unwrap()));
        assert!(is_local_ip("100.100.1.1".parse().unwrap()));
        assert!(!is_local_ip("1.1.1.1".parse().unwrap()));
        assert!(!is_local_ip("2606:4700::1111".parse().unwrap()));
    }
}

// ------------------------------------------------------------------ map

/// A point on the globe, in degrees.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Debug, Default)]
pub struct Coord {
    pub lat: f64,
    pub lon: f64,
}

impl Coord {
    /// Parse "52.52,13.40" (or with a space instead of the comma).
    pub fn parse(s: &str) -> Result<Coord, String> {
        let parts: Vec<&str> = s
            .split(|c: char| c == ',' || c.is_whitespace())
            .filter(|p| !p.is_empty())
            .collect();
        let bad = || format!("expected LAT,LON in degrees (e.g. 52.52,13.40), got '{s}'");
        if parts.len() != 2 {
            return Err(bad());
        }
        let lat: f64 = parts[0].parse().map_err(|_| bad())?;
        let lon: f64 = parts[1].parse().map_err(|_| bad())?;
        if !(-90.0..=90.0).contains(&lat) || !(-180.0..=180.0).contains(&lon) {
            return Err("latitude must be within ±90 and longitude within ±180".into());
        }
        Ok(Coord { lat, lon })
    }

    /// Great-circle distance in kilometres.
    pub fn distance_km(self, o: Coord) -> f64 {
        let (p1, p2) = (self.lat.to_radians(), o.lat.to_radians());
        let dp = p2 - p1;
        let dl = (o.lon - self.lon).to_radians();
        let a = (dp / 2.0).sin().powi(2) + p1.cos() * p2.cos() * (dl / 2.0).sin().powi(2);
        6371.0 * 2.0 * a.sqrt().min(1.0).asin()
    }
}

/// What the location database knows about one address.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub struct GeoInfo {
    pub lat: f64,
    pub lon: f64,
    /// ISO 3166 country code, e.g. "DE".
    #[serde(default)]
    pub cc: String,
    #[serde(default)]
    pub country: String,
    #[serde(default)]
    pub city: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asn: Option<u32>,
    /// The network's owner, e.g. "Amazon.com, Inc.".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,
}

impl GeoInfo {
    /// "Frankfurt, Germany", or just the country.
    pub fn place(&self) -> String {
        match (self.city.is_empty(), self.country.is_empty()) {
            (false, false) => format!("{}, {}", self.city, self.country),
            (true, false) => self.country.clone(),
            (false, true) => self.city.clone(),
            (true, true) => self.cc.clone(),
        }
    }
}

/// Where the map puts you.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub struct Home {
    pub lat: f64,
    pub lon: f64,
    /// "New York (time zone)" or "set by you".
    pub label: String,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub enum GeoState {
    /// No database installed.
    #[default]
    Missing,
    Downloading,
    Ready,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
#[serde(default)]
pub struct GeoStatus {
    pub state: GeoState,
    /// Attribution for the database in use, e.g. "DB-IP City Lite (2026-11)".
    pub source: Option<String>,
    /// Where the database lives.
    pub path: Option<String>,
    /// Owner names come from a separate ASN database.
    pub has_asn: bool,
    /// Why the last download failed.
    pub error: Option<String>,
}

/// One server as the map sees it.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
#[serde(default)]
pub struct MapServer {
    pub app: String,
    pub identity: String,
    pub host: String,
    pub ip: String,
    pub ports: Vec<u16>,
    pub org: Option<String>,
    pub tx: u64,
    pub rx: u64,
    pub tx_rate: u64,
    pub rx_rate: u64,
    pub active: u32,
    pub allowed: u64,
    pub denied: u64,
    pub last_seen: u64,
    pub last_action: Option<Action>,
}

/// Every server at one location, rolled up.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
#[serde(default)]
pub struct MapPlace {
    pub lat: f64,
    pub lon: f64,
    pub cc: String,
    pub country: String,
    pub city: String,
    /// Distinct network owners here, busiest first.
    pub orgs: Vec<String>,
    /// Distinct apps here, busiest first.
    pub apps: Vec<String>,
    pub tx: u64,
    pub rx: u64,
    pub tx_rate: u64,
    pub rx_rate: u64,
    pub active: u32,
    pub allowed: u64,
    pub denied: u64,
    pub last_seen: u64,
    /// Busiest first, capped; `more` counts the rest.
    pub servers: Vec<MapServer>,
    pub more: usize,
}

impl MapPlace {
    pub fn place(&self) -> String {
        GeoInfo {
            cc: self.cc.clone(),
            country: self.country.clone(),
            city: self.city.clone(),
            ..Default::default()
        }
        .place()
    }

    /// Something here is transferring data or holds an open connection.
    pub fn live(&self) -> bool {
        self.active > 0 || self.tx_rate + self.rx_rate > 0
    }

    /// Everything here was blocked.
    pub fn blocked(&self) -> bool {
        self.allowed == 0 && self.denied > 0
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
#[serde(default)]
pub struct MapView {
    pub home: Option<Home>,
    pub geo: GeoStatus,
    /// Busiest first.
    pub places: Vec<MapPlace>,
    /// Servers on the local network (they have no place on a world map).
    pub local: usize,
    /// Public servers the database could not place.
    pub unlocated: usize,
}
