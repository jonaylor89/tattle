//! Scriptable command-line interface.

use crate::client::{self, Client};
use crate::model::*;
use crate::proto::{Event, Request};
use anyhow::{Result, anyhow, bail};
use clap::{Args, Subcommand};

#[derive(Args)]
pub struct RuleArgs {
    /// Executable path, or "*" for any process. A bare name is looked up in PATH.
    pub process: String,
    /// Server: any | local | host.name | *.domain | 1.2.3.0/24
    #[arg(default_value = "any")]
    pub remote: String,
    /// Port or range (e.g. 443, 8000-8100)
    #[arg(short, long)]
    pub port: Option<String>,
    /// tcp | udp
    #[arg(long)]
    pub proto: Option<String>,
    /// Only while this profile is active
    #[arg(long)]
    pub profile: Option<String>,
    /// Expire after a duration: 30m, 2h, 1d
    #[arg(long = "for")]
    pub duration: Option<String>,
    /// Inbound rule (connections to a local service)
    #[arg(long)]
    pub inbound: bool,
    /// Only for this user id
    #[arg(long)]
    pub uid: Option<u32>,
    #[arg(long, default_value = "")]
    pub note: String,
}

#[derive(Subcommand)]
pub enum BlocklistCmd {
    /// List subscriptions
    List,
    /// Subscribe to a list (hosts, domains or ||adblock^ format, https only)
    Add { name: String, url: String },
    /// Subscribe to a well-known list by number (see `presets`)
    Preset { number: usize },
    /// Show well-known lists
    Presets,
    /// Unsubscribe
    Rm { name: String },
    /// Re-download every list now
    Refresh,
}

pub fn parse_duration(s: &str) -> Result<u64> {
    let s = s.trim();
    let (num, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len()));
    let n: u64 = num.parse().map_err(|_| anyhow!("invalid duration '{s}'"))?;
    Ok(match unit {
        "" | "s" => n,
        "m" => n * 60,
        "h" => n * 3600,
        "d" => n * 86400,
        _ => bail!("invalid duration unit in '{s}' (use s, m, h, d)"),
    })
}

fn resolve_process(p: &str) -> Result<String> {
    if p == "*" || p == "any" {
        return Ok(ANY_PROCESS.into());
    }
    if p == KERNEL_IDENTITY || p.starts_with('/') {
        return Ok(p.to_string());
    }
    let path = std::env::var_os("PATH").unwrap_or_default();
    for dir in std::env::split_paths(&path) {
        let cand = dir.join(p);
        if cand.is_file() {
            let real = std::fs::canonicalize(&cand).unwrap_or(cand);
            return Ok(real.to_string_lossy().into_owned());
        }
    }
    bail!("'{p}' is not an absolute path and was not found in PATH")
}

#[derive(Subcommand, Clone)]
pub enum GeoCmd {
    /// Show the location database and where the map puts you
    Status,
    /// Download DB-IP City Lite (free, CC BY 4.0; about 60 MB) and keep it current
    Update,
    /// Look up where an address is (offline, in the local database)
    Locate { ip: std::net::IpAddr },
    /// Set where the map puts you: LAT,LON — or "auto" for your time zone's city
    Home {
        #[arg(allow_hyphen_values = true)]
        at: String,
    },
}

pub fn geo(cmd: GeoCmd) -> Result<()> {
    let mut c = Client::connect()?;
    let view = |c: &mut Client| -> Result<MapView> {
        c.get(Request::Map {
            since: Some(0),
            limit: Some(0),
        })
    };
    match cmd {
        GeoCmd::Status => {
            let m = view(&mut c)?;
            let s: Status = c.get(Request::Status)?;
            match m.geo.state {
                GeoState::Ready => {
                    println!(
                        "location data  {}",
                        m.geo.source.as_deref().unwrap_or("ready")
                    );
                    println!(
                        "               {}{}",
                        m.geo.path.as_deref().unwrap_or(""),
                        if m.geo.has_asn {
                            "  (+ network owners)"
                        } else {
                            ""
                        }
                    );
                }
                GeoState::Downloading => println!("location data  downloading…"),
                GeoState::Missing => {
                    println!("location data  not installed");
                    println!(
                        "               tattle geo update   fetches DB-IP City Lite (about 60 MB, CC BY 4.0)"
                    );
                    println!(
                        "               Lookups happen on this machine; nothing about your traffic is sent anywhere."
                    );
                }
            }
            if let Some(e) = &m.geo.error {
                println!("               last download failed: {e}");
            }
            match &m.home {
                Some(h) => println!("you are        {:.2}, {:.2}  ({})", h.lat, h.lon, h.label),
                None => println!(
                    "you are        unknown (time zone has no city): tattle geo home LAT,LON"
                ),
            }
            if m.geo.state == GeoState::Ready {
                println!(
                    "auto-update    {}",
                    if s.settings.geo_auto_update {
                        "monthly"
                    } else {
                        "off"
                    }
                );
            }
        }
        GeoCmd::Locate { ip } => {
            let g: Option<GeoInfo> = c.get(Request::Locate { ip })?;
            match g {
                Some(g) => {
                    println!("{}  ({:.2}, {:.2})", g.place(), g.lat, g.lon);
                    if let Some(org) = g.org {
                        println!(
                            "{org}{}",
                            g.asn.map(|a| format!("  (AS{a})")).unwrap_or_default()
                        );
                    }
                }
                None if is_local_ip(ip) => println!("{ip} is on the local network"),
                None if view(&mut c)?.geo.state != GeoState::Ready => {
                    bail!("no location data yet; run: tattle geo update")
                }
                None => println!("{ip} is not in the location database"),
            }
        }
        GeoCmd::Update => {
            c.call(Request::GeoUpdate)?;
            eprint!("downloading the location database from db-ip.com ");
            let started = std::time::Instant::now();
            loop {
                std::thread::sleep(std::time::Duration::from_secs(1));
                let m = view(&mut c)?;
                if m.geo.state != GeoState::Downloading {
                    eprintln!();
                    if let Some(e) = m.geo.error {
                        bail!("download failed: {e}");
                    }
                    println!("ready: {}", m.geo.source.unwrap_or_default());
                    break;
                }
                if started.elapsed().as_secs() > 1200 {
                    eprintln!();
                    bail!("still downloading after 20 minutes; check `journalctl -u tattle`");
                }
                eprint!(".");
            }
        }
        GeoCmd::Home { at } => {
            let mut s: Status = c.get(Request::Status)?;
            s.settings.home = if at == "auto" {
                None
            } else {
                Some(Coord::parse(&at).map_err(|e| anyhow!(e))?)
            };
            c.call(Request::SetSettings {
                settings: s.settings,
            })?;
            let m = view(&mut c)?;
            match m.home {
                Some(h) => println!(
                    "the map puts you at {:.2}, {:.2} ({})",
                    h.lat, h.lon, h.label
                ),
                None => {
                    println!("your time zone has no city; set one with: tattle geo home LAT,LON")
                }
            }
        }
    }
    Ok(())
}

pub fn map(json: bool, minutes: Option<u64>) -> Result<()> {
    let m: MapView = Client::connect()?.get(Request::Map {
        since: minutes.map(|m| m * 60),
        limit: Some(if json { 60 } else { 0 }),
    })?;
    if json {
        println!("{}", serde_json::to_string_pretty(&m)?);
        return Ok(());
    }
    if m.geo.state != GeoState::Ready {
        bail!("no location data yet; run: tattle geo update");
    }
    let home = m.home.as_ref().map(|h| Coord {
        lat: h.lat,
        lon: h.lon,
    });
    println!(
        "{:<2} {:<26} {:>8} {:>10} {:>10} {:>5}  APPS",
        "", "PLACE", "DISTANCE", "SENT", "RECEIVED", "LIVE"
    );
    for p in &m.places {
        let dist = home
            .map(|h| {
                format!(
                    "{:.0} km",
                    h.distance_km(Coord {
                        lat: p.lat,
                        lon: p.lon
                    })
                )
            })
            .unwrap_or_default();
        let mut place = p.place();
        if place.chars().count() > 26 {
            place = place.chars().take(25).collect::<String>() + "…";
        }
        println!(
            "{:<2} {:<26} {:>8} {:>10} {:>10} {:>5}  {}",
            p.cc,
            place,
            dist,
            human_bytes(p.tx),
            human_bytes(p.rx),
            p.active,
            p.apps.join(", ")
        );
    }
    if m.local + m.unlocated > 0 {
        println!(
            "\n{} on the local network, {} not in the database",
            m.local, m.unlocated
        );
    }
    if let Some(src) = m.geo.source {
        println!("{src}");
    }
    Ok(())
}

pub fn status(json: bool) -> Result<()> {
    let mut c = Client::connect()?;
    let s: Status = c.get(Request::Status)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&s)?);
        return Ok(());
    }
    let state = if s.settings.enabled { "on" } else { "OFF" };
    println!(
        "tattle {}  ·  filtering {state}  ·  mode {}",
        s.version,
        s.settings.mode.label()
    );
    println!(
        "profile      {}",
        s.settings.active_profile.as_deref().unwrap_or("none")
    );
    println!("rules        {}", s.rules);
    println!(
        "alerts       {} waiting, {} alert UI(s) connected",
        s.pending, s.ui_clients
    );
    println!("connections  {} allowed, {} denied", s.allowed, s.denied);
    println!(
        "traffic      ↑ {}/s  ↓ {}/s   (total ↑ {} ↓ {})",
        human_bytes(s.tx_rate),
        human_bytes(s.rx_rate),
        human_bytes(s.tx_total),
        human_bytes(s.rx_total)
    );
    println!("blocklists   {} domains", s.blocked_domains);
    println!("dns cache    {} addresses", s.dns_cache);
    println!(
        "inbound      {}",
        if s.inbound_active {
            "filtered"
        } else {
            "not filtered"
        }
    );
    Ok(())
}

pub fn mode(m: &str) -> Result<()> {
    let mode: Mode = m.parse().map_err(|e: String| anyhow!(e))?;
    Client::connect()?.call(Request::SetMode { mode })?;
    println!("mode: {}", mode.label());
    Ok(())
}

pub fn enabled(on: bool) -> Result<()> {
    Client::connect()?.call(Request::SetEnabled { enabled: on })?;
    println!("filtering {}", if on { "on" } else { "off" });
    Ok(())
}

fn lifetime_label(l: &Lifetime) -> String {
    match l {
        Lifetime::Forever => String::new(),
        Lifetime::UntilQuit { pid, .. } => format!(" (until pid {pid} quits)"),
        Lifetime::Until { at } => format!(
            " (for {})",
            ago(at.saturating_sub(now())).replace(" ago", "")
        ),
    }
}

pub fn ago(secs: u64) -> String {
    match secs {
        0..=59 => format!("{secs}s ago"),
        60..=3599 => format!("{}m ago", secs / 60),
        3600..=86399 => format!("{}h ago", secs / 3600),
        _ => format!("{}d ago", secs / 86400),
    }
}

pub fn rules(json: bool) -> Result<()> {
    let rules: Vec<Rule> = Client::connect()?.get(Request::Rules)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&rules)?);
        return Ok(());
    }
    for r in rules {
        let flags = format!(
            "{}{}",
            if r.enabled { "" } else { " [off]" },
            r.profile
                .as_ref()
                .map(|p| format!(" [{p}]"))
                .unwrap_or_default()
        );
        println!(
            "{:>4}  {}{}{}  · {} hits",
            r.id,
            r.summary(),
            lifetime_label(&r.lifetime),
            flags,
            r.hits
        );
    }
    Ok(())
}

pub fn build_rule(action: Action, a: &RuleArgs) -> Result<Rule> {
    let mut r = Rule::new(
        action,
        resolve_process(&a.process)?,
        Remote::parse(&a.remote).map_err(|e| anyhow!(e))?,
    );
    r.port = match &a.port {
        Some(p) => PortRange::parse(p).map_err(|e| anyhow!(e))?,
        None => None,
    };
    r.proto = match a.proto.as_deref() {
        None | Some("any") => Proto::Any,
        Some("tcp") => Proto::Tcp,
        Some("udp") => Proto::Udp,
        Some(p) => bail!("unknown protocol '{p}'"),
    };
    r.profile = a.profile.clone();
    r.uid = a.uid;
    r.note = a.note.clone();
    if a.inbound {
        r.direction = Direction::In;
    }
    if let Some(d) = &a.duration {
        r.lifetime = Lifetime::Until {
            at: now() + parse_duration(d)?,
        };
    }
    Ok(r)
}

pub fn add_rule(action: Action, a: RuleArgs) -> Result<()> {
    let r = build_rule(action, &a)?;
    let summary = r.summary();
    let v = Client::connect()?.call(Request::AddRule { rule: r })?;
    println!("rule {} added: {summary}", v["id"]);
    Ok(())
}

pub fn remove(ids: Vec<u64>) -> Result<()> {
    let mut c = Client::connect()?;
    for id in ids {
        c.call(Request::DeleteRule { rule_id: id })?;
        println!("rule {id} deleted");
    }
    Ok(())
}

pub fn set_enabled(id: u64, enabled: bool) -> Result<()> {
    Client::connect()?.call(Request::SetRuleEnabled {
        rule_id: id,
        enabled,
    })?;
    Ok(())
}

pub fn profile(name: Option<String>) -> Result<()> {
    let mut c = Client::connect()?;
    match name {
        None => {
            let s: Status = c.get(Request::Status)?;
            for p in &s.settings.profiles {
                let mark = if s.settings.active_profile.as_ref() == Some(p) {
                    "●"
                } else {
                    "○"
                };
                println!("{mark} {p}");
            }
            if s.settings.active_profile.is_none() {
                println!("(no profile active)");
            }
        }
        Some(n) => {
            let profile = if n == "none" { None } else { Some(n.clone()) };
            c.call(Request::SetProfile { profile })?;
            println!("profile: {n}");
        }
    }
    Ok(())
}

pub fn blocklist(cmd: BlocklistCmd) -> Result<()> {
    let mut c = Client::connect()?;
    match cmd {
        BlocklistCmd::List => {
            let s: Status = c.get(Request::Status)?;
            if s.settings.blocklists.is_empty() {
                println!("no blocklists. Try: tattle blocklist presets");
            }
            for b in s.settings.blocklists {
                let when = b
                    .updated
                    .map(|u| ago(now().saturating_sub(u)))
                    .unwrap_or_else(|| "never".into());
                println!(
                    "{} {}  {} domains, updated {when}{}\n    {}",
                    if b.enabled { "●" } else { "○" },
                    b.name,
                    b.entries,
                    b.error.map(|e| format!("  ⚠ {e}")).unwrap_or_default(),
                    b.url
                );
            }
        }
        BlocklistCmd::Presets => {
            for (i, (name, url)) in crate::daemon::blocklist::PRESETS.iter().enumerate() {
                println!("{}  {name}\n   {url}", i + 1);
            }
        }
        BlocklistCmd::Preset { number } => {
            let (name, url) = crate::daemon::blocklist::PRESETS
                .get(number.wrapping_sub(1))
                .ok_or_else(|| anyhow!("no preset {number}"))?;
            c.call(Request::AddBlocklist {
                name: name.to_string(),
                url: url.to_string(),
            })?;
            println!("subscribed to {name}; downloading in the background");
        }
        BlocklistCmd::Add { name, url } => {
            c.call(Request::AddBlocklist {
                name: name.clone(),
                url,
            })?;
            println!("subscribed to {name}; downloading in the background");
        }
        BlocklistCmd::Rm { name } => {
            c.call(Request::RemoveBlocklist { name })?;
        }
        BlocklistCmd::Refresh => {
            c.call(Request::RefreshBlocklists)?;
            println!("refreshing in the background");
        }
    }
    Ok(())
}

// musl's time_t alias is flagged as changing to 64-bit; localtime_r wants
// whatever the platform defines, so that is what we hand it.
#[allow(deprecated)]
pub fn local_time(ts: u64, with_date: bool) -> String {
    let t = ts as libc::time_t;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { libc::localtime_r(&t, &mut tm) };
    if with_date {
        format!(
            "{:02}-{:02} {:02}:{:02}",
            tm.tm_mon + 1,
            tm.tm_mday,
            tm.tm_hour,
            tm.tm_min
        )
    } else {
        format!("{:02}:{:02}:{:02}", tm.tm_hour, tm.tm_min, tm.tm_sec)
    }
}

fn event_line(e: &ConnEvent, color: bool) -> String {
    let paint = |code: &str, s: &str| {
        if color {
            format!("\x1b[{code}m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    };
    let mark = match e.action {
        Action::Allow => paint("32", "✓"),
        Action::Deny => paint("31", "✗"),
    };
    let reason = match e.reason {
        Reason::Rule => e
            .rule_id
            .map(|r| format!("rule {r}"))
            .unwrap_or_else(|| "rule".into()),
        Reason::Blocklist => "blocklist".into(),
        Reason::Prompt => "you".into(),
        Reason::Mode => "silent mode".into(),
        Reason::NoUi => "no alert UI".into(),
        Reason::Timeout => "timeout".into(),
        Reason::Disabled => "filter off".into(),
        Reason::Own => "tattle".into(),
    };
    let arrow = if e.conn.direction == Direction::Out {
        "→"
    } else {
        "←"
    };
    let port = if e.conn.direction == Direction::Out {
        e.conn.remote_port
    } else {
        e.conn.local_port
    };
    format!(
        "{} {mark} {:<18} {arrow} {}:{} {}  {}",
        local_time(e.ts, false),
        e.conn.process.name(),
        e.conn.host(),
        port,
        e.conn.proto,
        paint("2", &format!("({reason})")),
    )
}

pub fn log(follow: bool, lines: usize, json: bool) -> Result<()> {
    use std::io::IsTerminal;
    let color = std::io::stdout().is_terminal();
    let mut c = Client::connect()?;
    let events: Vec<ConnEvent> = c.get(Request::Log {
        limit: Some(lines),
        denied: false,
    })?;
    for e in &events {
        if json {
            println!("{}", serde_json::to_string(e)?);
        } else {
            println!("{}", event_line(e, color));
        }
    }
    if follow {
        let rx = client::subscribe(false, false, true)?;
        while let Ok(Some(ev)) = rx.recv() {
            if let Event::Connection(e) = ev {
                if json {
                    println!("{}", serde_json::to_string(&e)?);
                } else {
                    println!("{}", event_line(&e, color));
                }
            }
        }
        bail!("daemon disconnected");
    }
    Ok(())
}

pub fn apps(json: bool) -> Result<()> {
    let apps: Vec<AppStats> = Client::connect()?.get(Request::Apps)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&apps)?);
        return Ok(());
    }
    println!(
        "{:<24} {:>8} {:>8} {:>10} {:>10} {:>6}",
        "APP", "ALLOWED", "DENIED", "SENT", "RECEIVED", "LIVE"
    );
    for a in apps {
        println!(
            "{:<24} {:>8} {:>8} {:>10} {:>10} {:>6}",
            a.name,
            a.allowed,
            a.denied,
            human_bytes(a.tx),
            human_bytes(a.rx),
            a.active
        );
    }
    Ok(())
}

pub fn export() -> Result<()> {
    let rules: Vec<Rule> = Client::connect()?.get(Request::Rules)?;
    let mine: Vec<&Rule> = rules
        .iter()
        .filter(|r| r.source == RuleSource::User)
        .collect();
    println!("{}", serde_json::to_string_pretty(&mine)?);
    Ok(())
}

pub fn import(file: &std::path::Path) -> Result<()> {
    let text = std::fs::read_to_string(file)?;
    let rules: Vec<Rule> = serde_json::from_str(&text)?;
    let mut c = Client::connect()?;
    let existing: Vec<Rule> = c.get(Request::Rules)?;
    let same = |a: &Rule, b: &Rule| {
        a.action == b.action
            && a.process == b.process
            && a.remote == b.remote
            && a.port == b.port
            && a.proto == b.proto
            && a.direction == b.direction
            && a.profile == b.profile
    };
    let (mut added, mut skipped) = (0, 0);
    for r in rules {
        if existing.iter().any(|e| same(e, &r)) {
            skipped += 1;
            continue;
        }
        c.call(Request::AddRule { rule: r })?;
        added += 1;
    }
    println!("imported {added} rules ({skipped} already present)");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn durations() {
        assert_eq!(parse_duration("90").unwrap(), 90);
        assert_eq!(parse_duration("30m").unwrap(), 1800);
        assert_eq!(parse_duration("2h").unwrap(), 7200);
        assert_eq!(parse_duration("1d").unwrap(), 86400);
        assert!(parse_duration("x").is_err());
        assert!(parse_duration("5y").is_err());
    }
}
