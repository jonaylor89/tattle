//! Daemon state and policy. Every thread shares one `Core` behind a mutex;
//! nothing slow (process lookups, downloads, disk scans) happens while the
//! lock is held.

use super::conntrack::{Flow, FlowKey};
use super::dns::DnsCache;
use super::geo::Geo;
use crate::model::*;
use crate::proto::{AppRate, Event};
use crate::rules::{self, BlockSet};
use anyhow::{Context, Result, anyhow, bail};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::mpsc::{Sender, SyncSender, TrySendError};

pub const LOG_CAP: usize = 5000;
const MAX_APPS: usize = 2000;
const MAX_REMOTES: usize = 400;
const MAX_FLOWS: usize = 200_000;
const MAX_PROMPTS: usize = 256;

pub enum QueueCmd {
    Resolve { prompt_id: u64, action: Action },
    Shutdown,
}

/// Lets other threads poke the packet thread out of `poll`.
#[derive(Clone)]
pub struct Waker {
    pub tx: Sender<QueueCmd>,
    pub fd: i32,
}

impl Waker {
    pub fn send(&self, cmd: QueueCmd) {
        let _ = self.tx.send(cmd);
        let b = [1u8];
        unsafe { libc::write(self.fd, b.as_ptr() as *const libc::c_void, 1) };
    }
}

pub struct Client {
    pub id: u64,
    pub tx: SyncSender<String>,
    pub subscribed: bool,
    pub alerts: bool,
    pub traffic: bool,
    pub connections: bool,
}

pub enum Outcome {
    Verdict(Action),
    Hold(u64),
}

struct FlowInfo {
    identity: String,
    remote_key: String,
    last_orig: u64,
    last_reply: u64,
    /// Bytes sent by us are in the original direction for outbound flows.
    outbound: bool,
}

struct App {
    stats: AppStats,
    remotes: HashMap<String, RemoteStats>,
    tick_tx: u64,
    tick_rx: u64,
}

pub struct Core {
    pub settings: Settings,
    pub rules: Vec<Rule>,
    next_rule_id: u64,
    pub blocks: BlockSet,
    pub dns: DnsCache,
    prompts: BTreeMap<u64, Prompt>,
    next_prompt_id: u64,
    log: VecDeque<ConnEvent>,
    apps: HashMap<String, App>,
    flows: HashMap<FlowKey, FlowInfo>,
    /// Flows we tried and failed to attribute; not retried.
    unattributable: HashSet<FlowKey>,
    pub clients: Vec<Client>,
    next_client_id: u64,
    pub waker: Waker,
    pub state_dir: PathBuf,
    pub started: u64,
    pub own_pid: u32,
    allowed: u64,
    denied: u64,
    tx_rate: u64,
    rx_rate: u64,
    tx_total: u64,
    rx_total: u64,
    pub inbound_active: bool,
    pub blocklist_refreshing: bool,
    pub geo: Geo,
}

fn flow_key(conn: &Connection) -> FlowKey {
    let local = canonical_ip(conn.local_ip);
    let remote = canonical_ip(conn.remote_ip);
    let proto = match conn.proto {
        Proto::Tcp => 6,
        Proto::Udp => 17,
        Proto::Any => 0,
    };
    match conn.direction {
        Direction::Out => FlowKey {
            proto,
            src: local,
            sport: conn.local_port,
            dst: remote,
            dport: conn.remote_port,
        },
        Direction::In => FlowKey {
            proto,
            src: remote,
            sport: conn.remote_port,
            dst: local,
            dport: conn.local_port,
        },
    }
}

fn canonical_key(k: FlowKey) -> FlowKey {
    FlowKey {
        src: canonical_ip(k.src),
        dst: canonical_ip(k.dst),
        ..k
    }
}

fn remote_key(conn: &Connection) -> String {
    conn.hostnames
        .first()
        .cloned()
        .unwrap_or_else(|| canonical_ip(conn.remote_ip).to_string())
}

fn validate_rule(r: &Rule) -> Result<()> {
    if r.process.is_empty() || r.process.len() > 4096 {
        bail!("process must be '*' or an executable path");
    }
    if !(r.process == ANY_PROCESS
        || r.process == KERNEL_IDENTITY
        || r.process.starts_with('/')
        || r.process.starts_with('['))
    {
        bail!("process must be '*', 'kernel', or an absolute executable path");
    }
    match &r.remote {
        Remote::Ip(n) => {
            n.parse::<IpNet>().map_err(|e| anyhow!(e))?;
        }
        Remote::Host(h) | Remote::Domain(h) => {
            valid_hostname(h).map_err(|e| anyhow!(e))?;
        }
        _ => {}
    }
    if let Some(p) = r.port
        && p.lo > p.hi
    {
        bail!("port range is reversed");
    }
    if r.note.len() > 1000 {
        bail!("note too long");
    }
    Ok(())
}

fn normalize_rule(r: &mut Rule) {
    match &mut r.remote {
        Remote::Host(h) | Remote::Domain(h) => {
            if let Ok(v) = valid_hostname(h) {
                *h = v
            }
        }
        Remote::Ip(n) => {
            if let Ok(v) = n.parse::<IpNet>() {
                *n = v.to_string()
            }
        }
        _ => {}
    }
}

impl Core {
    pub fn new(state_dir: PathBuf, waker: Waker) -> Result<Core> {
        let mut core = Core {
            settings: Settings::default(),
            rules: Vec::new(),
            next_rule_id: 1,
            blocks: BlockSet::new(),
            dns: DnsCache::new(100_000),
            prompts: BTreeMap::new(),
            next_prompt_id: 1,
            log: VecDeque::new(),
            apps: HashMap::new(),
            flows: HashMap::new(),
            unattributable: HashSet::new(),
            clients: Vec::new(),
            next_client_id: 1,
            waker,
            started: now(),
            own_pid: std::process::id(),
            allowed: 0,
            denied: 0,
            tx_rate: 0,
            rx_rate: 0,
            tx_total: 0,
            rx_total: 0,
            inbound_active: false,
            blocklist_refreshing: false,
            geo: Geo::new(&state_dir),
            state_dir,
        };
        core.load()?;
        Ok(core)
    }

    // ------------------------------------------------------------ storage

    /// Read saved settings and rules. A missing file means a fresh install
    /// and gets defaults; a file that exists but cannot be parsed is moved
    /// aside first, so nothing the operator wrote is ever overwritten. Any
    /// other read error (permissions, I/O) stops startup rather than
    /// replacing the operator's policy with defaults.
    fn load(&mut self) -> Result<()> {
        std::fs::create_dir_all(&self.state_dir)
            .with_context(|| format!("creating {}", self.state_dir.display()))?;
        let mut dirty = false;

        match self.read_state::<Settings>("settings.json")? {
            Some(v) => self.settings = v,
            None => dirty = true,
        }
        match self.read_state::<Vec<Rule>>("rules.json")? {
            Some(v) => self.rules = v,
            None => {
                self.rules = rules::default_rules();
                dirty = true;
            }
        }

        let mut seen = HashSet::new();
        for r in &mut self.rules {
            if r.id == 0 || !seen.insert(r.id) {
                r.id = 0;
                dirty = true;
            }
        }
        let mut next = self.rules.iter().map(|r| r.id).max().unwrap_or(0) + 1;
        for r in &mut self.rules {
            if r.id == 0 {
                r.id = next;
                seen.insert(next);
                next += 1;
            }
        }
        self.next_rule_id = next;
        if dirty {
            self.save_settings()?;
            self.save_rules()?;
        }
        Ok(())
    }

    /// `Ok(None)` when the file is absent, or was unparseable and has been
    /// moved aside to `<name>.broken-<time>`.
    fn read_state<T: serde::de::DeserializeOwned>(&self, name: &str) -> Result<Option<T>> {
        let path = self.state_dir.join(name);
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => bail!(
                "cannot read {}: {e}; refusing to start with default policy",
                path.display()
            ),
        };
        match serde_json::from_str(&text) {
            Ok(v) => Ok(Some(v)),
            Err(e) => {
                let aside = path.with_extension(format!("json.broken-{}", now()));
                std::fs::rename(&path, &aside).with_context(|| {
                    format!(
                        "{} is unreadable ({e}) and could not be moved aside",
                        path.display()
                    )
                })?;
                log::warn(&format!(
                    "{} unreadable ({e}); moved to {}, starting from defaults",
                    path.display(),
                    aside.display()
                ));
                Ok(None)
            }
        }
    }

    /// Write `data` to a temp file, flush it to disk, then rename it over
    /// `name`, so a crash leaves either the old file or the new one.
    fn write_atomic(&self, name: &str, data: &str) -> Result<()> {
        use std::io::Write;
        let path = self.state_dir.join(name);
        let tmp = self.state_dir.join(format!(".{name}.tmp"));
        let res = (|| -> std::io::Result<()> {
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(data.as_bytes())?;
            f.sync_all()?;
            std::fs::rename(&tmp, &path)?;
            std::fs::File::open(&self.state_dir)?.sync_all()
        })();
        if let Err(e) = res {
            let _ = std::fs::remove_file(&tmp);
            log::warn(&format!("could not save {}: {e}", path.display()));
            bail!("could not save {}: {e}", path.display());
        }
        Ok(())
    }

    pub fn save_rules(&self) -> Result<()> {
        self.write_atomic("rules.json", &serde_json::to_string_pretty(&self.rules)?)
    }

    pub fn save_settings(&self) -> Result<()> {
        self.write_atomic(
            "settings.json",
            &serde_json::to_string_pretty(&self.settings)?,
        )
    }

    // ------------------------------------------------------------ clients

    pub fn add_client(&mut self, tx: SyncSender<String>) -> u64 {
        let id = self.next_client_id;
        self.next_client_id += 1;
        self.clients.push(Client {
            id,
            tx,
            subscribed: false,
            alerts: false,
            traffic: false,
            connections: false,
        });
        id
    }

    pub fn remove_client(&mut self, id: u64) {
        self.clients.retain(|c| c.id != id);
        self.after_alert_clients_changed();
    }

    pub fn alert_clients(&self) -> usize {
        self.clients.iter().filter(|c| c.alerts).count()
    }

    /// With nobody left to answer, waiting alerts are settled right away
    /// instead of stalling apps until the timeout.
    pub fn after_alert_clients_changed(&mut self) {
        if self.alert_clients() == 0 && !self.prompts.is_empty() {
            let action = self.settings.no_ui_action;
            let ids: Vec<u64> = self.prompts.keys().copied().collect();
            for id in ids {
                self.resolve_prompt(id, action, Reason::NoUi, None);
            }
        }
    }

    pub fn subscribe(&mut self, id: u64, alerts: bool, traffic: bool, connections: bool) {
        let pending: Vec<Prompt> = self.prompts.values().cloned().collect();
        let status = self.status();
        if let Some(c) = self.clients.iter_mut().find(|c| c.id == id) {
            c.subscribed = true;
            c.alerts = alerts;
            c.traffic = traffic;
            c.connections = connections;
            let _ = c.tx.try_send(event_line(&Event::Status(status)));
            if alerts {
                for p in pending {
                    let _ = c.tx.try_send(event_line(&Event::Prompt(p)));
                }
            }
        }
    }

    pub fn broadcast(&mut self, ev: &Event) {
        let line = event_line(ev);
        let mut dead = Vec::new();
        for c in &self.clients {
            if !c.subscribed {
                continue;
            }
            let wants = match ev {
                Event::Prompt(_) | Event::PromptResolved { .. } => true,
                Event::Traffic { .. } => c.traffic,
                Event::Connection(_) => c.connections,
                Event::Status(_) | Event::RulesChanged => true,
            };
            if !wants {
                continue;
            }
            match c.tx.try_send(line.clone()) {
                Ok(()) => {}
                // A client that stopped reading is dropped rather than
                // allowed to grow the daemon's memory.
                Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => dead.push(c.id),
            }
        }
        if !dead.is_empty() {
            self.clients.retain(|c| !dead.contains(&c.id));
            self.after_alert_clients_changed();
        }
    }

    pub fn broadcast_status(&mut self) {
        let s = self.status();
        self.broadcast(&Event::Status(s));
    }

    // ------------------------------------------------------------ policy

    /// Decide what to do with a brand-new connection.
    pub fn decide_new(&mut self, conn: Connection) -> Outcome {
        let now = now();
        if conn.process.pid != 0
            && (conn.process.pid == self.own_pid || conn.process.ppid == self.own_pid)
        {
            self.record(&conn, Action::Allow, Reason::Own, None, 1);
            return Outcome::Verdict(Action::Allow);
        }
        if !self.settings.enabled {
            self.record(&conn, Action::Allow, Reason::Disabled, None, 1);
            return Outcome::Verdict(Action::Allow);
        }
        let profile = self.settings.active_profile.clone();
        if let Some(m) = rules::evaluate(&self.rules, &self.blocks, &conn, profile.as_deref(), now)
        {
            if let Some(id) = m.rule_id
                && let Some(r) = self.rules.iter_mut().find(|r| r.id == id)
            {
                r.hits += 1;
                r.last_hit = Some(now);
            }
            let reason = if m.blocklist.is_some() {
                Reason::Blocklist
            } else {
                Reason::Rule
            };
            self.record(&conn, m.action, reason, m.rule_id, 1);
            return Outcome::Verdict(m.action);
        }
        match self.settings.mode {
            Mode::SilentAllow => {
                self.record(&conn, Action::Allow, Reason::Mode, None, 1);
                Outcome::Verdict(Action::Allow)
            }
            Mode::SilentDeny => {
                self.record(&conn, Action::Deny, Reason::Mode, None, 1);
                Outcome::Verdict(Action::Deny)
            }
            Mode::Alert => {
                if self.alert_clients() == 0 {
                    let a = self.settings.no_ui_action;
                    self.record(&conn, a, Reason::NoUi, None, 1);
                    return Outcome::Verdict(a);
                }
                // Group bursts (retransmits, parallel requests) into one alert.
                let key_host = remote_key(&conn);
                if let Some(p) = self.prompts.values_mut().find(|p| {
                    p.conn.identity() == conn.identity()
                        && p.conn.direction == conn.direction
                        && p.conn.proto == conn.proto
                        && p.conn.remote_port == conn.remote_port
                        && remote_key(&p.conn) == key_host
                        && (conn.direction == Direction::Out
                            || p.conn.local_port == conn.local_port)
                }) {
                    p.attempts += 1;
                    return Outcome::Hold(p.id);
                }
                if self.prompts.len() >= MAX_PROMPTS {
                    let a = self.settings.timeout_action;
                    self.record(&conn, a, Reason::Timeout, None, 1);
                    return Outcome::Verdict(a);
                }
                let id = self.next_prompt_id;
                self.next_prompt_id += 1;
                let geo = self.geo.lookup(conn.remote_ip);
                let prompt = Prompt {
                    id,
                    geo,
                    domain: conn.hostnames.first().and_then(|h| registrable_domain(h)),
                    service: service_name(
                        conn.proto,
                        match conn.direction {
                            Direction::Out => conn.remote_port,
                            Direction::In => conn.local_port,
                        },
                    )
                    .map(str::to_string),
                    conn,
                    created: now,
                    deadline: now + self.settings.prompt_timeout.clamp(5, 3600),
                    attempts: 1,
                };
                self.prompts.insert(id, prompt.clone());
                self.broadcast(&Event::Prompt(prompt));
                Outcome::Hold(id)
            }
        }
    }

    /// Settle an alert: release held packets, log it, tell every client.
    pub fn resolve_prompt(
        &mut self,
        id: u64,
        action: Action,
        reason: Reason,
        rule_id: Option<u64>,
    ) {
        let Some(p) = self.prompts.remove(&id) else {
            return;
        };
        self.waker.send(QueueCmd::Resolve {
            prompt_id: id,
            action,
        });
        self.record(&p.conn, action, reason, rule_id, p.attempts as u64);
        self.broadcast(&Event::PromptResolved { id, action });
    }

    pub fn decide_prompt(&mut self, id: u64, d: Decision) -> Result<Option<u64>> {
        let p = self
            .prompts
            .get(&id)
            .cloned()
            .ok_or_else(|| anyhow!("alert {id} is no longer waiting"))?;
        let profile = self.settings.active_profile.clone();
        let mut new_rule = None;
        if let Some(mut rule) = rules::rule_from_decision(&p, &d, profile.as_deref(), now()) {
            rule.hits = p.attempts as u64;
            rule.last_hit = Some(now());
            rule.id = self.next_rule_id;
            self.next_rule_id += 1;
            new_rule = Some(rule.id);
            self.rules.push(rule);
            if let Err(e) = self.save_rules() {
                // Leave the alert waiting so the user can retry or pick
                // a one-off answer; don't pretend the rule exists.
                self.rules.pop();
                return Err(e);
            }
        }
        self.resolve_prompt(id, d.action, Reason::Prompt, new_rule);
        if new_rule.is_some() {
            self.broadcast(&Event::RulesChanged);
            self.reevaluate_prompts();
        }
        Ok(new_rule)
    }

    /// After the rules change, settle any alert they now answer.
    pub fn reevaluate_prompts(&mut self) {
        let profile = self.settings.active_profile.clone();
        let now = now();
        let mut settled = Vec::new();
        for p in self.prompts.values() {
            if let Some(m) =
                rules::evaluate(&self.rules, &self.blocks, &p.conn, profile.as_deref(), now)
            {
                settled.push((p.id, m.action, m.rule_id));
            } else if !self.settings.enabled || self.settings.mode != Mode::Alert {
                let a = if !self.settings.enabled || self.settings.mode == Mode::SilentAllow {
                    Action::Allow
                } else {
                    Action::Deny
                };
                settled.push((p.id, a, None));
            }
        }
        for (id, action, rule_id) in settled {
            let reason = if rule_id.is_some() {
                Reason::Rule
            } else {
                Reason::Mode
            };
            self.resolve_prompt(id, action, reason, rule_id);
        }
    }

    pub fn expire_prompts(&mut self) {
        let now = now();
        let expired: Vec<u64> = self
            .prompts
            .values()
            .filter(|p| p.deadline <= now)
            .map(|p| p.id)
            .collect();
        let a = self.settings.timeout_action;
        for id in expired {
            self.resolve_prompt(id, a, Reason::Timeout, None);
        }
    }

    pub fn pending(&self) -> Vec<Prompt> {
        self.prompts.values().cloned().collect()
    }

    // ------------------------------------------------------------ rules API

    pub fn add_rule(&mut self, mut rule: Rule) -> Result<u64> {
        let prev = self.rules.clone();
        validate_rule(&rule)?;
        normalize_rule(&mut rule);
        rule.id = self.next_rule_id;
        self.next_rule_id += 1;
        if rule.created == 0 {
            rule.created = now();
        }
        rule.hits = 0;
        rule.last_hit = None;
        let id = rule.id;
        self.rules.push(rule);
        self.rules_changed(prev)?;
        Ok(id)
    }

    pub fn update_rule(&mut self, mut rule: Rule) -> Result<()> {
        let prev = self.rules.clone();
        validate_rule(&rule)?;
        normalize_rule(&mut rule);
        let slot = self
            .rules
            .iter_mut()
            .find(|r| r.id == rule.id)
            .ok_or_else(|| anyhow!("no rule {}", rule.id))?;
        rule.hits = slot.hits;
        rule.last_hit = slot.last_hit;
        rule.created = slot.created;
        *slot = rule;
        self.rules_changed(prev)
    }

    pub fn delete_rule(&mut self, id: u64) -> Result<()> {
        let prev = self.rules.clone();
        let before = self.rules.len();
        self.rules.retain(|r| r.id != id);
        if self.rules.len() == before {
            bail!("no rule {id}");
        }
        self.rules_changed(prev)
    }

    pub fn set_rule_enabled(&mut self, id: u64, enabled: bool) -> Result<()> {
        let prev = self.rules.clone();
        let r = self
            .rules
            .iter_mut()
            .find(|r| r.id == id)
            .ok_or_else(|| anyhow!("no rule {id}"))?;
        r.enabled = enabled;
        self.rules_changed(prev)
    }

    pub fn reset_defaults(&mut self) -> Result<()> {
        let prev = self.rules.clone();
        self.rules.retain(|r| r.source != RuleSource::Default);
        for mut r in rules::default_rules() {
            r.id = self.next_rule_id;
            self.next_rule_id += 1;
            self.rules.push(r);
        }
        self.rules_changed(prev)
    }

    /// Persist a rules change. If it cannot be saved, put `prev` back and
    /// report the error, so what the daemon enforces always matches what
    /// survives a restart.
    pub fn rules_changed(&mut self, prev: Vec<Rule>) -> Result<()> {
        if let Err(e) = self.save_rules() {
            self.rules = prev;
            return Err(e);
        }
        self.broadcast(&Event::RulesChanged);
        self.reevaluate_prompts();
        self.broadcast_status();
        Ok(())
    }

    /// Like `rules_changed`, for settings.
    pub fn settings_changed(&mut self, prev: Settings) -> Result<()> {
        if let Err(e) = self.save_settings() {
            self.settings = prev;
            return Err(e);
        }
        self.reevaluate_prompts();
        self.broadcast_status();
        Ok(())
    }

    pub fn set_settings(&mut self, mut s: Settings) -> Result<bool> {
        s.prompt_timeout = s.prompt_timeout.clamp(5, 3600);
        s.profiles.retain(|p| !p.trim().is_empty() && p.len() <= 64);
        s.profiles.dedup();
        if let Some(h) = s.home
            && !(h.lat.is_finite()
                && h.lon.is_finite()
                && h.lat.abs() <= 90.0
                && h.lon.abs() <= 180.0)
        {
            bail!("home must be a latitude within ±90 and a longitude within ±180");
        }
        if let Some(a) = &s.active_profile
            && !s.profiles.contains(a)
        {
            bail!("unknown profile '{a}'");
        }
        // Blocklists are managed through their own requests; keep the
        // daemon's view of their status.
        s.blocklists = self.settings.blocklists.clone();
        let inbound_changed = s.inbound != self.settings.inbound;
        let prev = std::mem::replace(&mut self.settings, s);
        self.settings_changed(prev)?;
        Ok(inbound_changed)
    }

    // ------------------------------------------------------------ logging & stats

    pub fn record(
        &mut self,
        conn: &Connection,
        action: Action,
        reason: Reason,
        rule_id: Option<u64>,
        count: u64,
    ) {
        let now = now();
        let geo = self.geo.lookup(conn.remote_ip);
        match action {
            Action::Allow => self.allowed += count,
            Action::Deny => self.denied += count,
        }
        let ev = ConnEvent {
            ts: now,
            conn: conn.clone(),
            action,
            reason,
            rule_id,
        };
        if self.log.len() >= LOG_CAP {
            self.log.pop_front();
        }
        self.log.push_back(ev.clone());

        let identity = conn.identity();
        if !self.apps.contains_key(&identity)
            && self.apps.len() >= MAX_APPS
            && let Some(old) = self
                .apps
                .iter()
                .min_by_key(|(_, a)| a.stats.last_seen)
                .map(|(k, _)| k.clone())
        {
            self.apps.remove(&old);
        }
        let app = self.apps.entry(identity.clone()).or_insert_with(|| App {
            stats: AppStats {
                identity: identity.clone(),
                name: conn.process.name(),
                ..Default::default()
            },
            remotes: HashMap::new(),
            tick_tx: 0,
            tick_rx: 0,
        });
        app.stats.exe = conn.process.exe.clone();
        app.stats.last_pid = conn.process.pid;
        app.stats.user = conn.process.user.clone();
        app.stats.last_seen = now;
        match action {
            Action::Allow => app.stats.allowed += count,
            Action::Deny => app.stats.denied += count,
        }
        let rk = remote_key(conn);
        if !app.remotes.contains_key(&rk)
            && app.remotes.len() >= MAX_REMOTES
            && let Some(old) = app
                .remotes
                .iter()
                .min_by_key(|(_, r)| r.last_seen)
                .map(|(k, _)| k.clone())
        {
            app.remotes.remove(&old);
        }
        let r = app
            .remotes
            .entry(rk.clone())
            .or_insert_with(|| RemoteStats {
                host: rk.clone(),
                proto: conn.proto,
                ..Default::default()
            });
        r.ip = canonical_ip(conn.remote_ip).to_string();
        if geo.is_some() {
            r.geo = geo;
        }
        let port = if conn.direction == Direction::Out {
            conn.remote_port
        } else {
            conn.local_port
        };
        if !r.ports.contains(&port) && r.ports.len() < 16 {
            r.ports.push(port);
        }
        r.last_seen = now;
        r.last_action = Some(action);
        match action {
            Action::Allow => r.allowed += count,
            Action::Deny => r.denied += count,
        }
        if action == Action::Allow {
            if self.flows.len() >= MAX_FLOWS {
                self.flows.clear();
            }
            self.flows.insert(
                flow_key(conn),
                FlowInfo {
                    identity,
                    remote_key: rk,
                    last_orig: 0,
                    last_reply: 0,
                    outbound: conn.direction == Direction::Out,
                },
            );
        }
        self.broadcast(&Event::Connection(ev));
    }

    /// Flows from conntrack we know nothing about yet (worth attributing).
    pub fn unknown_flows(&self, flows: &[Flow], limit: usize) -> Vec<FlowKey> {
        flows
            .iter()
            .map(|f| canonical_key(f.key))
            .filter(|k| {
                (k.proto == 6 || k.proto == 17)
                    && !self.flows.contains_key(k)
                    && !self.unattributable.contains(k)
            })
            .take(limit)
            .collect()
    }

    /// Register a flow discovered in conntrack (opened before we started).
    pub fn adopt_flow(&mut self, key: FlowKey, conn: Option<Connection>) {
        match conn {
            None => {
                if self.unattributable.len() > 100_000 {
                    self.unattributable.clear();
                }
                self.unattributable.insert(key);
            }
            Some(conn) => {
                let identity = conn.identity();
                let rk = remote_key(&conn);
                let geo = self.geo.lookup(conn.remote_ip);
                let app = self.apps.entry(identity.clone()).or_insert_with(|| App {
                    stats: AppStats {
                        identity: identity.clone(),
                        name: conn.process.name(),
                        ..Default::default()
                    },
                    remotes: HashMap::new(),
                    tick_tx: 0,
                    tick_rx: 0,
                });
                app.stats.exe = conn.process.exe.clone();
                app.stats.user = conn.process.user.clone();
                app.stats.last_pid = conn.process.pid;
                app.remotes
                    .entry(rk.clone())
                    .or_insert_with(|| RemoteStats {
                        host: rk.clone(),
                        ip: canonical_ip(conn.remote_ip).to_string(),
                        proto: conn.proto,
                        ports: vec![if conn.direction == Direction::Out {
                            conn.remote_port
                        } else {
                            conn.local_port
                        }],
                        geo,
                        ..Default::default()
                    });
                self.flows.insert(
                    key,
                    FlowInfo {
                        identity,
                        remote_key: rk,
                        last_orig: 0,
                        last_reply: 0,
                        outbound: conn.direction == Direction::Out,
                    },
                );
            }
        }
    }

    /// Fold a conntrack snapshot into per-app byte counters and rates.
    pub fn apply_flows(&mut self, flows: &[Flow], elapsed: f64) -> Vec<AppRate> {
        let mut live: HashSet<FlowKey> = HashSet::with_capacity(flows.len());
        for a in self.apps.values_mut() {
            a.tick_tx = 0;
            a.tick_rx = 0;
            a.stats.active = 0;
            for r in a.remotes.values_mut() {
                // Until the end of this pass these hold bytes, not rates.
                r.active = 0;
                r.tx_rate = 0;
                r.rx_rate = 0;
            }
        }
        let now = now();
        for f in flows {
            let key = canonical_key(f.key);
            let Some(info) = self.flows.get_mut(&key) else {
                continue;
            };
            live.insert(key);
            let counts_as_open = f.open;
            // Counters only grow; a reset means the entry was recreated.
            let d_orig = f.orig_bytes.saturating_sub(info.last_orig);
            let d_reply = f.reply_bytes.saturating_sub(info.last_reply);
            info.last_orig = f.orig_bytes;
            info.last_reply = f.reply_bytes;
            let (tx, rx) = if info.outbound {
                (d_orig, d_reply)
            } else {
                (d_reply, d_orig)
            };
            if let Some(app) = self.apps.get_mut(&info.identity) {
                if counts_as_open {
                    app.stats.active += 1;
                }
                app.tick_tx += tx;
                app.tick_rx += rx;
                app.stats.tx += tx;
                app.stats.rx += rx;
                if tx + rx > 0 {
                    app.stats.last_seen = now;
                }
                if let Some(r) = app.remotes.get_mut(&info.remote_key) {
                    r.tx += tx;
                    r.rx += rx;
                    r.tx_rate += tx;
                    r.rx_rate += rx;
                    if counts_as_open {
                        r.active += 1;
                    }
                    if tx + rx > 0 {
                        r.last_seen = now;
                    }
                }
            }
        }
        // Forget flows the kernel no longer tracks.
        self.flows.retain(|k, _| live.contains(k));
        self.unattributable
            .retain(|k| flows.iter().any(|f| canonical_key(f.key) == *k));

        let secs = elapsed.max(0.001);
        let (mut ttx, mut trx) = (0u64, 0u64);
        let mut rates = Vec::new();
        for a in self.apps.values_mut() {
            a.stats.tx_rate = (a.tick_tx as f64 / secs) as u64;
            a.stats.rx_rate = (a.tick_rx as f64 / secs) as u64;
            for r in a.remotes.values_mut() {
                r.tx_rate = (r.tx_rate as f64 / secs) as u64;
                r.rx_rate = (r.rx_rate as f64 / secs) as u64;
            }
            ttx += a.tick_tx;
            trx += a.tick_rx;
            if a.stats.active > 0 || a.stats.tx_rate + a.stats.rx_rate > 0 {
                rates.push(AppRate {
                    identity: a.stats.identity.clone(),
                    name: a.stats.name.clone(),
                    tx_rate: a.stats.tx_rate,
                    rx_rate: a.stats.rx_rate,
                    active: a.stats.active,
                });
            }
        }
        self.tx_total += ttx;
        self.rx_total += trx;
        self.tx_rate = (ttx as f64 / secs) as u64;
        self.rx_rate = (trx as f64 / secs) as u64;
        rates.sort_by(|a, b| {
            (b.tx_rate + b.rx_rate)
                .cmp(&(a.tx_rate + a.rx_rate))
                .then(b.active.cmp(&a.active))
        });
        rates.truncate(50);
        rates
    }

    pub fn traffic_event(&self, rates: Vec<AppRate>) -> Event {
        Event::Traffic {
            apps: rates,
            tx_rate: self.tx_rate,
            rx_rate: self.rx_rate,
        }
    }

    pub fn apps(&self) -> Vec<AppStats> {
        let mut v: Vec<AppStats> = self
            .apps
            .values()
            .map(|a| {
                let mut s = a.stats.clone();
                let mut remotes: Vec<RemoteStats> = a.remotes.values().cloned().collect();
                remotes.sort_by_key(|x| std::cmp::Reverse(x.last_seen));
                s.remotes = remotes;
                s
            })
            .collect();
        v.sort_by_key(|a| std::cmp::Reverse(a.last_seen));
        v
    }

    pub fn log_tail(&self, limit: usize, denied_only: bool) -> Vec<ConnEvent> {
        let mut out: Vec<ConnEvent> = self
            .log
            .iter()
            .rev()
            .filter(|e| !denied_only || e.action == Action::Deny)
            .take(limit)
            .cloned()
            .collect();
        out.reverse();
        out
    }

    pub fn reset_stats(&mut self) {
        self.apps.clear();
        self.log.clear();
        self.allowed = 0;
        self.denied = 0;
        self.tx_total = 0;
        self.rx_total = 0;
        self.broadcast_status();
    }

    /// Drop rules whose time is up. Returns process-bound rules for the
    /// caller to check (that needs /proc, done outside the lock).
    pub fn expire_rules(&mut self, dead: &[u64]) -> bool {
        let now = now();
        let before = self.rules.len();
        self.rules.retain(|r| {
            !matches!(r.lifetime, Lifetime::Until { at } if at <= now) && !dead.contains(&r.id)
        });
        if self.rules.len() != before {
            // Expired rules no longer match either way; a failed save only
            // means they are dropped again after a restart.
            let _ = self.save_rules();
            self.broadcast(&Event::RulesChanged);
            return true;
        }
        false
    }

    pub fn process_bound_rules(&self) -> Vec<(u64, u32, u64)> {
        self.rules
            .iter()
            .filter_map(|r| match r.lifetime {
                Lifetime::UntilQuit { pid, start_time } => Some((r.id, pid, start_time)),
                _ => None,
            })
            .collect()
    }

    pub fn status(&self) -> Status {
        Status {
            version: env!("CARGO_PKG_VERSION").to_string(),
            pid: self.own_pid,
            uptime: now().saturating_sub(self.started),
            settings: self.settings.clone(),
            rules: self.rules.len(),
            pending: self.prompts.len(),
            allowed: self.allowed,
            denied: self.denied,
            tx_rate: self.tx_rate,
            rx_rate: self.rx_rate,
            tx_total: self.tx_total,
            rx_total: self.rx_total,
            ui_clients: self.alert_clients(),
            dns_cache: self.dns.len(),
            blocked_domains: self.blocks.len(),
            inbound_active: self.inbound_active,
        }
    }

    /// Place every known server once a location database becomes available.
    pub fn backfill_geo(&mut self) {
        for app in self.apps.values_mut() {
            for r in app.remotes.values_mut() {
                r.geo = r.ip.parse().ok().and_then(|ip| self.geo.lookup(ip));
            }
        }
    }

    /// Servers rolled up by location, for the map. `since`: only servers
    /// seen in the last so many seconds (open connections always count).
    /// `limit`: servers listed per place.
    pub fn map_view(&self, since: Option<u64>, limit: usize) -> MapView {
        let cutoff = since.map(|s| now().saturating_sub(s));
        let mut places: HashMap<(i64, i64), MapPlace> = HashMap::new();
        let (mut local, mut unlocated) = (0, 0);
        for app in self.apps.values() {
            for r in app.remotes.values() {
                if cutoff.is_some_and(|c| r.last_seen < c) && r.active == 0 {
                    continue;
                }
                let Some(g) = &r.geo else {
                    match r.ip.parse::<IpAddr>() {
                        Ok(ip) if is_local_ip(ip) => local += 1,
                        _ => unlocated += 1,
                    }
                    continue;
                };
                // Same city in the database means the same coordinates.
                let key = ((g.lat * 10.0).round() as i64, (g.lon * 10.0).round() as i64);
                let p = places.entry(key).or_insert_with(|| MapPlace {
                    lat: g.lat,
                    lon: g.lon,
                    cc: g.cc.clone(),
                    country: g.country.clone(),
                    city: g.city.clone(),
                    ..Default::default()
                });
                p.tx += r.tx;
                p.rx += r.rx;
                p.tx_rate += r.tx_rate;
                p.rx_rate += r.rx_rate;
                p.active += r.active;
                p.allowed += r.allowed;
                p.denied += r.denied;
                p.last_seen = p.last_seen.max(r.last_seen);
                p.servers.push(MapServer {
                    app: app.stats.name.clone(),
                    identity: app.stats.identity.clone(),
                    host: r.host.clone(),
                    ip: r.ip.clone(),
                    ports: r.ports.clone(),
                    org: g.org.clone(),
                    tx: r.tx,
                    rx: r.rx,
                    tx_rate: r.tx_rate,
                    rx_rate: r.rx_rate,
                    active: r.active,
                    allowed: r.allowed,
                    denied: r.denied,
                    last_seen: r.last_seen,
                    last_action: r.last_action,
                });
            }
        }
        let mut places: Vec<MapPlace> = places.into_values().collect();
        for p in &mut places {
            p.servers.sort_by(|a, b| {
                (b.tx_rate + b.rx_rate)
                    .cmp(&(a.tx_rate + a.rx_rate))
                    .then((b.tx + b.rx).cmp(&(a.tx + a.rx)))
                    .then(b.last_seen.cmp(&a.last_seen))
            });
            let mut seen = HashSet::new();
            p.apps = p
                .servers
                .iter()
                .filter(|s| seen.insert(s.app.clone()))
                .map(|s| s.app.clone())
                .take(8)
                .collect();
            let mut seen = HashSet::new();
            p.orgs = p
                .servers
                .iter()
                .filter_map(|s| s.org.clone())
                .filter(|o| seen.insert(o.clone()))
                .take(4)
                .collect();
            p.more = p.servers.len().saturating_sub(limit);
            p.servers.truncate(limit);
        }
        places.sort_by(|a, b| {
            b.live()
                .cmp(&a.live())
                .then((b.tx + b.rx).cmp(&(a.tx + a.rx)))
                .then(b.last_seen.cmp(&a.last_seen))
        });
        MapView {
            home: self.geo.home(&self.settings),
            geo: self.geo.status(),
            places,
            local,
            unlocated,
        }
    }

    pub fn hostnames_for(&self, ip: IpAddr) -> Vec<String> {
        self.dns.lookup(ip)
    }
}

pub fn event_line(ev: &Event) -> String {
    let mut s = serde_json::to_string(ev).unwrap_or_default();
    s.push('\n');
    s
}

pub mod log {
    pub fn info(msg: &str) {
        eprintln!("<6>tattle: {msg}");
    }
    pub fn warn(msg: &str) {
        eprintln!("<4>tattle: {msg}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn core() -> Core {
        let dir = std::env::temp_dir().join(format!(
            "tattle-core-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let (tx, _rx) = std::sync::mpsc::channel();
        Core::new(dir, Waker { tx, fd: -1 }).unwrap()
    }

    fn fresh_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("tattle-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn core_at(dir: &std::path::Path) -> Result<Core> {
        let (tx, _rx) = std::sync::mpsc::channel();
        Core::new(dir.to_path_buf(), Waker { tx, fd: -1 })
    }

    fn user_rule() -> Rule {
        Rule::new(
            Action::Deny,
            "/usr/bin/curl",
            Remote::Host("example.com".into()),
        )
    }

    #[test]
    fn rules_survive_a_restart() {
        let dir = fresh_dir("restart");
        let id = core_at(&dir).unwrap().add_rule(user_rule()).unwrap();
        let c = core_at(&dir).unwrap();
        assert!(c.rules.iter().any(|r| r.id == id));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn unparseable_state_is_moved_aside_not_overwritten() {
        let dir = fresh_dir("broken");
        std::fs::write(dir.join("settings.json"), "{ not json").unwrap();
        std::fs::write(dir.join("rules.json"), "[ not json").unwrap();
        core_at(&dir).unwrap();
        let names: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        for (prefix, body) in [
            ("settings.json.broken-", "{ not json"),
            ("rules.json.broken-", "[ not json"),
        ] {
            let aside = names.iter().find(|n| n.starts_with(prefix)).unwrap();
            assert_eq!(std::fs::read_to_string(dir.join(aside)).unwrap(), body);
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn unreadable_state_stops_startup() {
        let dir = fresh_dir("unreadable");
        // Reading a directory fails with an I/O error other than NotFound.
        std::fs::create_dir(dir.join("rules.json")).unwrap();
        assert!(core_at(&dir).is_err());
        assert!(dir.join("rules.json").is_dir());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn failed_save_reports_an_error_and_keeps_the_old_rules() {
        let dir = fresh_dir("savefail");
        let mut c = core_at(&dir).unwrap();
        let before = c.rules.clone();
        let settings = c.settings.clone();
        // Make every rename onto rules.json / settings.json fail, even as root.
        std::fs::remove_file(dir.join("rules.json")).unwrap();
        std::fs::create_dir(dir.join("rules.json")).unwrap();
        std::fs::remove_file(dir.join("settings.json")).unwrap();
        std::fs::create_dir(dir.join("settings.json")).unwrap();

        assert!(c.add_rule(user_rule()).is_err());
        assert_eq!(c.rules.len(), before.len());
        assert!(c.delete_rule(before[0].id).is_err());
        assert_eq!(c.rules.len(), before.len());

        let mut s = settings.clone();
        s.prompt_timeout = settings.prompt_timeout + 7;
        assert!(c.set_settings(s).is_err());
        assert_eq!(c.settings.prompt_timeout, settings.prompt_timeout);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn conn(exe: &str, host: &str, ip: &str) -> Connection {
        Connection {
            direction: Direction::Out,
            proto: Proto::Tcp,
            local_ip: "192.168.1.10".parse().unwrap(),
            local_port: 50000,
            remote_ip: ip.parse().unwrap(),
            remote_port: 443,
            hostnames: vec![host.to_string()],
            process: ProcessInfo {
                pid: 42,
                exe: exe.into(),
                ..Default::default()
            },
        }
    }

    fn place(c: &mut Core, ip: &str, lat: f64, lon: f64, city: &str) {
        for a in c.apps.values_mut() {
            for r in a.remotes.values_mut() {
                if r.ip == ip {
                    r.geo = Some(GeoInfo {
                        lat,
                        lon,
                        cc: "DE".into(),
                        country: "Germany".into(),
                        city: city.into(),
                        asn: None,
                        org: Some("Hetzner".into()),
                    });
                }
            }
        }
    }

    #[test]
    fn map_rolls_servers_up_by_place() {
        let mut c = core();
        c.record(
            &conn("/usr/bin/curl", "a.example", "5.9.0.1"),
            Action::Allow,
            Reason::Rule,
            None,
            1,
        );
        c.record(
            &conn("/usr/bin/pacman", "b.example", "5.9.0.2"),
            Action::Allow,
            Reason::Rule,
            None,
            1,
        );
        c.record(
            &conn("/usr/bin/curl", "c.example", "5.9.0.3"),
            Action::Deny,
            Reason::Rule,
            None,
            1,
        );
        c.record(
            &conn("/usr/bin/curl", "nas.lan", "192.168.1.2"),
            Action::Allow,
            Reason::Rule,
            None,
            1,
        );
        c.record(
            &conn("/usr/bin/curl", "d.example", "9.9.9.9"),
            Action::Allow,
            Reason::Rule,
            None,
            1,
        );
        // Same city in the database: one place. A different one: another.
        place(&mut c, "5.9.0.1", 50.48, 12.37, "Falkenstein");
        place(&mut c, "5.9.0.2", 50.48, 12.37, "Falkenstein");
        place(&mut c, "5.9.0.3", 52.52, 13.40, "Berlin");

        let m = c.map_view(None, 40);
        assert_eq!(m.places.len(), 2);
        assert_eq!((m.local, m.unlocated), (1, 1));
        let f = m.places.iter().find(|p| p.city == "Falkenstein").unwrap();
        assert_eq!(f.servers.len(), 2);
        assert_eq!(f.allowed, 2);
        assert_eq!(f.orgs, vec!["Hetzner".to_string()]);
        let mut apps = f.apps.clone();
        apps.sort();
        assert_eq!(apps, vec!["curl".to_string(), "pacman".to_string()]);
        let b = m.places.iter().find(|p| p.city == "Berlin").unwrap();
        assert!(b.blocked());

        // The server list is capped, with a count of the rest.
        let m = c.map_view(None, 1);
        let f = m.places.iter().find(|p| p.city == "Falkenstein").unwrap();
        assert_eq!((f.servers.len(), f.more), (1, 1));

        // Old servers drop out of a time window.
        for a in c.apps.values_mut() {
            for r in a.remotes.values_mut() {
                r.last_seen = 1;
            }
        }
        assert!(c.map_view(Some(3600), 40).places.is_empty());
        let _ = std::fs::remove_dir_all(&c.state_dir);
    }
}
