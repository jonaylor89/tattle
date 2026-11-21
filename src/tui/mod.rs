//! The interactive monitor. Colours come from the terminal's ANSI palette,
//! so it follows the active Omarchy theme automatically.

mod draw;
mod editor;

use crate::client::{self, Client};
use crate::model::*;
use crate::proto::{AppRate, Event, Request};
use anyhow::Result;
use crossterm::event::{self, Event as TermEvent, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use editor::{Input, RuleEditor};
use std::collections::{HashMap, VecDeque};
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Monitor,
    Rules,
    Log,
    Blocklists,
    Settings,
}

impl Tab {
    pub const ALL: [Tab; 5] = [
        Tab::Monitor,
        Tab::Rules,
        Tab::Log,
        Tab::Blocklists,
        Tab::Settings,
    ];
    pub fn title(self) -> &'static str {
        match self {
            Tab::Monitor => "Monitor",
            Tab::Rules => "Rules",
            Tab::Log => "Log",
            Tab::Blocklists => "Blocklists",
            Tab::Settings => "Settings",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    Apps,
    Remotes,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AppSort {
    Traffic,
    Recent,
    Name,
    Denied,
}

impl AppSort {
    fn next(self) -> AppSort {
        match self {
            AppSort::Traffic => AppSort::Recent,
            AppSort::Recent => AppSort::Name,
            AppSort::Name => AppSort::Denied,
            AppSort::Denied => AppSort::Traffic,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            AppSort::Traffic => "traffic",
            AppSort::Recent => "recent",
            AppSort::Name => "name",
            AppSort::Denied => "denied",
        }
    }
}

/// Options on the alert card, in display order.
pub struct AlertChoice {
    pub row: usize,
    pub remote: usize,
    pub port: usize,
    pub process: usize,
    pub lifetime: usize,
}

impl Default for AlertChoice {
    fn default() -> Self {
        AlertChoice {
            row: 0,
            remote: 1,
            port: 0,
            process: 0,
            lifetime: 2,
        }
    }
}

pub const LIFETIMES: [(&str, DecisionLifetime); 4] = [
    ("once", DecisionLifetime::Once),
    ("until quit", DecisionLifetime::UntilQuit),
    ("forever", DecisionLifetime::Forever),
    ("1 hour", DecisionLifetime::For(3600)),
];

pub fn remote_options(p: &Prompt) -> Vec<(RemoteScope, String)> {
    let mut v = Vec::new();
    if let Some(h) = p.conn.hostnames.first() {
        v.push((RemoteScope::Host, h.clone()));
    }
    if let Some(d) = &p.domain {
        v.push((RemoteScope::Domain, format!("*.{d}")));
    }
    v.push((RemoteScope::Ip, canonical_ip(p.conn.remote_ip).to_string()));
    v.push((RemoteScope::Any, "any server".into()));
    v
}

pub enum Modal {
    None,
    Help,
    Editor(Box<RuleEditor>),
    Confirm {
        text: String,
        action: ConfirmAction,
    },
    Input {
        title: String,
        fields: Vec<(String, Input)>,
        focus: usize,
        action: InputAction,
    },
    Presets {
        sel: usize,
    },
}

pub enum ConfirmAction {
    DeleteRule(u64),
    RemoveBlocklist(String),
    RemoveProfile(String),
    ResetDefaults,
    ResetStats,
}

pub enum InputAction {
    AddBlocklist,
    AddProfile,
}

pub struct App {
    pub client: Client,
    events: Receiver<Option<Event>>,
    pub connected: bool,
    pub tab: Tab,
    pub status: Status,
    pub rules: Vec<Rule>,
    pub apps: Vec<AppStats>,
    pub rates: HashMap<String, AppRate>,
    pub app_history: HashMap<String, VecDeque<u64>>,
    pub tx_hist: VecDeque<u64>,
    pub rx_hist: VecDeque<u64>,
    pub log: VecDeque<ConnEvent>,
    pub prompts: Vec<Prompt>,
    pub alert: AlertChoice,
    pub alert_hidden: bool,
    pub alert_shown_at: Instant,
    pub modal: Modal,
    pub focus: Focus,
    pub app_sel: usize,
    pub remote_sel: usize,
    pub rule_sel: usize,
    pub log_sel: Option<usize>,
    pub list_sel: usize,
    pub setting_sel: usize,
    pub sort: AppSort,
    pub filter: Input,
    pub filtering: bool,
    pub log_denied_only: bool,
    pub toast: Option<(String, bool, Instant)>,
    pub tick: u64,
    apps_dirty: bool,
    last_rules: Instant,
    last_apps: Instant,
    pub quit: bool,
}

pub const HISTORY: usize = 180;

impl App {
    fn new() -> Result<App> {
        let mut client = Client::connect()?;
        let events = client::subscribe(true, true, true)?;
        let status: Status = client.get(Request::Status)?;
        let rules: Vec<Rule> = client.get(Request::Rules)?;
        let apps: Vec<AppStats> = client.get(Request::Apps)?;
        let log: Vec<ConnEvent> = client.get(Request::Log {
            limit: Some(1000),
            denied: false,
        })?;
        Ok(App {
            client,
            events,
            connected: true,
            tab: Tab::Monitor,
            status,
            rules,
            apps,
            rates: HashMap::new(),
            app_history: HashMap::new(),
            tx_hist: VecDeque::from(vec![0; HISTORY]),
            rx_hist: VecDeque::from(vec![0; HISTORY]),
            log: log.into(),
            prompts: Vec::new(),
            alert: AlertChoice::default(),
            alert_hidden: false,
            alert_shown_at: Instant::now(),
            modal: Modal::None,
            focus: Focus::Apps,
            app_sel: 0,
            remote_sel: 0,
            rule_sel: 0,
            log_sel: None,
            list_sel: 0,
            setting_sel: 0,
            sort: AppSort::Traffic,
            filter: Input::default(),
            filtering: false,
            log_denied_only: false,
            toast: None,
            tick: 0,
            apps_dirty: false,
            last_rules: Instant::now(),
            last_apps: Instant::now(),
            quit: false,
        })
    }

    pub fn say(&mut self, msg: impl Into<String>) {
        self.toast = Some((msg.into(), false, Instant::now()));
    }
    pub fn err(&mut self, msg: impl Into<String>) {
        self.toast = Some((msg.into(), true, Instant::now()));
    }

    fn call(&mut self, req: Request) -> bool {
        match self.client.call(req) {
            Ok(_) => true,
            Err(e) => {
                self.err(format!("{e}"));
                false
            }
        }
    }

    fn reload_rules(&mut self) {
        if let Ok(r) = self.client.get::<Vec<Rule>>(Request::Rules) {
            self.rules = r;
        }
        self.last_rules = Instant::now();
    }

    fn reload_apps(&mut self) {
        if let Ok(a) = self.client.get::<Vec<AppStats>>(Request::Apps) {
            self.apps = a;
        }
        self.apps_dirty = false;
        self.last_apps = Instant::now();
    }

    fn drain_events(&mut self) {
        while let Ok(ev) = self.events.try_recv() {
            let Some(ev) = ev else {
                self.connected = false;
                return;
            };
            match ev {
                Event::Status(s) => {
                    self.status = s;
                    // Hit counts change without a rules_changed event.
                    if self.tab == Tab::Rules && self.last_rules.elapsed() > Duration::from_secs(2)
                    {
                        self.reload_rules();
                    }
                }
                Event::RulesChanged => self.reload_rules(),
                Event::Prompt(p) => {
                    if !self.prompts.iter().any(|x| x.id == p.id) {
                        if self.prompts.is_empty() {
                            self.alert = AlertChoice::default();
                            self.alert_shown_at = Instant::now();
                            self.alert_hidden = false;
                        }
                        self.prompts.push(p);
                    }
                }
                Event::PromptResolved { id, .. } => {
                    let was_first = self.prompts.first().map(|p| p.id) == Some(id);
                    self.prompts.retain(|p| p.id != id);
                    if was_first {
                        self.alert = AlertChoice::default();
                        self.alert_shown_at = Instant::now();
                    }
                }
                Event::Connection(c) => {
                    if self.log.len() >= 5000 {
                        self.log.pop_front();
                    }
                    // Keep a paused selection on the same row as new lines arrive on top.
                    let shifts = self.log_matches(&c);
                    self.log.push_back(c);
                    if let (Some(sel), true) = (self.log_sel.as_mut(), shifts) {
                        *sel += 1;
                    }
                    self.apps_dirty = true;
                }
                Event::Traffic {
                    apps,
                    tx_rate,
                    rx_rate,
                } => {
                    push_hist(&mut self.tx_hist, tx_rate);
                    push_hist(&mut self.rx_hist, rx_rate);
                    let live: HashMap<String, AppRate> =
                        apps.into_iter().map(|a| (a.identity.clone(), a)).collect();
                    for (id, h) in self.app_history.iter_mut() {
                        let v = live.get(id).map(|r| r.tx_rate + r.rx_rate).unwrap_or(0);
                        if h.len() >= 24 {
                            h.pop_front();
                        }
                        h.push_back(v);
                    }
                    for (id, r) in &live {
                        self.app_history.entry(id.clone()).or_insert_with(|| {
                            let mut d = VecDeque::from(vec![0; 23]);
                            d.push_back(r.tx_rate + r.rx_rate);
                            d
                        });
                    }
                    self.rates = live;
                    self.apps_dirty = true;
                }
            }
        }
    }

    /// Apps in display order, filtered.
    pub fn sorted_apps(&self) -> Vec<&AppStats> {
        let q = self.filter.value.to_lowercase();
        let mut v: Vec<&AppStats> = self
            .apps
            .iter()
            .filter(|a| {
                q.is_empty()
                    || a.name.to_lowercase().contains(&q)
                    || a.identity.to_lowercase().contains(&q)
                    || a.remotes.iter().any(|r| r.host.contains(&q))
            })
            .collect();
        let rate = |a: &AppStats| {
            self.rates
                .get(&a.identity)
                .map(|r| r.tx_rate + r.rx_rate)
                .unwrap_or(0)
        };
        match self.sort {
            AppSort::Traffic => v.sort_by(|a, b| {
                rate(b)
                    .cmp(&rate(a))
                    .then((b.tx + b.rx).cmp(&(a.tx + a.rx)))
                    .then(b.last_seen.cmp(&a.last_seen))
            }),
            AppSort::Recent => v.sort_by_key(|a| std::cmp::Reverse(a.last_seen)),
            AppSort::Name => v.sort_by_key(|a| a.name.to_lowercase()),
            AppSort::Denied => {
                v.sort_by(|a, b| b.denied.cmp(&a.denied).then(b.last_seen.cmp(&a.last_seen)))
            }
        }
        v
    }

    pub fn selected_app(&self) -> Option<&AppStats> {
        self.sorted_apps().get(self.app_sel).copied()
    }

    pub fn filtered_rules(&self) -> Vec<&Rule> {
        let q = self.filter.value.to_lowercase();
        let mut v: Vec<&Rule> = self
            .rules
            .iter()
            .filter(|r| {
                q.is_empty()
                    || r.summary().to_lowercase().contains(&q)
                    || r.process.to_lowercase().contains(&q)
                    || r.note.to_lowercase().contains(&q)
            })
            .collect();
        // Your rules first, then built-ins; newest first inside each.
        v.sort_by(|a, b| {
            (a.source != RuleSource::User)
                .cmp(&(b.source != RuleSource::User))
                .then(b.id.cmp(&a.id))
        });
        v
    }

    fn log_matches(&self, e: &ConnEvent) -> bool {
        let q = self.filter.value.to_lowercase();
        (!self.log_denied_only || e.action == Action::Deny)
            && (q.is_empty()
                || e.conn.process.name().to_lowercase().contains(&q)
                || e.conn.host().contains(&q)
                || e.conn.remote_ip.to_string().contains(&q))
    }

    pub fn filtered_log(&self) -> Vec<&ConnEvent> {
        self.log
            .iter()
            .rev()
            .filter(|e| self.log_matches(e))
            .collect()
    }

    fn answer(&mut self, action: Action) {
        let Some(p) = self.prompts.first().cloned() else {
            return;
        };
        // Guard against a keystroke meant for something else.
        if self.alert_shown_at.elapsed() < Duration::from_millis(600) {
            return;
        }
        let opts = remote_options(&p);
        let (scope, _) = opts[self.alert.remote.min(opts.len() - 1)].clone();
        let decision = Decision {
            action,
            remote: scope,
            port_only: self.alert.port == 0,
            any_process: self.alert.process == 1,
            lifetime: LIFETIMES[self.alert.lifetime].1,
            in_profile: false,
        };
        if self.call(Request::Decide {
            prompt_id: p.id,
            decision,
        }) {
            self.prompts.retain(|x| x.id != p.id);
            self.alert = AlertChoice::default();
            self.alert_shown_at = Instant::now();
            self.say(format!(
                "{} {} → {}",
                if action == Action::Allow {
                    "Allowed"
                } else {
                    "Denied"
                },
                p.conn.process.name(),
                p.conn.host()
            ));
        }
    }

    fn alert_key(&mut self, k: KeyEvent) -> bool {
        if self.prompts.is_empty() || self.alert_hidden {
            return false;
        }
        let p = self.prompts[0].clone();
        let nremote = remote_options(&p).len();
        let cycle =
            |v: &mut usize, n: usize, d: i32| *v = ((*v as i32 + d).rem_euclid(n as i32)) as usize;
        match k.code {
            KeyCode::Char('a') | KeyCode::Char('A') => self.answer(Action::Allow),
            KeyCode::Char('d') | KeyCode::Char('D') => self.answer(Action::Deny),
            KeyCode::Esc => {
                self.alert_hidden = true;
                self.say("Alert deferred — press ! to bring it back");
            }
            KeyCode::Up | KeyCode::Char('k') => cycle(&mut self.alert.row, 4, -1),
            KeyCode::Down | KeyCode::Char('j') | KeyCode::Tab => cycle(&mut self.alert.row, 4, 1),
            KeyCode::Left | KeyCode::Right | KeyCode::Char('h') | KeyCode::Char('l') => {
                let d = if matches!(k.code, KeyCode::Left | KeyCode::Char('h')) {
                    -1
                } else {
                    1
                };
                match self.alert.row {
                    0 => cycle(&mut self.alert.remote, nremote, d),
                    1 => cycle(&mut self.alert.port, 2, d),
                    2 => cycle(&mut self.alert.process, 2, d),
                    _ => cycle(&mut self.alert.lifetime, LIFETIMES.len(), d),
                }
            }
            KeyCode::Char('s') => cycle(&mut self.alert.remote, nremote, 1),
            KeyCode::Char('p') => cycle(&mut self.alert.port, 2, 1),
            KeyCode::Char('o') => cycle(&mut self.alert.process, 2, 1),
            KeyCode::Char('f') => cycle(&mut self.alert.lifetime, LIFETIMES.len(), 1),
            KeyCode::Char('q') if k.modifiers.contains(KeyModifiers::CONTROL) => self.quit = true,
            _ => {}
        }
        true
    }

    fn quick_rule(&mut self, action: Action, whole_app: bool) {
        let Some(app) = self.selected_app().cloned() else {
            return;
        };
        if app.identity == ANY_PROCESS {
            return;
        }
        let remote = if whole_app || self.focus == Focus::Apps {
            Remote::Any
        } else {
            match app.remotes.get(self.remote_sel) {
                Some(r) => Remote::parse(&r.host).unwrap_or(Remote::Ip(r.ip.clone())),
                None => return,
            }
        };
        let rule = Rule::new(action, app.identity.clone(), remote);
        let summary = rule.summary();
        if self.call(Request::AddRule { rule }) {
            self.say(format!("Rule added: {summary}"));
        }
    }

    fn handle_key(&mut self, k: KeyEvent) {
        if k.kind != KeyEventKind::Press {
            return;
        }
        if k.code == KeyCode::Char('c') && k.modifiers.contains(KeyModifiers::CONTROL) {
            self.quit = true;
            return;
        }
        // Modals first.
        match std::mem::replace(&mut self.modal, Modal::None) {
            Modal::None => {}
            Modal::Help => return,
            Modal::Editor(mut ed) => {
                match ed.key(k, &self.status.settings.profiles) {
                    editor::EditorResult::Continue => self.modal = Modal::Editor(ed),
                    editor::EditorResult::Cancel => {}
                    editor::EditorResult::Save(rule) => {
                        let summary = rule.summary();
                        let req = if rule.id == 0 {
                            Request::AddRule { rule }
                        } else {
                            Request::UpdateRule { rule }
                        };
                        match self.client.call(req) {
                            Ok(_) => self.say(format!("Saved: {summary}")),
                            Err(e) => {
                                ed.error = Some(e.to_string());
                                self.modal = Modal::Editor(ed);
                            }
                        }
                    }
                }
                return;
            }
            Modal::Confirm { text, action } => {
                if matches!(
                    k.code,
                    KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter
                ) {
                    let ok = match &action {
                        ConfirmAction::DeleteRule(id) => {
                            self.call(Request::DeleteRule { rule_id: *id })
                        }
                        ConfirmAction::RemoveBlocklist(n) => {
                            self.call(Request::RemoveBlocklist { name: n.clone() })
                        }
                        ConfirmAction::RemoveProfile(n) => {
                            self.call(Request::RemoveProfile { name: n.clone() })
                        }
                        ConfirmAction::ResetDefaults => self.call(Request::ResetDefaults),
                        ConfirmAction::ResetStats => {
                            let ok = self.call(Request::ResetStats);
                            if ok {
                                self.log.clear();
                                self.reload_apps();
                            }
                            ok
                        }
                    };
                    if ok {
                        self.say("Done");
                    }
                } else if !matches!(
                    k.code,
                    KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc
                ) {
                    self.modal = Modal::Confirm { text, action };
                }
                return;
            }
            Modal::Input {
                title,
                mut fields,
                mut focus,
                action,
            } => {
                match k.code {
                    KeyCode::Esc => {}
                    KeyCode::Tab | KeyCode::Down => {
                        focus = (focus + 1) % fields.len();
                        self.modal = Modal::Input {
                            title,
                            fields,
                            focus,
                            action,
                        };
                    }
                    KeyCode::BackTab | KeyCode::Up => {
                        focus = (focus + fields.len() - 1) % fields.len();
                        self.modal = Modal::Input {
                            title,
                            fields,
                            focus,
                            action,
                        };
                    }
                    KeyCode::Enter => {
                        let vals: Vec<String> = fields
                            .iter()
                            .map(|(_, i)| i.value.trim().to_string())
                            .collect();
                        let ok = match action {
                            InputAction::AddBlocklist => self.call(Request::AddBlocklist {
                                name: vals[0].clone(),
                                url: vals[1].clone(),
                            }),
                            InputAction::AddProfile => self.call(Request::AddProfile {
                                name: vals[0].clone(),
                            }),
                        };
                        if ok {
                            self.say("Saved");
                        } else {
                            self.modal = Modal::Input {
                                title,
                                fields,
                                focus,
                                action,
                            };
                        }
                    }
                    _ => {
                        fields[focus].1.key(k);
                        self.modal = Modal::Input {
                            title,
                            fields,
                            focus,
                            action,
                        };
                    }
                }
                return;
            }
            Modal::Presets { mut sel } => {
                let presets = crate::daemon::blocklist::PRESETS;
                match k.code {
                    KeyCode::Up | KeyCode::Char('k') => {
                        sel = sel.saturating_sub(1);
                        self.modal = Modal::Presets { sel };
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        sel = (sel + 1).min(presets.len() - 1);
                        self.modal = Modal::Presets { sel };
                    }
                    KeyCode::Enter => {
                        let (n, u) = presets[sel];
                        if self.call(Request::AddBlocklist {
                            name: n.into(),
                            url: u.into(),
                        }) {
                            self.say(format!("Subscribed to {n} — downloading…"));
                        }
                    }
                    KeyCode::Esc => {}
                    _ => self.modal = Modal::Presets { sel },
                }
                return;
            }
        }

        if self.alert_key(k) {
            return;
        }

        if self.filtering {
            match k.code {
                KeyCode::Esc => {
                    self.filtering = false;
                    self.filter = Input::default();
                }
                KeyCode::Enter => self.filtering = false,
                _ => {
                    self.filter.key(k);
                    self.app_sel = 0;
                    self.rule_sel = 0;
                    self.log_sel = None;
                }
            }
            return;
        }

        match k.code {
            KeyCode::Char('q') => {
                self.quit = true;
                return;
            }
            KeyCode::Char('?') => {
                self.modal = Modal::Help;
                return;
            }
            KeyCode::Char('!') => {
                if !self.prompts.is_empty() {
                    self.alert_hidden = false;
                    self.alert_shown_at = Instant::now();
                }
                return;
            }
            KeyCode::Char('/') => {
                self.filtering = true;
                return;
            }
            KeyCode::Esc if !self.filter.value.is_empty() => {
                self.filter = Input::default();
                return;
            }
            KeyCode::Char(c @ '1'..='5') => {
                self.tab = Tab::ALL[(c as u8 - b'1') as usize];
                self.filter = Input::default();
                return;
            }
            KeyCode::Tab if self.tab != Tab::Monitor => {
                let i = Tab::ALL.iter().position(|t| *t == self.tab).unwrap();
                self.tab = Tab::ALL[(i + 1) % Tab::ALL.len()];
                return;
            }
            KeyCode::BackTab => {
                let i = Tab::ALL.iter().position(|t| *t == self.tab).unwrap();
                self.tab = Tab::ALL[(i + Tab::ALL.len() - 1) % Tab::ALL.len()];
                return;
            }
            KeyCode::Char('m') => {
                let next = match self.status.settings.mode {
                    Mode::Alert => Mode::SilentAllow,
                    Mode::SilentAllow => Mode::SilentDeny,
                    Mode::SilentDeny => Mode::Alert,
                };
                if self.call(Request::SetMode { mode: next }) {
                    self.say(format!("Mode: {}", next.label()));
                }
                return;
            }
            KeyCode::Char('F') => {
                let on = !self.status.settings.enabled;
                if self.call(Request::SetEnabled { enabled: on }) {
                    self.say(if on {
                        "Filtering on — tattling resumed"
                    } else {
                        "Filtering off — everything is allowed"
                    });
                }
                return;
            }
            _ => {}
        }

        match self.tab {
            Tab::Monitor => self.monitor_key(k),
            Tab::Rules => self.rules_key(k),
            Tab::Log => self.log_key(k),
            Tab::Blocklists => self.blocklists_key(k),
            Tab::Settings => self.settings_key(k),
        }
    }

    fn monitor_key(&mut self, k: KeyEvent) {
        let napps = self.sorted_apps().len();
        let nremotes = self.selected_app().map(|a| a.remotes.len()).unwrap_or(0);
        match k.code {
            KeyCode::Tab | KeyCode::Right | KeyCode::Char('l')
                if self.focus == Focus::Apps && nremotes > 0 =>
            {
                self.focus = Focus::Remotes;
                self.remote_sel = self.remote_sel.min(nremotes - 1);
            }
            KeyCode::Tab | KeyCode::Left | KeyCode::Char('h') if self.focus == Focus::Remotes => {
                self.focus = Focus::Apps
            }
            KeyCode::Up | KeyCode::Char('k') => match self.focus {
                Focus::Apps => {
                    self.app_sel = self.app_sel.saturating_sub(1);
                    self.remote_sel = 0;
                }
                Focus::Remotes => self.remote_sel = self.remote_sel.saturating_sub(1),
            },
            KeyCode::Down | KeyCode::Char('j') => match self.focus {
                Focus::Apps => {
                    self.app_sel = (self.app_sel + 1).min(napps.saturating_sub(1));
                    self.remote_sel = 0;
                }
                Focus::Remotes => {
                    self.remote_sel = (self.remote_sel + 1).min(nremotes.saturating_sub(1))
                }
            },
            KeyCode::Home | KeyCode::Char('g') => self.app_sel = 0,
            KeyCode::End | KeyCode::Char('G') => self.app_sel = napps.saturating_sub(1),
            KeyCode::Char('s') => self.sort = self.sort.next(),
            KeyCode::Char('a') => self.quick_rule(Action::Allow, false),
            KeyCode::Char('d') => self.quick_rule(Action::Deny, false),
            KeyCode::Char('A') => self.quick_rule(Action::Allow, true),
            KeyCode::Char('D') => self.quick_rule(Action::Deny, true),
            KeyCode::Char('r') => self.reload_apps(),
            KeyCode::Char('n') => {
                let mut ed = RuleEditor::new(None);
                if let Some(app) = self.selected_app() {
                    ed.process.value = app.identity.clone();
                    if self.focus == Focus::Remotes
                        && let Some(r) = app.remotes.get(self.remote_sel)
                    {
                        ed.remote.value = r.host.clone();
                    }
                }
                self.modal = Modal::Editor(Box::new(ed));
            }
            _ => {}
        }
    }

    fn rules_key(&mut self, k: KeyEvent) {
        let rules: Vec<Rule> = self.filtered_rules().into_iter().cloned().collect();
        let n = rules.len();
        let sel = rules.get(self.rule_sel).cloned();
        match k.code {
            KeyCode::Up | KeyCode::Char('k') => self.rule_sel = self.rule_sel.saturating_sub(1),
            KeyCode::Down | KeyCode::Char('j') => {
                self.rule_sel = (self.rule_sel + 1).min(n.saturating_sub(1))
            }
            KeyCode::PageUp => self.rule_sel = self.rule_sel.saturating_sub(10),
            KeyCode::PageDown => self.rule_sel = (self.rule_sel + 10).min(n.saturating_sub(1)),
            KeyCode::Home | KeyCode::Char('g') => self.rule_sel = 0,
            KeyCode::End | KeyCode::Char('G') => self.rule_sel = n.saturating_sub(1),
            KeyCode::Char(' ') => {
                if let Some(r) = sel {
                    self.call(Request::SetRuleEnabled {
                        rule_id: r.id,
                        enabled: !r.enabled,
                    });
                }
            }
            KeyCode::Char('x') | KeyCode::Delete => {
                if let Some(r) = sel {
                    self.modal = Modal::Confirm {
                        text: format!("Delete rule “{}”?", r.summary()),
                        action: ConfirmAction::DeleteRule(r.id),
                    };
                }
            }
            KeyCode::Char('e') | KeyCode::Enter => {
                if let Some(r) = sel {
                    self.modal = Modal::Editor(Box::new(RuleEditor::new(Some(&r))));
                }
            }
            KeyCode::Char('n') => self.modal = Modal::Editor(Box::new(RuleEditor::new(None))),
            KeyCode::Char('t') => {
                if let Some(mut r) = sel {
                    r.action = if r.action == Action::Allow {
                        Action::Deny
                    } else {
                        Action::Allow
                    };
                    self.call(Request::UpdateRule { rule: r });
                }
            }
            _ => {}
        }
        self.rule_sel = self.rule_sel.min(n.saturating_sub(1));
    }

    fn log_key(&mut self, k: KeyEvent) {
        let n = self.filtered_log().len();
        match k.code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.log_sel = Some(self.log_sel.map_or(0, |s| s.saturating_sub(1)))
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.log_sel = Some(self.log_sel.map_or(0, |s| (s + 1).min(n.saturating_sub(1))))
            }
            KeyCode::PageDown => {
                self.log_sel = Some(
                    self.log_sel
                        .map_or(0, |s| (s + 20).min(n.saturating_sub(1))),
                )
            }
            KeyCode::PageUp => {
                self.log_sel = Some(self.log_sel.map_or(0, |s| s.saturating_sub(20)))
            }
            KeyCode::Home | KeyCode::Char('g') | KeyCode::Esc => self.log_sel = None,
            KeyCode::Char('b') => {
                self.log_denied_only = !self.log_denied_only;
                self.log_sel = None;
            }
            KeyCode::Char('a') | KeyCode::Char('d') => {
                let action = if k.code == KeyCode::Char('a') {
                    Action::Allow
                } else {
                    Action::Deny
                };
                let ev = self
                    .log_sel
                    .and_then(|s| self.filtered_log().get(s).map(|e| (*e).clone()));
                if let Some(e) = ev {
                    let remote = match e.conn.hostnames.first() {
                        Some(h) => Remote::Host(h.clone()),
                        None => Remote::Ip(canonical_ip(e.conn.remote_ip).to_string()),
                    };
                    let mut rule = Rule::new(action, e.conn.identity(), remote);
                    rule.direction = e.conn.direction;
                    let s = rule.summary();
                    if self.call(Request::AddRule { rule }) {
                        self.say(format!("Rule added: {s}"));
                    }
                }
            }
            _ => {}
        }
    }

    fn blocklists_key(&mut self, k: KeyEvent) {
        let lists = self.status.settings.blocklists.clone();
        let n = lists.len();
        match k.code {
            KeyCode::Up | KeyCode::Char('k') => self.list_sel = self.list_sel.saturating_sub(1),
            KeyCode::Down | KeyCode::Char('j') => {
                self.list_sel = (self.list_sel + 1).min(n.saturating_sub(1))
            }
            KeyCode::Char('p') => self.modal = Modal::Presets { sel: 0 },
            KeyCode::Char('n') => {
                self.modal = Modal::Input {
                    title: "Subscribe to a blocklist".into(),
                    fields: vec![
                        ("Name".into(), Input::default()),
                        ("HTTPS URL".into(), Input::default()),
                    ],
                    focus: 0,
                    action: InputAction::AddBlocklist,
                }
            }
            KeyCode::Char(' ') => {
                if let Some(b) = lists.get(self.list_sel) {
                    self.call(Request::SetBlocklistEnabled {
                        name: b.name.clone(),
                        enabled: !b.enabled,
                    });
                }
            }
            KeyCode::Char('x') | KeyCode::Delete => {
                if let Some(b) = lists.get(self.list_sel) {
                    self.modal = Modal::Confirm {
                        text: format!("Unsubscribe from “{}”?", b.name),
                        action: ConfirmAction::RemoveBlocklist(b.name.clone()),
                    };
                }
            }
            KeyCode::Char('r') if self.call(Request::RefreshBlocklists) => {
                self.say("Refreshing blocklists…");
            }
            _ => {}
        }
        self.list_sel = self.list_sel.min(n.saturating_sub(1));
    }

    pub fn settings_rows(&self) -> Vec<(String, String, &'static str)> {
        let s = &self.status.settings;
        let mut rows = vec![
            (
                "Filtering".to_string(),
                if s.enabled { "on".into() } else { "off".into() },
                "space: toggle",
            ),
            ("Mode".to_string(), s.mode.label().to_string(), "←→: change"),
            (
                "Profile".to_string(),
                s.active_profile.clone().unwrap_or_else(|| "none".into()),
                "←→: switch",
            ),
            (
                "Alert timeout".to_string(),
                format!("{} s", s.prompt_timeout),
                "←→: ±5 s",
            ),
            (
                "When an alert times out".to_string(),
                s.timeout_action.to_string(),
                "space: toggle",
            ),
            (
                "When no alert UI is running".to_string(),
                s.no_ui_action.to_string(),
                "space: toggle",
            ),
            (
                "Filter inbound connections".to_string(),
                if s.inbound { "yes".into() } else { "no".into() },
                "space: toggle",
            ),
            (
                "Blocklist refresh".to_string(),
                if s.blocklist_refresh_hours == 0 {
                    "manual".into()
                } else {
                    format!("every {} h", s.blocklist_refresh_hours)
                },
                "←→: change",
            ),
        ];
        for p in &s.profiles {
            rows.push((
                format!("Profile · {p}"),
                if s.active_profile.as_ref() == Some(p) {
                    "active".into()
                } else {
                    String::new()
                },
                "x: remove",
            ));
        }
        rows.push(("Add profile…".into(), String::new(), "enter"));
        rows.push(("Restore built-in rules".into(), String::new(), "enter"));
        rows.push(("Reset statistics".into(), String::new(), "enter"));
        rows
    }

    fn settings_key(&mut self, k: KeyEvent) {
        let rows = self.settings_rows();
        let n = rows.len();
        let mut s = self.status.settings.clone();
        let nprof = s.profiles.len();
        let d: i64 = match k.code {
            KeyCode::Left | KeyCode::Char('h') => -1,
            KeyCode::Right | KeyCode::Char('l') | KeyCode::Char(' ') | KeyCode::Enter => 1,
            _ => 0,
        };
        match k.code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.setting_sel = self.setting_sel.saturating_sub(1);
                return;
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.setting_sel = (self.setting_sel + 1).min(n - 1);
                return;
            }
            _ => {}
        }
        let row = self.setting_sel;
        if row >= 8 && row < 8 + nprof {
            let name = s.profiles[row - 8].clone();
            match k.code {
                KeyCode::Char('x') | KeyCode::Delete => {
                    self.modal = Modal::Confirm {
                        text: format!("Remove profile “{name}” and its rules?"),
                        action: ConfirmAction::RemoveProfile(name),
                    }
                }
                KeyCode::Enter | KeyCode::Char(' ') => {
                    let p = if s.active_profile.as_ref() == Some(&name) {
                        None
                    } else {
                        Some(name)
                    };
                    self.call(Request::SetProfile { profile: p });
                }
                _ => {}
            }
            return;
        }
        if d == 0 {
            return;
        }
        match row {
            0 => {
                self.call(Request::SetEnabled {
                    enabled: !s.enabled,
                });
                return;
            }
            1 => {
                let modes = [Mode::Alert, Mode::SilentAllow, Mode::SilentDeny];
                let i = modes.iter().position(|m| *m == s.mode).unwrap_or(0) as i64;
                let m = modes[(i + d).rem_euclid(3) as usize];
                self.call(Request::SetMode { mode: m });
                return;
            }
            2 => {
                let mut opts: Vec<Option<String>> = vec![None];
                opts.extend(s.profiles.iter().cloned().map(Some));
                let i = opts
                    .iter()
                    .position(|o| *o == s.active_profile)
                    .unwrap_or(0) as i64;
                let p = opts[(i + d).rem_euclid(opts.len() as i64) as usize].clone();
                self.call(Request::SetProfile { profile: p });
                return;
            }
            3 => s.prompt_timeout = (s.prompt_timeout as i64 + d * 5).clamp(5, 3600) as u64,
            4 => s.timeout_action = flip(s.timeout_action),
            5 => s.no_ui_action = flip(s.no_ui_action),
            6 => s.inbound = !s.inbound,
            7 => {
                let steps = [0u64, 6, 12, 24, 72, 168];
                let i = steps
                    .iter()
                    .position(|x| *x == s.blocklist_refresh_hours)
                    .unwrap_or(3) as i64;
                s.blocklist_refresh_hours =
                    steps[(i + d).clamp(0, steps.len() as i64 - 1) as usize];
            }
            r if r == 8 + nprof => {
                self.modal = Modal::Input {
                    title: "New profile".into(),
                    fields: vec![("Name".into(), Input::default())],
                    focus: 0,
                    action: InputAction::AddProfile,
                };
                return;
            }
            r if r == 9 + nprof => {
                self.modal = Modal::Confirm {
                    text: "Restore the built-in rules (DNS, DHCP, time sync)?".into(),
                    action: ConfirmAction::ResetDefaults,
                };
                return;
            }
            r if r == 10 + nprof => {
                self.modal = Modal::Confirm {
                    text: "Clear all statistics and the log?".into(),
                    action: ConfirmAction::ResetStats,
                };
                return;
            }
            _ => return,
        }
        self.call(Request::SetSettings { settings: s });
    }
}

fn flip(a: Action) -> Action {
    if a == Action::Allow {
        Action::Deny
    } else {
        Action::Allow
    }
}

fn push_hist(h: &mut VecDeque<u64>, v: u64) {
    if h.len() >= HISTORY {
        h.pop_front();
    }
    h.push_back(v);
}

pub fn run() -> Result<()> {
    let mut app = App::new()?;
    let mut terminal = ratatui::init();
    let res = (|| -> Result<()> {
        let mut last_tick = Instant::now();
        while !app.quit {
            app.drain_events();
            if app.apps_dirty && app.last_apps.elapsed() > Duration::from_millis(1000) {
                app.reload_apps();
            }
            if let Some((_, _, t)) = &app.toast
                && t.elapsed() > Duration::from_secs(4)
            {
                app.toast = None;
            }
            if last_tick.elapsed() >= Duration::from_millis(250) {
                app.tick += 1;
                last_tick = Instant::now();
            }
            terminal.draw(|f| draw::draw(f, &app))?;
            if !app.connected {
                // Keep the screen up, but say so; try to reconnect.
                std::thread::sleep(Duration::from_millis(500));
                if let Ok(mut fresh) = App::new() {
                    fresh.tab = app.tab;
                    app = fresh;
                    app.say("Reconnected to the daemon");
                }
            }
            if event::poll(Duration::from_millis(100))?
                && let TermEvent::Key(k) = event::read()?
            {
                app.handle_key(k);
            }
        }
        Ok(())
    })();
    ratatui::restore();
    res
}
