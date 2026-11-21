//! Text input and the rule editor form.

use crate::cli::parse_duration;
use crate::model::*;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

#[derive(Default, Clone)]
pub struct Input {
    pub value: String,
    /// Cursor position in chars.
    pub cursor: usize,
}

impl Input {
    pub fn with(v: impl Into<String>) -> Input {
        let value = v.into();
        let cursor = value.chars().count();
        Input { value, cursor }
    }

    fn byte_at(&self, char_idx: usize) -> usize {
        self.value
            .char_indices()
            .nth(char_idx)
            .map(|(b, _)| b)
            .unwrap_or(self.value.len())
    }

    /// Returns true if the key was consumed.
    pub fn key(&mut self, k: KeyEvent) -> bool {
        let len = self.value.chars().count();
        self.cursor = self.cursor.min(len);
        match k.code {
            KeyCode::Char('u') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                let b = self.byte_at(self.cursor);
                self.value.replace_range(..b, "");
                self.cursor = 0;
            }
            KeyCode::Char('w') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                let chars: Vec<char> = self.value.chars().collect();
                let mut i = self.cursor;
                while i > 0 && chars[i - 1] == ' ' {
                    i -= 1;
                }
                while i > 0 && chars[i - 1] != ' ' && chars[i - 1] != '/' && chars[i - 1] != '.' {
                    i -= 1;
                }
                let (a, b) = (self.byte_at(i), self.byte_at(self.cursor));
                self.value.replace_range(a..b, "");
                self.cursor = i;
            }
            KeyCode::Char(c) if !k.modifiers.contains(KeyModifiers::CONTROL) => {
                if self.value.len() < 4096 {
                    let b = self.byte_at(self.cursor);
                    self.value.insert(b, c);
                    self.cursor += 1;
                }
            }
            KeyCode::Backspace if self.cursor > 0 => {
                let b = self.byte_at(self.cursor - 1);
                self.value.remove(b);
                self.cursor -= 1;
            }
            KeyCode::Delete if self.cursor < len => {
                let b = self.byte_at(self.cursor);
                self.value.remove(b);
            }
            KeyCode::Left => self.cursor = self.cursor.saturating_sub(1),
            KeyCode::Right => self.cursor = (self.cursor + 1).min(len),
            KeyCode::Home => self.cursor = 0,
            KeyCode::End => self.cursor = len,
            _ => return false,
        }
        true
    }
}

pub enum EditorResult {
    Continue,
    Cancel,
    Save(Rule),
}

pub const FIELDS: [&str; 9] = [
    "Action",
    "Direction",
    "Process",
    "Server",
    "Port",
    "Protocol",
    "Profile",
    "Expires in",
    "Note",
];

pub struct RuleEditor {
    pub base: Option<Rule>,
    pub field: usize,
    pub action: Action,
    pub direction: Direction,
    pub process: Input,
    pub remote: Input,
    pub port: Input,
    pub proto: Proto,
    pub profile: Option<String>,
    pub expires: Input,
    pub note: Input,
    pub error: Option<String>,
}

impl RuleEditor {
    pub fn new(rule: Option<&Rule>) -> RuleEditor {
        let r = rule.cloned();
        let remote_text = |r: &Remote| match r {
            Remote::Any => "any".to_string(),
            Remote::Local => "local".to_string(),
            Remote::Host(h) => h.clone(),
            Remote::Domain(d) => format!("*.{d}"),
            Remote::Ip(n) => n.clone(),
        };
        let expires = match r.as_ref().map(|r| &r.lifetime) {
            Some(Lifetime::Until { at }) => {
                let left = at.saturating_sub(now());
                if left % 3600 == 0 && left > 0 {
                    format!("{}h", left / 3600)
                } else {
                    format!("{}m", left.div_ceil(60))
                }
            }
            _ => String::new(),
        };
        RuleEditor {
            field: if r.is_some() { 0 } else { 2 },
            action: r.as_ref().map_or(Action::Allow, |r| r.action),
            direction: r.as_ref().map_or(Direction::Out, |r| r.direction),
            process: Input::with(r.as_ref().map_or("*".to_string(), |r| r.process.clone())),
            remote: Input::with(
                r.as_ref()
                    .map_or("any".to_string(), |r| remote_text(&r.remote)),
            ),
            port: Input::with(
                r.as_ref()
                    .and_then(|r| r.port)
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "any".into()),
            ),
            proto: r.as_ref().map_or(Proto::Any, |r| r.proto),
            profile: r.as_ref().and_then(|r| r.profile.clone()),
            expires: Input::with(expires),
            note: Input::with(r.as_ref().map_or(String::new(), |r| r.note.clone())),
            base: r,
            error: None,
        }
    }

    pub fn is_text(&self, field: usize) -> bool {
        matches!(field, 2 | 3 | 4 | 7 | 8)
    }

    pub fn input(&mut self, field: usize) -> Option<&mut Input> {
        match field {
            2 => Some(&mut self.process),
            3 => Some(&mut self.remote),
            4 => Some(&mut self.port),
            7 => Some(&mut self.expires),
            8 => Some(&mut self.note),
            _ => None,
        }
    }

    pub fn value(&self, field: usize) -> String {
        match field {
            0 => self.action.to_string(),
            1 => {
                if self.direction == Direction::Out {
                    "outgoing".into()
                } else {
                    "incoming".into()
                }
            }
            2 => self.process.value.clone(),
            3 => self.remote.value.clone(),
            4 => self.port.value.clone(),
            5 => self.proto.to_string(),
            6 => self
                .profile
                .clone()
                .unwrap_or_else(|| "all profiles".into()),
            7 => {
                if self.expires.value.is_empty()
                    && !matches!(
                        self.base.as_ref().map(|b| &b.lifetime),
                        Some(Lifetime::UntilQuit { .. })
                    )
                {
                    "never".into()
                } else if self.expires.value.is_empty() {
                    "when the process quits".into()
                } else {
                    self.expires.value.clone()
                }
            }
            8 => self.note.value.clone(),
            _ => String::new(),
        }
    }

    pub fn hint(&self, field: usize) -> &'static str {
        match field {
            0 | 1 | 5 | 6 => "←→ change",
            2 => "* = any process · kernel · /path/to/exe",
            3 => "any · local · host.name · *.domain · 10.0.0.0/8",
            4 => "any · 443 · 8000-8100",
            7 => "empty = never · 30m · 2h · 7d",
            _ => "",
        }
    }

    fn build(&self) -> Result<Rule, String> {
        let process = self.process.value.trim();
        let process = if process.is_empty() || process == "any" {
            ANY_PROCESS.to_string()
        } else {
            process.to_string()
        };
        let mut r = self
            .base
            .clone()
            .unwrap_or_else(|| Rule::new(self.action, ANY_PROCESS, Remote::Any));
        r.action = self.action;
        r.direction = self.direction;
        r.process = process;
        r.remote = Remote::parse(&self.remote.value)?;
        r.port = PortRange::parse(&self.port.value)?;
        r.proto = self.proto;
        r.profile = self.profile.clone();
        r.note = self.note.value.trim().to_string();
        let e = self.expires.value.trim();
        if e.is_empty() {
            if !matches!(r.lifetime, Lifetime::UntilQuit { .. }) {
                r.lifetime = Lifetime::Forever;
            }
        } else {
            let secs = parse_duration(e).map_err(|e| e.to_string())?;
            r.lifetime = Lifetime::Until { at: now() + secs };
        }
        // Editing a built-in rule makes it yours.
        r.source = RuleSource::User;
        Ok(r)
    }

    pub fn key(&mut self, k: KeyEvent, profiles: &[String]) -> EditorResult {
        let d: i32 = match k.code {
            KeyCode::Left => -1,
            KeyCode::Right | KeyCode::Char(' ') => 1,
            _ => 0,
        };
        match k.code {
            KeyCode::Esc => return EditorResult::Cancel,
            KeyCode::Enter => {
                return match self.build() {
                    Ok(r) => EditorResult::Save(r),
                    Err(e) => {
                        self.error = Some(e);
                        EditorResult::Continue
                    }
                };
            }
            KeyCode::Tab | KeyCode::Down => {
                self.field = (self.field + 1) % FIELDS.len();
                return EditorResult::Continue;
            }
            KeyCode::BackTab | KeyCode::Up => {
                self.field = (self.field + FIELDS.len() - 1) % FIELDS.len();
                return EditorResult::Continue;
            }
            _ => {}
        }
        self.error = None;
        let field = self.field;
        if self.is_text(field) {
            if let Some(i) = self.input(field) {
                i.key(k);
            }
            return EditorResult::Continue;
        }
        if d != 0 {
            match field {
                0 => {
                    self.action = if self.action == Action::Allow {
                        Action::Deny
                    } else {
                        Action::Allow
                    }
                }
                1 => {
                    self.direction = if self.direction == Direction::Out {
                        Direction::In
                    } else {
                        Direction::Out
                    }
                }
                5 => {
                    let all = [Proto::Any, Proto::Tcp, Proto::Udp];
                    let i = all.iter().position(|p| *p == self.proto).unwrap_or(0) as i32;
                    self.proto = all[(i + d).rem_euclid(3) as usize];
                }
                6 => {
                    let mut opts: Vec<Option<String>> = vec![None];
                    opts.extend(profiles.iter().cloned().map(Some));
                    let i = opts.iter().position(|o| *o == self.profile).unwrap_or(0) as i32;
                    self.profile = opts[(i + d).rem_euclid(opts.len() as i32) as usize].clone();
                }
                _ => {}
            }
        }
        EditorResult::Continue
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyEventKind;

    fn key(c: KeyCode) -> KeyEvent {
        KeyEvent {
            code: c,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
        }
    }

    #[test]
    fn input_editing_is_unicode_safe() {
        let mut i = Input::with("héllo");
        i.key(key(KeyCode::Backspace));
        assert_eq!(i.value, "héll");
        i.key(key(KeyCode::Home));
        i.key(key(KeyCode::Right));
        i.key(key(KeyCode::Right));
        i.key(key(KeyCode::Backspace));
        assert_eq!(i.value, "hll");
        i.key(key(KeyCode::Char('é')));
        assert_eq!(i.value, "héll");
    }

    #[test]
    fn editor_round_trip() {
        let mut r = Rule::new(
            Action::Deny,
            "/usr/bin/curl",
            Remote::Domain("example.com".into()),
        );
        r.id = 5;
        r.port = Some(PortRange::single(443));
        let ed = RuleEditor::new(Some(&r));
        assert_eq!(ed.remote.value, "*.example.com");
        let built = ed.build().unwrap();
        assert_eq!(built.id, 5);
        assert_eq!(built.remote, r.remote);
        assert_eq!(built.port, r.port);
        assert_eq!(built.action, Action::Deny);
        let mut bad = RuleEditor::new(None);
        bad.port = Input::with("99999");
        assert!(bad.build().is_err());
    }
}
