//! Control-socket protocol: newline-delimited JSON over a Unix stream socket.
//!
//! Client → daemon:  {"id": 7, "cmd": "status"}
//! Daemon → client:  {"id": 7, "ok": true, "data": {...}}
//!                   {"id": 7, "ok": false, "error": "..."}
//! Daemon → client (after "subscribe"):  {"event": "prompt", "data": {...}}

use crate::model::*;
use serde::{Deserialize, Serialize};

pub const SOCKET_PATH: &str = "/run/tattle/tattle.sock";

pub fn socket_path() -> String {
    std::env::var("TATTLE_SOCKET").unwrap_or_else(|_| SOCKET_PATH.to_string())
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Envelope {
    #[serde(default)]
    pub id: Option<u64>,
    #[serde(flatten)]
    pub req: Request,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    Status,
    /// Start streaming events. `alerts`: this client can answer alerts.
    Subscribe {
        #[serde(default)]
        alerts: bool,
        #[serde(default)]
        traffic: bool,
        #[serde(default)]
        connections: bool,
    },
    Rules,
    AddRule {
        rule: Rule,
    },
    UpdateRule {
        rule: Rule,
    },
    DeleteRule {
        rule_id: u64,
    },
    SetRuleEnabled {
        rule_id: u64,
        enabled: bool,
    },
    Pending,
    Decide {
        prompt_id: u64,
        decision: Decision,
    },
    Apps,
    Log {
        #[serde(default)]
        limit: Option<usize>,
        /// Only denied connections.
        #[serde(default)]
        denied: bool,
    },
    SetMode {
        mode: Mode,
    },
    SetEnabled {
        enabled: bool,
    },
    SetProfile {
        profile: Option<String>,
    },
    AddProfile {
        name: String,
    },
    RemoveProfile {
        name: String,
    },
    SetSettings {
        settings: Settings,
    },
    AddBlocklist {
        name: String,
        url: String,
    },
    RemoveBlocklist {
        name: String,
    },
    SetBlocklistEnabled {
        name: String,
        enabled: bool,
    },
    RefreshBlocklists,
    /// Servers rolled up by location, for the map.
    Map {
        /// Only servers seen in the last so many seconds.
        #[serde(default)]
        since: Option<u64>,
        /// Servers listed per place (default 40).
        #[serde(default)]
        limit: Option<usize>,
    },
    /// Download (or refresh) the free DB-IP location database.
    GeoUpdate,
    /// Where an address is, according to the location database.
    Locate {
        ip: std::net::IpAddr,
    },
    ResetStats,
    ResetDefaults,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Reply {
    pub id: Option<u64>,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "event", content = "data", rename_all = "snake_case")]
pub enum Event {
    Prompt(Prompt),
    /// An alert was answered (by anyone), timed out, or became moot.
    PromptResolved {
        id: u64,
        action: Action,
    },
    Connection(ConnEvent),
    Status(Status),
    RulesChanged,
    /// Periodic per-app transfer rates, only for subscribers asking for traffic.
    Traffic {
        apps: Vec<AppRate>,
        tx_rate: u64,
        rx_rate: u64,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AppRate {
    pub identity: String,
    pub name: String,
    pub tx_rate: u64,
    pub rx_rate: u64,
    pub active: u32,
}

/// Any line the daemon sends. Short-lived (parsed, then matched), so the
/// size difference between variants doesn't matter.
#[allow(clippy::large_enum_variant)]
#[derive(Deserialize, Debug)]
#[serde(untagged)]
pub enum Incoming {
    Event(Event),
    Reply(Reply),
}
