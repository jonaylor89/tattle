//! The control socket. Access is limited twice: the socket file is
//! root:<admin group> 0660, and every peer's credentials are checked again.

use super::blocklist;
use super::core::{Core, log};
use super::nft::{self, NftConfig};
use crate::model::*;
use crate::proto::{Envelope, Reply, Request};
use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::mpsc::sync_channel;
use std::sync::{Arc, Mutex};

pub struct Ctx {
    pub core: Arc<Mutex<Core>>,
    pub nft: Arc<Mutex<NftConfig>>,
    /// Members of this group may control the daemon (default: wheel).
    pub admin_gid: Option<u32>,
}

pub fn group_gid(name: &str) -> Option<u32> {
    let s = std::fs::read_to_string("/etc/group").ok()?;
    s.lines().find_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        (f.len() > 2 && f[0] == name)
            .then(|| f[2].parse().ok())
            .flatten()
    })
}

fn peer_cred(s: &UnixStream) -> Option<libc::ucred> {
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let r = unsafe {
        libc::getsockopt(
            s.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    (r == 0).then_some(cred)
}

fn authorized(cred: &libc::ucred, admin_gid: Option<u32>) -> bool {
    let me = unsafe { libc::geteuid() };
    if cred.uid == 0 || cred.uid == me {
        return true;
    }
    let Some(gid) = admin_gid else { return false };
    if cred.gid == gid {
        return true;
    }
    // Supplementary groups of the connecting process.
    std::fs::read_to_string(format!("/proc/{}/status", cred.pid))
        .ok()
        .and_then(|s| {
            s.lines().find(|l| l.starts_with("Groups:")).map(|l| {
                l[7..]
                    .split_whitespace()
                    .any(|g| g.parse::<u32>() == Ok(gid))
            })
        })
        .unwrap_or(false)
}

pub fn bind(path: &str, admin_gid: Option<u32>) -> Result<UnixListener> {
    let p = std::path::Path::new(path);
    if let Some(dir) = p.parent() {
        std::fs::create_dir_all(dir)?;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755));
    }
    let _ = std::fs::remove_file(p);
    let l = UnixListener::bind(p)?;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o660))?;
    if let Some(gid) = admin_gid {
        let c = std::ffi::CString::new(path).unwrap();
        unsafe { libc::chown(c.as_ptr(), 0, gid) };
    }
    Ok(l)
}

pub fn serve(ctx: Arc<Ctx>, listener: UnixListener) {
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let Some(cred) = peer_cred(&stream) else {
            continue;
        };
        if !authorized(&cred, ctx.admin_gid) {
            let mut s = stream;
            let _ = s.write_all(b"{\"id\":null,\"ok\":false,\"error\":\"permission denied: not in the admin group\"}\n");
            continue;
        }
        let ctx = ctx.clone();
        std::thread::spawn(move || client(ctx, stream));
    }
}

fn client(ctx: Arc<Ctx>, stream: UnixStream) {
    let (tx, rx) = sync_channel::<String>(4096);
    let id = ctx.core.lock().unwrap().add_client(tx.clone());
    let Ok(mut writer) = stream.try_clone() else {
        return;
    };
    let w = std::thread::spawn(move || {
        for line in rx {
            if writer.write_all(line.as_bytes()).is_err() {
                break;
            }
        }
        let _ = writer.shutdown(std::net::Shutdown::Both);
    });
    // Cap a single request at 1 MiB so a client cannot balloon memory.
    let mut reader = BufReader::new(stream.take(u64::MAX));
    let mut line = String::new();
    loop {
        line.clear();
        let mut limited = (&mut reader).take(1 << 20);
        match limited.read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        if !line.ends_with('\n') && line.len() >= 1 << 20 {
            break;
        }
        if line.trim().is_empty() {
            continue;
        }
        let reply = match serde_json::from_str::<Envelope>(&line) {
            Ok(env) => {
                let rid = env.id;
                match handle(&ctx, id, env.req) {
                    Ok(data) => Reply {
                        id: rid,
                        ok: true,
                        data: Some(data),
                        error: None,
                    },
                    Err(e) => Reply {
                        id: rid,
                        ok: false,
                        data: None,
                        error: Some(e.to_string()),
                    },
                }
            }
            Err(e) => Reply {
                id: None,
                ok: false,
                data: None,
                error: Some(format!("bad request: {e}")),
            },
        };
        let mut s = serde_json::to_string(&reply).unwrap_or_default();
        s.push('\n');
        if tx.try_send(s).is_err() {
            break;
        }
    }
    ctx.core.lock().unwrap().remove_client(id);
    drop(tx);
    let _ = w.join();
}

fn to_value<T: serde::Serialize>(v: T) -> Result<Value> {
    Ok(serde_json::to_value(v)?)
}

fn reinstall_nft(ctx: &Ctx, inbound: bool) -> Result<()> {
    let mut cfg = ctx.nft.lock().unwrap();
    cfg.inbound = inbound;
    nft::install(&cfg)?;
    ctx.core.lock().unwrap().inbound_active = inbound;
    Ok(())
}

fn handle(ctx: &Ctx, client_id: u64, req: Request) -> Result<Value> {
    let core = &ctx.core;
    match req {
        Request::Status => to_value(core.lock().unwrap().status()),
        Request::Subscribe {
            alerts,
            traffic,
            connections,
        } => {
            let mut c = core.lock().unwrap();
            c.subscribe(client_id, alerts, traffic, connections);
            Ok(json!({ "subscribed": true }))
        }
        Request::Rules => to_value(core.lock().unwrap().rules.clone()),
        Request::AddRule { rule } => Ok(json!({ "id": core.lock().unwrap().add_rule(rule)? })),
        Request::UpdateRule { rule } => core.lock().unwrap().update_rule(rule).map(|_| json!({})),
        Request::DeleteRule { rule_id } => {
            core.lock().unwrap().delete_rule(rule_id).map(|_| json!({}))
        }
        Request::SetRuleEnabled { rule_id, enabled } => core
            .lock()
            .unwrap()
            .set_rule_enabled(rule_id, enabled)
            .map(|_| json!({})),
        Request::Pending => to_value(core.lock().unwrap().pending()),
        Request::Decide {
            prompt_id,
            decision,
        } => {
            let rule = core.lock().unwrap().decide_prompt(prompt_id, decision)?;
            Ok(json!({ "rule_id": rule }))
        }
        Request::Apps => to_value(core.lock().unwrap().apps()),
        Request::Log { limit, denied } => to_value(
            core.lock()
                .unwrap()
                .log_tail(limit.unwrap_or(500).min(5000), denied),
        ),
        Request::SetMode { mode } => {
            let mut c = core.lock().unwrap();
            c.settings.mode = mode;
            c.settings_changed();
            Ok(json!({}))
        }
        Request::SetEnabled { enabled } => {
            let mut c = core.lock().unwrap();
            c.settings.enabled = enabled;
            c.settings_changed();
            Ok(json!({}))
        }
        Request::SetProfile { profile } => {
            let mut c = core.lock().unwrap();
            if let Some(p) = &profile
                && !c.settings.profiles.contains(p)
            {
                bail!("unknown profile '{p}'");
            }
            c.settings.active_profile = profile;
            c.settings_changed();
            Ok(json!({}))
        }
        Request::AddProfile { name } => {
            let name = name.trim().to_string();
            if name.is_empty() || name.len() > 64 {
                bail!("profile name must be 1-64 characters");
            }
            let mut c = core.lock().unwrap();
            if !c.settings.profiles.contains(&name) {
                c.settings.profiles.push(name);
            }
            c.settings_changed();
            Ok(json!({}))
        }
        Request::RemoveProfile { name } => {
            let mut c = core.lock().unwrap();
            c.settings.profiles.retain(|p| *p != name);
            if c.settings.active_profile.as_deref() == Some(name.as_str()) {
                c.settings.active_profile = None;
            }
            // Rules of a deleted profile would never apply again.
            let before = c.rules.len();
            c.rules
                .retain(|r| r.profile.as_deref() != Some(name.as_str()));
            if c.rules.len() != before {
                c.save_rules();
                c.broadcast(&crate::proto::Event::RulesChanged);
            }
            c.settings_changed();
            Ok(json!({}))
        }
        Request::SetSettings { settings } => {
            let inbound = settings.inbound;
            let changed = core.lock().unwrap().set_settings(settings)?;
            if changed && let Err(e) = reinstall_nft(ctx, inbound) {
                log::warn(&format!("could not apply inbound setting: {e}"));
                bail!("settings saved, but the firewall could not be updated: {e}");
            }
            Ok(json!({}))
        }
        Request::AddBlocklist { name, url } => {
            let name = name.trim().to_string();
            blocklist::validate(&name, &url)?;
            {
                let mut c = core.lock().unwrap();
                if c.settings.blocklists.iter().any(|b| b.name == name) {
                    bail!("a blocklist named '{name}' already exists");
                }
                c.settings.blocklists.push(Blocklist {
                    name: name.clone(),
                    url,
                    enabled: true,
                    entries: 0,
                    updated: None,
                    error: None,
                });
                c.settings_changed();
            }
            let core = core.clone();
            std::thread::spawn(move || blocklist::refresh(core, Some(name)));
            Ok(json!({ "refreshing": true }))
        }
        Request::RemoveBlocklist { name } => {
            {
                let mut c = core.lock().unwrap();
                let before = c.settings.blocklists.len();
                c.settings.blocklists.retain(|b| b.name != name);
                if before == c.settings.blocklists.len() {
                    return Err(anyhow!("no blocklist '{name}'"));
                }
                blocklist::remove_cache(&c.state_dir, &name);
                c.settings_changed();
            }
            blocklist::rebuild(core);
            Ok(json!({}))
        }
        Request::SetBlocklistEnabled { name, enabled } => {
            {
                let mut c = core.lock().unwrap();
                let b = c
                    .settings
                    .blocklists
                    .iter_mut()
                    .find(|b| b.name == name)
                    .ok_or_else(|| anyhow!("no blocklist '{name}'"))?;
                b.enabled = enabled;
                let needs_download = enabled && b.updated.is_none();
                c.settings_changed();
                if needs_download {
                    let core = core.clone();
                    std::thread::spawn(move || blocklist::refresh(core, Some(name)));
                    return Ok(json!({ "refreshing": true }));
                }
            }
            blocklist::rebuild(core);
            Ok(json!({}))
        }
        Request::RefreshBlocklists => {
            let core = core.clone();
            std::thread::spawn(move || blocklist::refresh(core, None));
            Ok(json!({ "refreshing": true }))
        }
        Request::ResetStats => {
            core.lock().unwrap().reset_stats();
            Ok(json!({}))
        }
        Request::ResetDefaults => {
            core.lock().unwrap().reset_defaults();
            Ok(json!({}))
        }
    }
}
