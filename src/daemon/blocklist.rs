//! Subscribable domain blocklists (hosts files, plain domain lists, or
//! simple Adblock `||domain^` lists). Downloads go through curl over HTTPS
//! only; parsed lists are cached on disk so they work offline after boot.

use super::core::{Core, log};
use crate::model::{Blocklist, now, valid_hostname};
use crate::rules::BlockSet;
use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

const MAX_ENTRIES: usize = 2_000_000;

pub const PRESETS: &[(&str, &str)] = &[
    (
        "HaGeZi Light",
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/light-onlydomains.txt",
    ),
    (
        "HaGeZi Pro",
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro-onlydomains.txt",
    ),
    (
        "HaGeZi Threat Intelligence",
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif-onlydomains.txt",
    ),
    (
        "StevenBlack Unified",
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    ),
];

pub fn validate(name: &str, url: &str) -> Result<()> {
    if name.trim().is_empty() || name.len() > 64 {
        bail!("name must be 1-64 characters");
    }
    if !name
        .chars()
        .all(|c| c.is_alphanumeric() || " _.-()".contains(c))
    {
        bail!("name may only contain letters, digits, spaces and _.-()");
    }
    if !url.starts_with("https://")
        || url.len() > 2048
        || url.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        bail!("blocklist URL must be a plain https:// URL");
    }
    Ok(())
}

fn slug(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect()
}

fn cache_path(dir: &Path, name: &str) -> PathBuf {
    dir.join("blocklists").join(format!("{}.txt", slug(name)))
}

pub fn parse_list(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty()
            || line.starts_with('#')
            || line.starts_with('!')
            || line.starts_with('[')
        {
            continue;
        }
        let line = line.split('#').next().unwrap_or("").trim();
        let mut candidates: Vec<&str> = Vec::new();
        if let Some(rest) = line.strip_prefix("||") {
            // Only plain domain rules; anything with options or paths is
            // not something a connection firewall can honour exactly.
            if let Some(d) = rest.strip_suffix('^') {
                candidates.push(d);
            }
        } else {
            let mut toks = line.split_whitespace();
            let first = toks.next().unwrap_or("");
            if first.parse::<std::net::IpAddr>().is_ok() {
                candidates.extend(toks);
            } else if toks.next().is_none() {
                candidates.push(first);
            }
        }
        for c in candidates {
            let c = c.strip_prefix("*.").unwrap_or(c);
            if matches!(
                c,
                "localhost"
                    | "localhost.localdomain"
                    | "local"
                    | "broadcasthost"
                    | "ip6-localhost"
                    | "ip6-loopback"
                    | "0.0.0.0"
            ) || !c.contains('.')
                || c.parse::<std::net::IpAddr>().is_ok()
            {
                continue;
            }
            if let Ok(d) = valid_hostname(c) {
                out.push(d);
                if out.len() >= MAX_ENTRIES {
                    return out;
                }
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

fn download(url: &str) -> Result<String> {
    let out = Command::new("curl")
        .args([
            "-fsSL",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--max-time",
            "120",
            "--max-filesize",
            "100000000",
            "--retry",
            "2",
            "-A",
            concat!("tattle/", env!("CARGO_PKG_VERSION")),
            "--",
            url,
        ])
        .output()
        .context("running curl")?;
    if !out.status.success() {
        bail!(
            "download failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Build the in-memory set from cached files of every enabled list.
pub fn build(dir: &Path, lists: &[Blocklist]) -> BlockSet {
    let mut set = BlockSet::new();
    for l in lists.iter().filter(|l| l.enabled) {
        if let Ok(text) = std::fs::read_to_string(cache_path(dir, &l.name)) {
            set.insert_list(
                &l.name,
                text.lines().filter(|s| !s.is_empty()).map(str::to_string),
            );
        }
    }
    set
}

/// Rebuild the block set off-lock and swap it in.
pub fn rebuild(core: &Arc<Mutex<Core>>) {
    let (dir, lists) = {
        let c = core.lock().unwrap();
        (c.state_dir.clone(), c.settings.blocklists.clone())
    };
    let set = build(&dir, &lists);
    let mut c = core.lock().unwrap();
    c.blocks = set;
    c.reevaluate_prompts();
    c.broadcast_status();
}

/// Download (all or one) list(s), update their status, rebuild.
pub fn refresh(core: Arc<Mutex<Core>>, only: Option<String>) {
    let (dir, lists) = {
        let mut c = core.lock().unwrap();
        if c.blocklist_refreshing {
            return;
        }
        c.blocklist_refreshing = true;
        (c.state_dir.clone(), c.settings.blocklists.clone())
    };
    let _ = std::fs::create_dir_all(dir.join("blocklists"));
    for l in lists
        .iter()
        .filter(|l| l.enabled && only.as_ref().is_none_or(|o| *o == l.name))
    {
        let result = download(&l.url).map(|text| parse_list(&text));
        let mut c = core.lock().unwrap();
        let Some(entry) = c.settings.blocklists.iter_mut().find(|x| x.name == l.name) else {
            continue;
        };
        match result {
            Ok(domains) if domains.is_empty() => {
                entry.error = Some("list contained no usable domains".into());
            }
            Ok(domains) => {
                let path = cache_path(&dir, &l.name);
                let tmp = path.with_extension("tmp");
                match std::fs::write(&tmp, domains.join("\n"))
                    .and_then(|_| std::fs::rename(&tmp, &path))
                {
                    Ok(()) => {
                        entry.entries = domains.len();
                        entry.updated = Some(now());
                        entry.error = None;
                        log::info(&format!(
                            "blocklist '{}' updated: {} domains",
                            l.name,
                            domains.len()
                        ));
                    }
                    Err(e) => entry.error = Some(format!("saving: {e}")),
                }
            }
            Err(e) => {
                log::warn(&format!("blocklist '{}': {e}", l.name));
                entry.error = Some(e.to_string());
            }
        }
        c.save_settings();
    }
    core.lock().unwrap().blocklist_refreshing = false;
    rebuild(&core);
}

pub fn remove_cache(dir: &Path, name: &str) {
    let _ = std::fs::remove_file(cache_path(dir, name));
}

/// Is any enabled list due for its periodic refresh?
pub fn due(lists: &[Blocklist], hours: u64) -> bool {
    if hours == 0 {
        return false;
    }
    let now = now();
    lists.iter().any(|l| {
        l.enabled
            && l.updated
                .is_none_or(|u| now.saturating_sub(u) >= hours * 3600)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats() {
        let text = "# comment\n0.0.0.0 ads.example.com\n127.0.0.1 localhost\n0.0.0.0 a.com b.org # trailing\n\
                    tracker.net\n||adserver.io^\n||x.com^$third-party\n*.wild.dev\n! adblock comment\nnot a domain line\n\
                    1.2.3.4\n";
        let d = parse_list(text);
        assert_eq!(
            d,
            vec![
                "a.com",
                "ads.example.com",
                "adserver.io",
                "b.org",
                "tracker.net",
                "wild.dev"
            ]
        );
    }

    #[test]
    fn validation() {
        assert!(validate("Ads", "https://example.com/list.txt").is_ok());
        assert!(validate("Ads", "http://example.com/list.txt").is_err());
        assert!(validate("Ads", "https://x.com/a b").is_err());
        assert!(validate("../etc", "https://x.com/").is_err());
        assert_eq!(slug("HaGeZi Pro"), "hagezi-pro");
    }
}
