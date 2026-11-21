//! nftables plumbing: one private table that sends *new* flows to userspace.
//!
//! Every rule uses `queue flags bypass`: if the daemon is not running the
//! kernel lets traffic through instead of black-holing the machine.

use anyhow::{Context, Result, bail};
use std::io::Write;
use std::process::{Command, Stdio};

pub const TABLE: &str = "tattle";

/// Packets we deny are re-injected (NF_REPEAT) carrying this mark, so the
/// table can answer them with a TCP reset / ICMP unreachable: the app fails
/// instantly instead of hanging until its connect timeout.
pub const DENY_MARK: u32 = 0x7a77_0d1e;

pub struct NftConfig {
    pub conn_queue: u16,
    pub dns_queue: u16,
    pub inbound: bool,
    /// Also filter loopback (only for tests in a network namespace).
    pub include_loopback: bool,
}

pub fn ruleset(c: &NftConfig) -> String {
    let lo_out = if c.include_loopback {
        ""
    } else {
        "        oifname \"lo\" accept\n"
    };
    let lo_in = if c.include_loopback {
        ""
    } else {
        "        iifname \"lo\" accept\n"
    };
    let reject = format!(
        "        meta mark {DENY_MARK:#x} meta l4proto tcp reject with tcp reset\n\
         \x20       meta mark {DENY_MARK:#x} reject\n"
    );
    let mut s = format!(
        "table inet {TABLE}\n\
         delete table inet {TABLE}\n\
         table inet {TABLE} {{\n\
         \x20   chain output {{\n\
         \x20       type filter hook output priority filter - 10; policy accept;\n\
         {lo_out}\
         {reject}\
         \x20       meta l4proto {{ tcp, udp }} ct state new queue flags bypass to {q}\n\
         \x20   }}\n\
         \x20   chain dns {{\n\
         \x20       type filter hook input priority filter - 10; policy accept;\n\
         \x20       udp sport 53 queue flags bypass to {d}\n\
         \x20   }}\n",
        q = c.conn_queue,
        d = c.dns_queue,
    );
    if c.inbound {
        s.push_str(&format!(
            "    chain input {{\n\
             \x20       type filter hook input priority filter - 9; policy accept;\n\
             {lo_in}\
             {reject}\
             \x20       meta l4proto {{ tcp, udp }} ct state new queue flags bypass to {q}\n\
             \x20   }}\n",
            q = c.conn_queue,
        ));
    }
    s.push_str("}\n");
    s
}

fn run_nft(script: &str) -> Result<()> {
    let mut child = Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("running nft (is nftables installed?)")?;
    child.stdin.take().unwrap().write_all(script.as_bytes())?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        bail!(
            "nft failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// Atomically (re)install the table.
pub fn install(c: &NftConfig) -> Result<()> {
    run_nft(&ruleset(c))
}

pub fn remove() {
    let _ = run_nft(&format!("table inet {TABLE}\ndelete table inet {TABLE}\n"));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ruleset_shape() {
        let r = ruleset(&NftConfig {
            conn_queue: 4200,
            dns_queue: 4201,
            inbound: false,
            include_loopback: false,
        });
        assert!(r.contains("queue flags bypass to 4200"));
        assert!(r.contains("udp sport 53 queue flags bypass to 4201"));
        assert!(r.contains("oifname \"lo\" accept"));
        assert!(r.contains("reject with tcp reset"));
        assert!(!r.contains("chain input"));
        let r = ruleset(&NftConfig {
            conn_queue: 1,
            dns_queue: 2,
            inbound: true,
            include_loopback: true,
        });
        assert!(r.contains("chain input"));
        assert!(!r.contains("\"lo\""));
    }
}
