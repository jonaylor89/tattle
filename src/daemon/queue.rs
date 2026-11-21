//! The packet thread: reads queued packets, asks `Core` for a verdict, and
//! parks packets whose fate is waiting on an alert.

use super::core::{Core, Outcome, QueueCmd, log};
use super::{dns, packet, procs::Procs};
use crate::model::*;
use anyhow::{Context, Result};
use nfq::{Message, Queue, Verdict};
use std::collections::HashMap;
use std::os::fd::AsRawFd;
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const NF_INET_LOCAL_IN: u8 = 1;

pub struct QueueConfig {
    pub conn_queue: u16,
    pub dns_queue: u16,
}

pub fn open(cfg: &QueueConfig) -> Result<Queue> {
    let mut q = Queue::open().context("opening netfilter queue socket")?;
    for &num in &[cfg.conn_queue, cfg.dns_queue] {
        q.bind(num)
            .with_context(|| format!("binding NFQUEUE {num} (another firewall using it?)"))?;
        q.set_fail_open(num, true)?;
        q.set_queue_max_len(num, 4096)?;
    }
    // Connection decisions only need headers; DNS needs whole answers.
    q.set_copy_range(cfg.conn_queue, 256)?;
    q.set_copy_range(cfg.dns_queue, 0xffff)?;
    q.set_recv_uid_gid(cfg.conn_queue, true)?;
    q.set_nonblocking(true);
    Ok(q)
}

fn verdict(q: &mut Queue, mut msg: Message, action: Action) {
    match action {
        Action::Allow => msg.set_verdict(Verdict::Accept),
        // Re-run the chain with the deny mark: its reject rule answers.
        Action::Deny => {
            msg.set_nfmark(super::nft::DENY_MARK);
            msg.set_verdict(Verdict::Repeat);
        }
    }
    if let Err(e) = q.verdict(msg) {
        log::warn(&format!("verdict failed: {e}"));
    }
}

pub fn run(
    core: Arc<Mutex<Core>>,
    mut q: Queue,
    cfg: QueueConfig,
    rx: Receiver<QueueCmd>,
    wake_fd: i32,
) {
    let mut procs = Procs::new();
    let mut held: HashMap<u64, Vec<Message>> = HashMap::new();
    let mut last_expiry = Instant::now();
    let qfd = q.as_raw_fd();
    loop {
        let mut fds = [
            libc::pollfd {
                fd: qfd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: wake_fd,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        unsafe { libc::poll(fds.as_mut_ptr(), 2, 250) };

        if fds[1].revents & libc::POLLIN != 0 {
            let mut buf = [0u8; 64];
            while unsafe { libc::read(wake_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) }
                > 0
            {}
        }
        while let Ok(cmd) = rx.try_recv() {
            match cmd {
                QueueCmd::Resolve { prompt_id, action } => {
                    for msg in held.remove(&prompt_id).unwrap_or_default() {
                        verdict(&mut q, msg, action);
                    }
                }
                QueueCmd::Shutdown => {
                    let action = core.lock().unwrap().settings.no_ui_action;
                    for (_, msgs) in held.drain() {
                        for m in msgs {
                            verdict(&mut q, m, action);
                        }
                    }
                    return;
                }
            }
        }

        // Drain everything the kernel has for us.
        loop {
            match q.recv() {
                Ok(msg) => handle(&core, &mut q, &mut procs, &mut held, &cfg, msg),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) if e.raw_os_error() == Some(libc::ENOBUFS) => {
                    log::warn(
                        "kernel queue overflowed; some packets passed unfiltered (fail-open)",
                    );
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    log::warn(&format!("queue receive failed: {e}"));
                    std::thread::sleep(Duration::from_millis(50));
                    break;
                }
            }
        }

        if last_expiry.elapsed() >= Duration::from_millis(500) {
            last_expiry = Instant::now();
            core.lock().unwrap().expire_prompts();
        }
    }
}

fn handle(
    core: &Arc<Mutex<Core>>,
    q: &mut Queue,
    procs: &mut Procs,
    held: &mut HashMap<u64, Vec<Message>>,
    cfg: &QueueConfig,
    msg: Message,
) {
    if msg.get_queue_num() == cfg.dns_queue {
        if let Some(p) = packet::parse(msg.get_payload())
            && p.proto == packet::UDP
            && p.sport == 53
        {
            let answers = dns::parse_response(p.payload);
            if !answers.is_empty() {
                let now = now();
                let mut c = core.lock().unwrap();
                for (ip, names, ttl) in answers {
                    c.dns.insert(ip, names, ttl, now);
                }
            }
        }
        verdict(q, msg, Action::Allow);
        return;
    }

    let Some(p) = packet::parse(msg.get_payload()) else {
        verdict(q, msg, Action::Allow);
        return;
    };
    let direction = if msg.get_hook() == NF_INET_LOCAL_IN {
        Direction::In
    } else {
        Direction::Out
    };
    let (local, remote) = match direction {
        Direction::Out => ((p.src, p.sport), (p.dst, p.dport)),
        Direction::In => ((p.dst, p.dport), (p.src, p.sport)),
    };
    let process = procs.resolve(p.proto, direction, local, remote, msg.get_uid());

    let mut c = core.lock().unwrap();
    let conn = Connection {
        direction,
        proto: Proto::from_num(p.proto),
        local_ip: canonical_ip(local.0),
        local_port: local.1,
        remote_ip: canonical_ip(remote.0),
        remote_port: remote.1,
        hostnames: c.hostnames_for(remote.0),
        process,
    };
    match c.decide_new(conn) {
        Outcome::Verdict(a) => {
            drop(c);
            verdict(q, msg, a);
        }
        Outcome::Hold(id) => {
            drop(c);
            held.entry(id).or_default().push(msg);
        }
    }
}
