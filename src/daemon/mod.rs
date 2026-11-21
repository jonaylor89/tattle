pub mod blocklist;
pub mod conntrack;
pub mod core;
pub mod dns;
pub mod geo;
pub mod ipc;
pub mod netlink;
pub mod nft;
pub mod packet;
pub mod procs;
pub mod queue;

use self::core::{Core, QueueCmd, Waker, log};
use crate::model::*;
use anyhow::{Context, Result, bail};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub struct DaemonArgs {
    pub state_dir: PathBuf,
    pub socket: String,
    pub group: String,
    pub conn_queue: u16,
    pub dns_queue: u16,
    pub include_loopback: bool,
}

fn block_signals() -> libc::sigset_t {
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        for s in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
            libc::sigaddset(&mut set, s);
        }
        libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
        set
    }
}

fn local_addrs() -> Vec<IpAddr> {
    let mut out = Vec::new();
    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifap) != 0 {
            return out;
        }
        let mut cur = ifap;
        while !cur.is_null() {
            let a = (*cur).ifa_addr;
            if !a.is_null() {
                match (*a).sa_family as i32 {
                    libc::AF_INET => {
                        let sin = &*(a as *const libc::sockaddr_in);
                        out.push(IpAddr::V4(std::net::Ipv4Addr::from(u32::from_be(
                            sin.sin_addr.s_addr,
                        ))));
                    }
                    libc::AF_INET6 => {
                        let sin6 = &*(a as *const libc::sockaddr_in6);
                        out.push(IpAddr::V6(std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr)));
                    }
                    _ => {}
                }
            }
            cur = (*cur).ifa_next;
        }
        libc::freeifaddrs(ifap);
    }
    out
}

pub fn run(args: DaemonArgs) -> Result<()> {
    if unsafe { libc::geteuid() } != 0 && std::env::var_os("TATTLE_ALLOW_NONROOT").is_none() {
        bail!(
            "the daemon needs root (CAP_NET_ADMIN); run it via systemd: sudo systemctl enable --now tattle"
        );
    }
    let sigset = block_signals();

    let mut pipe = [0i32; 2];
    if unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) } != 0 {
        bail!("pipe2 failed");
    }
    let (tx, rx) = std::sync::mpsc::channel();
    let waker = Waker { tx, fd: pipe[1] };
    let core = Arc::new(Mutex::new(Core::new(
        args.state_dir.clone(),
        waker.clone(),
    )?));
    blocklist::rebuild(&core);
    conntrack::enable_accounting();

    let inbound = core.lock().unwrap().settings.inbound;
    let nft_cfg = nft::NftConfig {
        conn_queue: args.conn_queue,
        dns_queue: args.dns_queue,
        inbound,
        include_loopback: args.include_loopback,
    };
    let qcfg = queue::QueueConfig {
        conn_queue: args.conn_queue,
        dns_queue: args.dns_queue,
    };
    // Bind the queues before the rules exist, so nothing is ever queued to
    // a queue with no listener (it would pass, thanks to bypass, but we
    // would miss it).
    let q = queue::open(&qcfg)?;
    nft::install(&nft_cfg).context("installing nftables rules")?;
    core.lock().unwrap().inbound_active = inbound;
    let nft_cfg = Arc::new(Mutex::new(nft_cfg));

    let admin_gid = ipc::group_gid(&args.group);
    if admin_gid.is_none() {
        log::warn(&format!(
            "group '{}' not found; only root can use the control socket",
            args.group
        ));
    }
    let listener =
        ipc::bind(&args.socket, admin_gid).with_context(|| format!("binding {}", args.socket))?;

    {
        let c = core.lock().unwrap();
        log::info(&format!(
            "watching (mode: {}, {} rules, {} blocked domains, inbound: {}) — control socket {}",
            c.settings.mode.label(),
            c.rules.len(),
            c.blocks.len(),
            inbound,
            args.socket
        ));
    }

    let qcore = core.clone();
    let wake_r = pipe[0];
    let queue_thread = std::thread::Builder::new()
        .name("queue".into())
        .spawn(move || {
            queue::run(qcore, q, qcfg, rx, wake_r);
        })?;

    let ctx = Arc::new(ipc::Ctx {
        core: core.clone(),
        nft: nft_cfg,
        admin_gid,
    });
    std::thread::Builder::new()
        .name("ipc".into())
        .spawn(move || ipc::serve(ctx, listener))?;

    let score = core.clone();
    std::thread::Builder::new()
        .name("stats".into())
        .spawn(move || stats_loop(score))?;

    // Main thread: wait for a signal, then tear down cleanly.
    loop {
        let mut sig: libc::c_int = 0;
        unsafe { libc::sigwait(&sigset, &mut sig) };
        if sig == libc::SIGHUP {
            log::info("SIGHUP: refreshing blocklists");
            let c = core.clone();
            std::thread::spawn(move || blocklist::refresh(c, None));
            continue;
        }
        break;
    }
    log::info("shutting down");
    // Stop queueing first, then release anything still held.
    nft::remove();
    waker.send(QueueCmd::Shutdown);
    let deadline = Instant::now() + Duration::from_secs(2);
    while !queue_thread.is_finished() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    let _ = std::fs::remove_file(&args.socket);
    Ok(())
}

fn stats_loop(core: Arc<Mutex<Core>>) {
    let mut ct = conntrack::Conntrack::open().ok();
    let mut procs = procs::Procs::new();
    let mut last = Instant::now();
    let mut last_gc = Instant::now();
    let mut last_prune = Instant::now();
    let mut last_blocklist_check = Instant::now() - Duration::from_secs(3600);
    let mut last_geo_check = Instant::now();
    loop {
        std::thread::sleep(Duration::from_secs(2));
        let elapsed = last.elapsed().as_secs_f64();
        last = Instant::now();

        if ct.is_none() {
            ct = conntrack::Conntrack::open().ok();
        }
        let flows = match ct.as_mut().map(|c| c.dump()) {
            Some(Ok(f)) => f,
            Some(Err(e)) => {
                log::warn(&format!("conntrack dump failed: {e}"));
                ct = None;
                Vec::new()
            }
            None => Vec::new(),
        };

        // Attribute flows that predate us (or that we only saw in DNS).
        let unknown = core.lock().unwrap().unknown_flows(&flows, 64);
        let mut adopted = Vec::new();
        if !unknown.is_empty() {
            let locals = local_addrs();
            for key in unknown {
                let (direction, local, remote) = if locals.contains(&key.src) {
                    (Direction::Out, (key.src, key.sport), (key.dst, key.dport))
                } else if locals.contains(&key.dst) {
                    (Direction::In, (key.dst, key.dport), (key.src, key.sport))
                } else {
                    adopted.push((key, None)); // forwarded (containers, VMs)
                    continue;
                };
                let found = procs
                    .find_socket(key.proto, direction, local, remote)
                    .and_then(|s| Some((s, procs.pid_for_inode(s.inode, Some(s.uid))?)))
                    .and_then(|(s, pid)| procs.process_info(pid, Some(s.uid)));
                adopted.push((key, found.map(|p| (direction, local, remote, p))));
            }
        }

        let mut c = core.lock().unwrap();
        for (key, found) in adopted {
            let conn = found.map(|(direction, local, remote, process)| Connection {
                direction,
                proto: Proto::from_num(key.proto),
                local_ip: local.0,
                local_port: local.1,
                remote_ip: remote.0,
                remote_port: remote.1,
                hostnames: c.hostnames_for(remote.0),
                process,
            });
            c.adopt_flow(key, conn);
        }
        let rates = c.apply_flows(&flows, elapsed);
        let ev = c.traffic_event(rates);
        c.broadcast(&ev);
        c.broadcast_status();

        if last_prune.elapsed() > Duration::from_secs(600) {
            last_prune = Instant::now();
            c.dns.prune(now());
        }
        let bound = if last_gc.elapsed() > Duration::from_secs(5) {
            last_gc = Instant::now();
            Some(c.process_bound_rules())
        } else {
            None
        };
        // A location database installed or updated by something else.
        let mut geo_due = false;
        if last_geo_check.elapsed() > Duration::from_secs(60) {
            last_geo_check = Instant::now();
            if c.geo.reload() {
                c.backfill_geo();
            }
            geo_due = c.settings.geo_auto_update && !c.geo.downloading && c.geo.update_due();
        }
        let check_lists = last_blocklist_check.elapsed() > Duration::from_secs(600);
        let lists_due = check_lists
            && !c.blocklist_refreshing
            && blocklist::due(&c.settings.blocklists, c.settings.blocklist_refresh_hours);
        drop(c);

        if let Some(bound) = bound {
            let dead: Vec<u64> = bound
                .into_iter()
                .filter(|&(_, pid, st)| !procs.alive(pid, st))
                .map(|(id, _, _)| id)
                .collect();
            core.lock().unwrap().expire_rules(&dead);
        }
        if geo_due {
            let c = core.clone();
            std::thread::spawn(move || geo::download(c));
        }
        if check_lists {
            last_blocklist_check = Instant::now();
            if lists_due {
                let c = core.clone();
                std::thread::spawn(move || blocklist::refresh(c, None));
            }
        }
    }
}
