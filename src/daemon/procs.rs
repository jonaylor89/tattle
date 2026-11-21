//! Who owns this packet? Map a 5-tuple to a socket (sock_diag), the socket
//! to a process (/proc/*/fd), and the process to an identity rules can use.

use super::netlink::{NETLINK_SOCK_DIAG, NLM_F_DUMP, Netlink};
use crate::model::{Direction, KERNEL_IDENTITY, ProcessInfo, canonical_ip};
use std::collections::{HashMap, VecDeque};
use std::fs;
use std::net::{IpAddr, Ipv6Addr};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

const SOCK_DIAG_BY_FAMILY: u16 = 20;
const NOCOOKIE: u32 = 0xffff_ffff;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SockMatch {
    pub uid: u32,
    pub inode: u32,
}

struct DiagMsg {
    sport: u16,
    dport: u16,
    src: IpAddr,
    dst: IpAddr,
    uid: u32,
    inode: u32,
}

fn ip_bytes(ip: IpAddr, family: u8) -> [u8; 16] {
    let mut b = [0u8; 16];
    match (ip, family as i32) {
        (IpAddr::V4(v4), libc::AF_INET) => b[..4].copy_from_slice(&v4.octets()),
        (IpAddr::V4(v4), _) => b = v4.to_ipv6_mapped().octets(),
        (IpAddr::V6(v6), _) => b = v6.octets(),
    }
    b
}

fn diag_request(
    family: u8,
    proto: u8,
    states: u32,
    src: Option<(IpAddr, u16)>,
    dst: Option<(IpAddr, u16)>,
) -> Vec<u8> {
    let mut r = Vec::with_capacity(56);
    r.extend_from_slice(&[family, proto, 0, 0]);
    r.extend_from_slice(&states.to_ne_bytes());
    r.extend_from_slice(&src.map_or(0, |s| s.1).to_be_bytes());
    r.extend_from_slice(&dst.map_or(0, |d| d.1).to_be_bytes());
    r.extend_from_slice(&src.map_or([0; 16], |s| ip_bytes(s.0, family)));
    r.extend_from_slice(&dst.map_or([0; 16], |d| ip_bytes(d.0, family)));
    r.extend_from_slice(&0u32.to_ne_bytes()); // interface
    r.extend_from_slice(&NOCOOKIE.to_ne_bytes());
    r.extend_from_slice(&NOCOOKIE.to_ne_bytes());
    r
}

fn parse_diag(b: &[u8]) -> Option<DiagMsg> {
    if b.len() < 72 {
        return None;
    }
    let family = b[0] as i32;
    let addr = |at: usize| -> IpAddr {
        if family == libc::AF_INET {
            IpAddr::V4(std::net::Ipv4Addr::new(
                b[at],
                b[at + 1],
                b[at + 2],
                b[at + 3],
            ))
        } else {
            let a: [u8; 16] = b[at..at + 16].try_into().unwrap();
            canonical_ip(IpAddr::V6(Ipv6Addr::from(a)))
        }
    };
    Some(DiagMsg {
        sport: u16::from_be_bytes([b[4], b[5]]),
        dport: u16::from_be_bytes([b[6], b[7]]),
        src: addr(8),
        dst: addr(24),
        uid: u32::from_ne_bytes(b[64..68].try_into().unwrap()),
        inode: u32::from_ne_bytes(b[68..72].try_into().unwrap()),
    })
}

pub struct Procs {
    diag: Option<Netlink>,
    inode_pid: HashMap<u32, u32>,
    /// Pids that recently owned sockets: scanned first on a cache miss.
    recent: VecDeque<u32>,
    users: HashMap<u32, String>,
    proc_root: PathBuf,
}

impl Procs {
    pub fn new() -> Procs {
        Procs {
            diag: Netlink::open(NETLINK_SOCK_DIAG).ok(),
            inode_pid: HashMap::new(),
            recent: VecDeque::new(),
            users: load_users(),
            proc_root: PathBuf::from("/proc"),
        }
    }

    fn diag(&mut self) -> Option<&mut Netlink> {
        if self.diag.is_none() {
            self.diag = Netlink::open(NETLINK_SOCK_DIAG).ok();
        }
        self.diag.as_mut()
    }

    /// Find the socket for a connection. For outbound traffic local/remote
    /// are source/destination; inbound looks for the listening socket.
    pub fn find_socket(
        &mut self,
        proto: u8,
        direction: Direction,
        local: (IpAddr, u16),
        remote: (IpAddr, u16),
    ) -> Option<SockMatch> {
        let v4 = local.0.is_ipv4();
        let families: &[u8] = if v4 {
            &[libc::AF_INET as u8, libc::AF_INET6 as u8]
        } else {
            &[libc::AF_INET6 as u8]
        };
        // TCP outbound: exact lookup (sockets in SYN_SENT live in the
        // established hash, so the kernel finds them directly).
        if proto == 6 && direction == Direction::Out {
            for &fam in families {
                let req = diag_request(fam, proto, u32::MAX, Some(local), Some(remote));
                if let Ok(msgs) = self.diag()?.request(SOCK_DIAG_BY_FAMILY, 0, &req)
                    && let Some(m) = msgs.first().and_then(|m| parse_diag(m))
                    && m.inode != 0
                {
                    return Some(SockMatch {
                        uid: m.uid,
                        inode: m.inode,
                    });
                }
            }
        }
        // Otherwise dump and pick the best candidate on the local port.
        let states = u32::MAX;
        let local_ip = canonical_ip(local.0);
        let remote_ip = canonical_ip(remote.0);
        let mut best: Option<(u8, SockMatch)> = None;
        for &fam in families {
            let req = diag_request(fam, proto, states, None, None);
            let Ok(msgs) = self.diag()?.request(SOCK_DIAG_BY_FAMILY, NLM_F_DUMP, &req) else {
                continue;
            };
            for m in msgs.iter().filter_map(|m| parse_diag(m)) {
                if m.sport != local.1 || m.inode == 0 {
                    continue;
                }
                let src_ok = m.src.is_unspecified() || m.src == local_ip;
                if !src_ok {
                    continue;
                }
                let connected = m.dport != 0 && !m.dst.is_unspecified();
                let score = if connected {
                    if m.dst == remote_ip && m.dport == remote.1 {
                        3
                    } else {
                        continue;
                    }
                } else if !m.src.is_unspecified() {
                    2
                } else {
                    1
                };
                if best.is_none_or(|(s, _)| score > s) {
                    best = Some((
                        score,
                        SockMatch {
                            uid: m.uid,
                            inode: m.inode,
                        },
                    ));
                }
            }
        }
        best.map(|(_, m)| m)
    }

    fn scan_pid_fds(&mut self, pid: u32, want: u32) -> bool {
        let dir = self.proc_root.join(pid.to_string()).join("fd");
        let Ok(entries) = fs::read_dir(&dir) else {
            return false;
        };
        let mut found = false;
        for e in entries.flatten() {
            let Ok(target) = fs::read_link(e.path()) else {
                continue;
            };
            let t = target.as_os_str().as_encoded_bytes();
            if let Some(num) = t
                .strip_prefix(b"socket:[")
                .and_then(|r| r.strip_suffix(b"]"))
                && let Some(inode) = std::str::from_utf8(num)
                    .ok()
                    .and_then(|s| s.parse::<u32>().ok())
            {
                self.inode_pid.insert(inode, pid);
                if inode == want {
                    found = true;
                }
            }
        }
        found
    }

    fn note_recent(&mut self, pid: u32) {
        self.recent.retain(|&p| p != pid);
        self.recent.push_front(pid);
        self.recent.truncate(24);
    }

    pub fn pid_for_inode(&mut self, inode: u32, uid: Option<u32>) -> Option<u32> {
        if let Some(&pid) = self.inode_pid.get(&inode) {
            if self.proc_root.join(pid.to_string()).exists() {
                self.note_recent(pid);
                return Some(pid);
            }
            self.inode_pid.remove(&inode);
        }
        if self.inode_pid.len() > 200_000 {
            self.inode_pid.clear();
        }
        let recent: Vec<u32> = self.recent.iter().copied().collect();
        for pid in recent {
            if self.scan_pid_fds(pid, inode) {
                self.note_recent(pid);
                return Some(pid);
            }
        }
        let Ok(entries) = fs::read_dir(&self.proc_root) else {
            return None;
        };
        let mut pids: Vec<(u32, u32)> = entries
            .flatten()
            .filter_map(|e| {
                let pid = e.file_name().to_str()?.parse::<u32>().ok()?;
                let owner = e.metadata().ok()?.uid();
                Some((pid, owner))
            })
            .collect();
        // Likely owners first: the socket's user, then root-owned
        // (non-dumpable processes show up as root), newest pids first.
        pids.sort_by_key(|&(pid, owner)| {
            let rank = match uid {
                Some(u) if owner == u => 0,
                _ if owner == 0 => 1,
                _ => 2,
            };
            (rank, std::cmp::Reverse(pid))
        });
        for (pid, _) in pids {
            if self.scan_pid_fds(pid, inode) {
                self.note_recent(pid);
                return Some(pid);
            }
        }
        None
    }

    pub fn user_name(&mut self, uid: u32) -> String {
        if !self.users.contains_key(&uid) {
            self.users = load_users();
        }
        self.users
            .get(&uid)
            .cloned()
            .unwrap_or_else(|| uid.to_string())
    }

    pub fn process_info(&mut self, pid: u32, sock_uid: Option<u32>) -> Option<ProcessInfo> {
        let base = self.proc_root.join(pid.to_string());
        let stat = fs::read_to_string(base.join("stat")).ok()?;
        let after = &stat[stat.rfind(')')? + 2..];
        let fields: Vec<&str> = after.split_whitespace().collect();
        let ppid = fields.get(1)?.parse().ok()?;
        let start_time = fields.get(19)?.parse().ok()?;
        let cmdline: Vec<String> = fs::read(base.join("cmdline"))
            .map(|b| {
                b.split(|&c| c == 0)
                    .filter(|s| !s.is_empty())
                    .map(|s| String::from_utf8_lossy(s).into_owned())
                    .collect()
            })
            .unwrap_or_default();
        let (exe, exe_deleted) = match fs::read_link(base.join("exe")) {
            Ok(p) => {
                let s = p.to_string_lossy().into_owned();
                match s.strip_suffix(" (deleted)") {
                    Some(stripped) => (stripped.to_string(), true),
                    None => (s, false),
                }
            }
            // Kernel threads and some sandboxed processes hide their exe.
            Err(_) => {
                let comm = fs::read_to_string(base.join("comm")).unwrap_or_default();
                (format!("[{}]", comm.trim()), false)
            }
        };
        let uid = sock_uid
            .or_else(|| fs::metadata(&base).ok().map(|m| m.uid()))
            .unwrap_or(0);
        let cwd = fs::read_link(base.join("cwd")).ok();
        let script = script_of(&exe, &cmdline, cwd.as_deref());
        Some(ProcessInfo {
            pid,
            ppid,
            uid,
            user: self.user_name(uid),
            exe,
            script,
            cmdline,
            start_time,
            exe_deleted,
        })
    }

    /// Full pipeline from a 5-tuple to a process (or the kernel pseudo-process).
    pub fn resolve(
        &mut self,
        proto: u8,
        direction: Direction,
        local: (IpAddr, u16),
        remote: (IpAddr, u16),
        queue_uid: Option<u32>,
    ) -> ProcessInfo {
        let sock = self.find_socket(proto, direction, local, remote);
        let uid = sock.map(|s| s.uid).or(queue_uid);
        if let Some(s) = sock
            && let Some(pid) = self.pid_for_inode(s.inode, Some(s.uid))
            && let Some(info) = self.process_info(pid, Some(s.uid))
        {
            return info;
        }
        // No owning process: kernel-originated (WireGuard, NFS, ICMP-ish),
        // or a socket that vanished before we looked.
        let uid = uid.unwrap_or(0);
        ProcessInfo {
            pid: 0,
            uid,
            user: self.user_name(uid),
            exe: KERNEL_IDENTITY.to_string(),
            ..Default::default()
        }
    }

    pub fn alive(&self, pid: u32, start_time: u64) -> bool {
        let Ok(stat) = fs::read_to_string(self.proc_root.join(pid.to_string()).join("stat")) else {
            return false;
        };
        let Some(close) = stat.rfind(')') else {
            return false;
        };
        stat[close + 2..]
            .split_whitespace()
            .nth(19)
            .and_then(|s| s.parse::<u64>().ok())
            == Some(start_time)
    }
}

fn load_users() -> HashMap<u32, String> {
    let mut m = HashMap::new();
    if let Ok(s) = fs::read_to_string("/etc/passwd") {
        for line in s.lines() {
            let f: Vec<&str> = line.split(':').collect();
            if f.len() > 2
                && let Ok(uid) = f[2].parse()
            {
                m.insert(uid, f[0].to_string());
            }
        }
    }
    m
}

const INTERPRETERS: &[&str] = &[
    "python",
    "python2",
    "python3",
    "pypy",
    "pypy3",
    "perl",
    "ruby",
    "node",
    "nodejs",
    "bun",
    "deno",
    "bash",
    "sh",
    "dash",
    "zsh",
    "fish",
    "lua",
    "luajit",
    "php",
    "tclsh",
    "Rscript",
    "osascript",
];

fn is_interpreter(exe: &str) -> bool {
    let base = exe.rsplit('/').next().unwrap_or(exe);
    INTERPRETERS.iter().any(|i| {
        base == *i
            || base.strip_prefix(i).is_some_and(|rest| {
                !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit() || c == '.')
            })
    })
}

/// For interpreters, which script is running? `python3 -m http.server` →
/// "-m http.server", `node ./app.js` → "/abs/app.js", `bash -c ...` → None.
pub fn script_of(exe: &str, cmdline: &[String], cwd: Option<&Path>) -> Option<String> {
    if !is_interpreter(exe) {
        return None;
    }
    let mut args = cmdline.iter().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "-c" | "-e" | "--eval" | "-" => return None,
            "-m" => return args.next().map(|m| format!("-m {m}")),
            // Deno/Bun subcommands: `deno run [flags] script.ts`.
            "run" if exe.ends_with("deno") || exe.ends_with("bun") => continue,
            s if s.starts_with('-') => continue,
            s => {
                let p = Path::new(s);
                let abs = if p.is_absolute() {
                    p.to_path_buf()
                } else {
                    match cwd {
                        Some(c) => c.join(p),
                        None => p.to_path_buf(),
                    }
                };
                return Some(normalize(&abs).to_string_lossy().into_owned());
            }
        }
    }
    None
}

fn normalize(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn interpreter_detection() {
        assert!(is_interpreter("/usr/bin/python3.13"));
        assert!(is_interpreter("/usr/bin/node"));
        assert!(!is_interpreter("/usr/bin/pythonista"));
        assert!(!is_interpreter("/usr/lib/firefox/firefox"));
    }

    #[test]
    fn scripts() {
        let cwd = Path::new("/home/u/proj");
        assert_eq!(
            script_of(
                "/usr/bin/python3",
                &args(&["python3", "-u", "./tools/../sync.py", "x"]),
                Some(cwd)
            )
            .as_deref(),
            Some("/home/u/proj/sync.py")
        );
        assert_eq!(
            script_of(
                "/usr/bin/python3",
                &args(&["python3", "-m", "http.server"]),
                Some(cwd)
            )
            .as_deref(),
            Some("-m http.server")
        );
        assert_eq!(
            script_of("/usr/bin/bash", &args(&["bash", "-c", "curl x"]), Some(cwd)),
            None
        );
        assert_eq!(
            script_of("/usr/bin/curl", &args(&["curl", "x"]), Some(cwd)),
            None
        );
        assert_eq!(
            script_of(
                "/usr/bin/deno",
                &args(&["deno", "run", "-A", "/srv/main.ts"]),
                None
            )
            .as_deref(),
            Some("/srv/main.ts")
        );
    }

    #[test]
    fn diag_request_layout() {
        let r = diag_request(
            libc::AF_INET as u8,
            6,
            u32::MAX,
            Some(("10.0.0.1".parse().unwrap(), 4000)),
            Some(("1.1.1.1".parse().unwrap(), 443)),
        );
        assert_eq!(r.len(), 56);
        assert_eq!(&r[8..10], &4000u16.to_be_bytes());
        assert_eq!(&r[10..12], &443u16.to_be_bytes());
        assert_eq!(&r[12..16], &[10, 0, 0, 1]);
        assert_eq!(&r[28..32], &[1, 1, 1, 1]);
        let r6 = diag_request(
            libc::AF_INET6 as u8,
            6,
            0,
            Some(("10.0.0.1".parse().unwrap(), 1)),
            None,
        );
        assert_eq!(
            &r6[12..28],
            &"::ffff:10.0.0.1".parse::<Ipv6Addr>().unwrap().octets()
        );
    }

    #[test]
    fn finds_own_tcp_socket() {
        // Real kernel round trip: a listening socket and a connection to it.
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let c = std::net::TcpStream::connect(addr).unwrap();
        let local = c.local_addr().unwrap();
        let mut p = Procs::new();
        let m = p
            .find_socket(
                6,
                Direction::Out,
                (local.ip(), local.port()),
                (addr.ip(), addr.port()),
            )
            .expect("socket found");
        let pid = p.pid_for_inode(m.inode, Some(m.uid)).expect("pid found");
        assert_eq!(pid, std::process::id());
        let info = p.process_info(pid, Some(m.uid)).unwrap();
        assert!(info.exe.contains("tattle"), "{}", info.exe);
        assert_eq!(info.uid, unsafe { libc::getuid() });
        // Inbound: the listening socket owns the port.
        let li = p
            .find_socket(
                6,
                Direction::In,
                (addr.ip(), addr.port()),
                (local.ip(), local.port()),
            )
            .expect("listener found");
        assert_eq!(p.pid_for_inode(li.inode, None), Some(std::process::id()));
    }

    #[test]
    fn finds_own_udp_socket() {
        let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let local = s.local_addr().unwrap();
        let mut p = Procs::new();
        let m = p
            .find_socket(
                17,
                Direction::Out,
                (local.ip(), local.port()),
                ("127.0.0.1".parse().unwrap(), 9),
            )
            .expect("udp socket found");
        assert_eq!(
            p.pid_for_inode(m.inode, Some(m.uid)),
            Some(std::process::id())
        );
    }
}
