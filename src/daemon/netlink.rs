//! Tiny raw-netlink client: just enough for sock_diag and ctnetlink.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

pub const NETLINK_SOCK_DIAG: i32 = 4;
pub const NETLINK_NETFILTER: i32 = 12;

const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
pub const NLM_F_REQUEST: u16 = 1;
pub const NLM_F_DUMP: u16 = 0x300;

pub struct Netlink {
    fd: OwnedFd,
    seq: u32,
    buf: Vec<u8>,
}

impl Netlink {
    pub fn open(protocol: i32) -> io::Result<Netlink> {
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                protocol,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let tv = libc::timeval {
            tv_sec: 1,
            tv_usec: 0,
        };
        unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as u32,
            );
            let size: libc::c_int = 1 << 20;
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &size as *const _ as *const libc::c_void,
                4,
            );
        }
        Ok(Netlink {
            fd,
            seq: 1,
            buf: vec![0u8; 1 << 16],
        })
    }

    /// Send one request and collect the payloads of every reply message.
    /// A non-dump request returns after its single answer. `Err(ENOENT)` and
    /// friends come back as io errors.
    pub fn request(
        &mut self,
        msg_type: u16,
        flags: u16,
        payload: &[u8],
    ) -> io::Result<Vec<Vec<u8>>> {
        self.seq = self.seq.wrapping_add(1);
        let seq = self.seq;
        let len = 16 + payload.len();
        let mut msg = Vec::with_capacity(len);
        msg.extend_from_slice(&(len as u32).to_ne_bytes());
        msg.extend_from_slice(&msg_type.to_ne_bytes());
        msg.extend_from_slice(&(flags | NLM_F_REQUEST).to_ne_bytes());
        msg.extend_from_slice(&seq.to_ne_bytes());
        msg.extend_from_slice(&0u32.to_ne_bytes());
        msg.extend_from_slice(payload);
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        let sent = unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                msg.as_ptr() as *const libc::c_void,
                msg.len(),
                0,
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as u32,
            )
        };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
        let dump = flags & NLM_F_DUMP == NLM_F_DUMP;
        let mut out = Vec::new();
        loop {
            let n = unsafe {
                libc::recv(
                    self.fd.as_raw_fd(),
                    self.buf.as_mut_ptr() as *mut libc::c_void,
                    self.buf.len(),
                    0,
                )
            };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            let data = &self.buf[..n as usize];
            let mut off = 0;
            while off + 16 <= data.len() {
                let mlen = u32::from_ne_bytes(data[off..off + 4].try_into().unwrap()) as usize;
                let mtype = u16::from_ne_bytes(data[off + 4..off + 6].try_into().unwrap());
                let mseq = u32::from_ne_bytes(data[off + 8..off + 12].try_into().unwrap());
                if mlen < 16 || off + mlen > data.len() {
                    break;
                }
                let body = &data[off + 16..off + mlen];
                off += (mlen + 3) & !3;
                if mseq != seq {
                    continue; // stale answer to an earlier, timed-out request
                }
                match mtype {
                    NLMSG_DONE => return Ok(out),
                    NLMSG_ERROR => {
                        let errno = body
                            .get(..4)
                            .map(|b| i32::from_ne_bytes(b.try_into().unwrap()))
                            .unwrap_or(0);
                        if errno == 0 {
                            return Ok(out);
                        }
                        return Err(io::Error::from_raw_os_error(-errno));
                    }
                    _ => {
                        out.push(body.to_vec());
                        if !dump {
                            return Ok(out);
                        }
                    }
                }
            }
        }
    }
}

/// Iterate netlink attributes (type with NLA_F_NESTED masked off, payload).
pub fn attrs(mut data: &[u8]) -> impl Iterator<Item = (u16, &[u8])> {
    std::iter::from_fn(move || {
        if data.len() < 4 {
            return None;
        }
        let len = u16::from_ne_bytes([data[0], data[1]]) as usize;
        let ty = u16::from_ne_bytes([data[2], data[3]]) & 0x3fff;
        if len < 4 || len > data.len() {
            return None;
        }
        let payload = &data[4..len];
        let adv = ((len + 3) & !3).min(data.len());
        data = &data[adv..];
        Some((ty, payload))
    })
}
