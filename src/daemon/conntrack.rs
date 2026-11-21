//! Per-flow byte counters from the kernel's connection tracker (ctnetlink),
//! so traffic can be attributed to the app that opened each flow.

use super::netlink::{NETLINK_NETFILTER, NLM_F_DUMP, Netlink, attrs};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const NFNL_SUBSYS_CTNETLINK: u16 = 1;
const IPCTNL_MSG_CT_GET: u16 = 1;

const CTA_TUPLE_ORIG: u16 = 1;
const CTA_COUNTERS_ORIG: u16 = 9;
const CTA_COUNTERS_REPLY: u16 = 10;
const CTA_TUPLE_IP: u16 = 1;
const CTA_TUPLE_PROTO: u16 = 2;
const CTA_IP_V4_SRC: u16 = 1;
const CTA_IP_V4_DST: u16 = 2;
const CTA_IP_V6_SRC: u16 = 3;
const CTA_IP_V6_DST: u16 = 4;
const CTA_PROTO_NUM: u16 = 1;
const CTA_PROTO_SRC_PORT: u16 = 2;
const CTA_PROTO_DST_PORT: u16 = 3;
const CTA_COUNTERS_BYTES: u16 = 2;
const CTA_PROTOINFO: u16 = 4;
const CTA_PROTOINFO_TCP: u16 = 1;
const CTA_PROTOINFO_TCP_STATE: u16 = 1;
/// TCP conntrack states SYN_SENT(1) through LAST_ACK(6) are live;
/// TIME_WAIT(7), CLOSE(8) and later are not.
fn tcp_state_open(state: u8) -> bool {
    (1..=6).contains(&state)
}

/// Original-direction tuple of a tracked flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub proto: u8,
    pub src: IpAddr,
    pub sport: u16,
    pub dst: IpAddr,
    pub dport: u16,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Flow {
    pub key: FlowKey,
    /// Bytes in the original direction (initiator → responder).
    pub orig_bytes: u64,
    pub reply_bytes: u64,
    /// Still carrying traffic (TCP not yet closing or in TIME_WAIT).
    pub open: bool,
}

pub struct Conntrack {
    nl: Netlink,
}

impl Conntrack {
    pub fn open() -> io::Result<Conntrack> {
        Ok(Conntrack {
            nl: Netlink::open(NETLINK_NETFILTER)?,
        })
    }

    pub fn dump(&mut self) -> io::Result<Vec<Flow>> {
        // nfgenmsg: family AF_UNSPEC dumps both IPv4 and IPv6.
        let req = [libc::AF_UNSPEC as u8, 0, 0, 0];
        let msgs = self.nl.request(
            (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_GET,
            NLM_F_DUMP,
            &req,
        )?;
        Ok(msgs
            .iter()
            .filter_map(|m| parse_flow(m.get(4..)?))
            .collect())
    }
}

/// Make sure the kernel counts bytes per flow (off by default on Arch).
pub fn enable_accounting() {
    let _ = std::fs::write("/proc/sys/net/netfilter/nf_conntrack_acct", "1");
}

fn be64(b: &[u8]) -> Option<u64> {
    Some(u64::from_be_bytes(b.get(..8)?.try_into().ok()?))
}

fn parse_flow(body: &[u8]) -> Option<Flow> {
    let mut key: Option<FlowKey> = None;
    let mut orig = 0;
    let mut reply = 0;
    let mut open = true;
    for (ty, payload) in attrs(body) {
        match ty {
            CTA_TUPLE_ORIG => key = parse_tuple(payload),
            CTA_PROTOINFO => {
                for (pty, pp) in attrs(payload) {
                    if pty == CTA_PROTOINFO_TCP {
                        for (tty, tp) in attrs(pp) {
                            if tty == CTA_PROTOINFO_TCP_STATE
                                && let Some(&st) = tp.first()
                            {
                                open = tcp_state_open(st);
                            }
                        }
                    }
                }
            }
            CTA_COUNTERS_ORIG | CTA_COUNTERS_REPLY => {
                for (cty, cp) in attrs(payload) {
                    if cty == CTA_COUNTERS_BYTES {
                        let v = be64(cp).unwrap_or(0);
                        if ty == CTA_COUNTERS_ORIG {
                            orig = v
                        } else {
                            reply = v
                        }
                    }
                }
            }
            _ => {}
        }
    }
    Some(Flow {
        key: key?,
        orig_bytes: orig,
        reply_bytes: reply,
        open,
    })
}

fn parse_tuple(t: &[u8]) -> Option<FlowKey> {
    let (mut src, mut dst, mut proto, mut sport, mut dport) = (None, None, 0u8, 0u16, 0u16);
    for (ty, p) in attrs(t) {
        match ty {
            CTA_TUPLE_IP => {
                for (ity, ip) in attrs(p) {
                    let addr = match ity {
                        CTA_IP_V4_SRC | CTA_IP_V4_DST if ip.len() >= 4 => {
                            Some(IpAddr::V4(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])))
                        }
                        CTA_IP_V6_SRC | CTA_IP_V6_DST if ip.len() >= 16 => {
                            let a: [u8; 16] = ip[..16].try_into().ok()?;
                            Some(IpAddr::V6(Ipv6Addr::from(a)))
                        }
                        _ => None,
                    };
                    match ity {
                        CTA_IP_V4_SRC | CTA_IP_V6_SRC => src = addr,
                        CTA_IP_V4_DST | CTA_IP_V6_DST => dst = addr,
                        _ => {}
                    }
                }
            }
            CTA_TUPLE_PROTO => {
                for (pty, pp) in attrs(p) {
                    match pty {
                        CTA_PROTO_NUM => proto = *pp.first()?,
                        CTA_PROTO_SRC_PORT if pp.len() >= 2 => {
                            sport = u16::from_be_bytes([pp[0], pp[1]])
                        }
                        CTA_PROTO_DST_PORT if pp.len() >= 2 => {
                            dport = u16::from_be_bytes([pp[0], pp[1]])
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    Some(FlowKey {
        proto,
        src: src?,
        sport,
        dst: dst?,
        dport,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nla(ty: u16, payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&((4 + payload.len()) as u16).to_ne_bytes());
        v.extend_from_slice(&ty.to_ne_bytes());
        v.extend_from_slice(payload);
        while v.len() % 4 != 0 {
            v.push(0);
        }
        v
    }

    #[test]
    fn parses_nested_flow() {
        let nested = 0x8000;
        let ip = [
            nla(CTA_IP_V4_SRC, &[10, 0, 0, 2]),
            nla(CTA_IP_V4_DST, &[1, 1, 1, 1]),
        ]
        .concat();
        let proto = [
            nla(CTA_PROTO_NUM, &[6]),
            nla(CTA_PROTO_SRC_PORT, &40000u16.to_be_bytes()),
            nla(CTA_PROTO_DST_PORT, &443u16.to_be_bytes()),
        ]
        .concat();
        let tuple = [
            nla(CTA_TUPLE_IP | nested, &ip),
            nla(CTA_TUPLE_PROTO | nested, &proto),
        ]
        .concat();
        let body = [
            nla(CTA_TUPLE_ORIG | nested, &tuple),
            nla(
                CTA_COUNTERS_ORIG | nested,
                &nla(CTA_COUNTERS_BYTES, &1234u64.to_be_bytes()),
            ),
            nla(
                CTA_COUNTERS_REPLY | nested,
                &nla(CTA_COUNTERS_BYTES, &98765u64.to_be_bytes()),
            ),
            nla(
                CTA_PROTOINFO | nested,
                &nla(
                    CTA_PROTOINFO_TCP | nested,
                    &nla(CTA_PROTOINFO_TCP_STATE, &[7]),
                ),
            ),
        ]
        .concat();
        let f = parse_flow(&body).unwrap();
        assert_eq!(f.key.proto, 6);
        assert_eq!(f.key.src, "10.0.0.2".parse::<IpAddr>().unwrap());
        assert_eq!((f.key.sport, f.key.dport), (40000, 443));
        assert_eq!((f.orig_bytes, f.reply_bytes), (1234, 98765));
        assert!(!f.open, "TIME_WAIT is not a live connection");
    }
}
