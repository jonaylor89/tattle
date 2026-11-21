//! Minimal IPv4/IPv6 + TCP/UDP header parsing for queued packets.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, PartialEq)]
pub struct Packet<'a> {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub proto: u8,
    pub sport: u16,
    pub dport: u16,
    pub tcp_flags: u8,
    pub payload: &'a [u8],
}

pub const TCP: u8 = 6;
pub const UDP: u8 = 17;
#[cfg(test)]
pub const TCP_SYN: u8 = 0x02;

fn be16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(at)?, *b.get(at + 1)?]))
}

pub fn parse(data: &[u8]) -> Option<Packet<'_>> {
    let version = data.first()? >> 4;
    let (src, dst, proto, l4) = match version {
        4 => {
            let ihl = ((data[0] & 0x0f) as usize) * 4;
            if ihl < 20 || data.len() < ihl {
                return None;
            }
            // Non-first fragments carry no transport header.
            let frag = be16(data, 6)? & 0x1fff;
            if frag != 0 {
                return None;
            }
            let src = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
            let dst = Ipv4Addr::new(data[16], data[17], data[18], data[19]);
            (IpAddr::V4(src), IpAddr::V4(dst), data[9], &data[ihl..])
        }
        6 => {
            if data.len() < 40 {
                return None;
            }
            let src: [u8; 16] = data[8..24].try_into().ok()?;
            let dst: [u8; 16] = data[24..40].try_into().ok()?;
            let mut next = data[6];
            let mut off = 40;
            // Walk extension headers to the transport header.
            loop {
                match next {
                    0 | 43 | 60 => {
                        let len = (*data.get(off + 1)? as usize + 1) * 8;
                        next = *data.get(off)?;
                        off += len;
                    }
                    44 => {
                        let frag = be16(data, off + 2)? >> 3;
                        if frag != 0 {
                            return None;
                        }
                        next = *data.get(off)?;
                        off += 8;
                    }
                    _ => break,
                }
                if off > data.len() {
                    return None;
                }
            }
            (
                IpAddr::V6(Ipv6Addr::from(src)),
                IpAddr::V6(Ipv6Addr::from(dst)),
                next,
                &data[off..],
            )
        }
        _ => return None,
    };
    match proto {
        TCP => {
            let doff = ((*l4.get(12)? >> 4) as usize) * 4;
            Some(Packet {
                src,
                dst,
                proto,
                sport: be16(l4, 0)?,
                dport: be16(l4, 2)?,
                tcp_flags: *l4.get(13)?,
                payload: l4.get(doff.max(20)..).unwrap_or(&[]),
            })
        }
        UDP => Some(Packet {
            src,
            dst,
            proto,
            sport: be16(l4, 0)?,
            dport: be16(l4, 2)?,
            tcp_flags: 0,
            payload: l4.get(8..).unwrap_or(&[]),
        }),
        _ => None,
    }
}

#[cfg(test)]
pub fn build_v4_udp(src: [u8; 4], sport: u16, dst: [u8; 4], dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut p = vec![0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, UDP, 0, 0];
    p.extend_from_slice(&src);
    p.extend_from_slice(&dst);
    let total = (20 + 8 + payload.len()) as u16;
    p[2..4].copy_from_slice(&total.to_be_bytes());
    p.extend_from_slice(&sport.to_be_bytes());
    p.extend_from_slice(&dport.to_be_bytes());
    p.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    p.extend_from_slice(&[0, 0]);
    p.extend_from_slice(payload);
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_udp() {
        let pkt = build_v4_udp([10, 0, 0, 1], 5000, [1, 1, 1, 1], 53, b"hi");
        let p = parse(&pkt).unwrap();
        assert_eq!(p.src, "10.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(p.dst, "1.1.1.1".parse::<IpAddr>().unwrap());
        assert_eq!(
            (p.proto, p.sport, p.dport, p.payload),
            (UDP, 5000, 53, &b"hi"[..])
        );
    }

    #[test]
    fn ipv4_tcp_syn() {
        let mut pkt = vec![
            0x45, 0, 0, 40, 0, 0, 0x40, 0, 64, TCP, 0, 0, 192, 168, 1, 2, 93, 184, 216, 34,
        ];
        let mut tcp = vec![0u8; 20];
        tcp[0..2].copy_from_slice(&40000u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&443u16.to_be_bytes());
        tcp[12] = 5 << 4;
        tcp[13] = TCP_SYN;
        pkt.extend(tcp);
        let p = parse(&pkt).unwrap();
        assert_eq!((p.sport, p.dport, p.tcp_flags), (40000, 443, TCP_SYN));
    }

    #[test]
    fn ipv6_with_hop_by_hop() {
        let mut pkt = vec![0x60, 0, 0, 0, 0, 16, 0 /* hop-by-hop */, 64];
        pkt.extend_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        pkt.extend_from_slice(&"2606:4700::1111".parse::<Ipv6Addr>().unwrap().octets());
        pkt.extend_from_slice(&[UDP, 0, 0, 0, 0, 0, 0, 0]); // ext header, 8 bytes
        pkt.extend_from_slice(&[0x13, 0x88, 0x00, 0x35, 0, 8, 0, 0]);
        let p = parse(&pkt).unwrap();
        assert_eq!((p.proto, p.sport, p.dport), (UDP, 5000, 53));
    }

    #[test]
    fn garbage() {
        assert!(parse(&[]).is_none());
        assert!(parse(&[0x45, 0, 0]).is_none());
        assert!(parse(&[0x60; 10]).is_none());
    }
}
