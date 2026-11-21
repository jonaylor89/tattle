//! Learns which host names map to which addresses by reading DNS answers as
//! they arrive, so alerts and rules can talk about `api.github.com` instead
//! of `140.82.112.5`.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Answers from a single DNS response: (address, names that lead to it).
pub fn parse_response(msg: &[u8]) -> Vec<(IpAddr, Vec<String>, u32)> {
    let mut out = Vec::new();
    if msg.len() < 12 {
        return out;
    }
    let flags = u16::from_be_bytes([msg[2], msg[3]]);
    let is_response = flags & 0x8000 != 0;
    let rcode = flags & 0x000f;
    if !is_response || rcode != 0 {
        return out;
    }
    let qd = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let an = u16::from_be_bytes([msg[6], msg[7]]) as usize;
    let mut off = 12;
    let mut question: Option<String> = None;
    for _ in 0..qd.min(4) {
        let Some((name, next)) = read_name(msg, off) else {
            return out;
        };
        if question.is_none() {
            question = Some(name);
        }
        off = next + 4;
    }
    // owner -> cname target, for walking the chain back to the question.
    let mut cnames: Vec<(String, String)> = Vec::new();
    let mut addrs: Vec<(String, IpAddr, u32)> = Vec::new();
    for _ in 0..an.min(64) {
        let Some((owner, next)) = read_name(msg, off) else {
            break;
        };
        off = next;
        if off + 10 > msg.len() {
            break;
        }
        let rtype = u16::from_be_bytes([msg[off], msg[off + 1]]);
        let ttl = u32::from_be_bytes([msg[off + 4], msg[off + 5], msg[off + 6], msg[off + 7]]);
        let rdlen = u16::from_be_bytes([msg[off + 8], msg[off + 9]]) as usize;
        let rdata = off + 10;
        if rdata + rdlen > msg.len() {
            break;
        }
        match (rtype, rdlen) {
            (1, 4) => {
                let ip = Ipv4Addr::new(msg[rdata], msg[rdata + 1], msg[rdata + 2], msg[rdata + 3]);
                addrs.push((owner, IpAddr::V4(ip), ttl));
            }
            (28, 16) => {
                let b: [u8; 16] = msg[rdata..rdata + 16].try_into().unwrap();
                addrs.push((owner, IpAddr::V6(Ipv6Addr::from(b)), ttl));
            }
            (5, _) => {
                if let Some((target, _)) = read_name(msg, rdata) {
                    cnames.push((owner, target));
                }
            }
            _ => {}
        }
        off = rdata + rdlen;
    }
    for (owner, ip, ttl) in addrs {
        // Names in order of relevance: what the app asked for first, then
        // the CNAME chain, then the final owner name.
        let mut names = Vec::new();
        if let Some(q) = &question {
            names.push(q.clone());
        }
        let mut cur = owner.clone();
        let mut chain = vec![cur.clone()];
        for _ in 0..16 {
            match cnames.iter().find(|(_, t)| *t == cur) {
                Some((o, _)) => {
                    cur = o.clone();
                    chain.push(cur.clone());
                }
                None => break,
            }
        }
        chain.reverse();
        for n in chain {
            if !names.contains(&n) {
                names.push(n);
            }
        }
        // Only trust answers that connect to the question asked; anything
        // else is unsolicited additional data.
        if let Some(q) = &question
            && cur != *q
        {
            continue;
        }
        out.push((ip, names, ttl));
    }
    out
}

fn read_name(msg: &[u8], mut off: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut end: Option<usize> = None;
    let mut jumps = 0;
    loop {
        let len = *msg.get(off)? as usize;
        if len == 0 {
            off += 1;
            break;
        }
        if len & 0xc0 == 0xc0 {
            let ptr = ((len & 0x3f) << 8) | *msg.get(off + 1)? as usize;
            if end.is_none() {
                end = Some(off + 2);
            }
            jumps += 1;
            if jumps > 32 || ptr >= msg.len() {
                return None;
            }
            off = ptr;
            continue;
        }
        if len > 63 {
            return None;
        }
        let label = msg.get(off + 1..off + 1 + len)?;
        labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
        off += 1 + len;
        if labels.len() > 127 {
            return None;
        }
    }
    Some((labels.join("."), end.unwrap_or(off)))
}

struct Entry {
    names: Vec<String>,
    expires: u64,
}

/// Address → recently resolved names.
pub struct DnsCache {
    map: HashMap<IpAddr, Entry>,
    max: usize,
}

/// Apps keep using an address long after its TTL, so names are kept at
/// least this long.
const MIN_KEEP: u64 = 6 * 3600;

impl DnsCache {
    pub fn new(max: usize) -> Self {
        DnsCache {
            map: HashMap::new(),
            max,
        }
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn insert(&mut self, ip: IpAddr, names: Vec<String>, ttl: u32, now: u64) {
        let ip = crate::model::canonical_ip(ip);
        if self.map.len() >= self.max && !self.map.contains_key(&ip) {
            self.prune(now);
            if self.map.len() >= self.max {
                // Still full: drop the entry closest to expiry.
                if let Some(k) = self
                    .map
                    .iter()
                    .min_by_key(|(_, e)| e.expires)
                    .map(|(k, _)| *k)
                {
                    self.map.remove(&k);
                }
            }
        }
        let expires = now + (ttl as u64).max(MIN_KEEP);
        let e = self.map.entry(ip).or_insert(Entry {
            names: Vec::new(),
            expires,
        });
        e.expires = e.expires.max(expires);
        // Newest question first, keep a handful.
        for n in names.into_iter().rev() {
            e.names.retain(|x| *x != n);
            e.names.insert(0, n);
        }
        e.names.truncate(8);
    }

    pub fn lookup(&self, ip: IpAddr) -> Vec<String> {
        let ip = crate::model::canonical_ip(ip);
        self.map
            .get(&ip)
            .map(|e| e.names.clone())
            .unwrap_or_default()
    }

    pub fn prune(&mut self, now: u64) {
        self.map.retain(|_, e| e.expires > now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(n: &str) -> Vec<u8> {
        let mut v = Vec::new();
        for l in n.split('.') {
            v.push(l.len() as u8);
            v.extend_from_slice(l.as_bytes());
        }
        v.push(0);
        v
    }

    fn rr(owner: &[u8], rtype: u16, ttl: u32, rdata: &[u8]) -> Vec<u8> {
        let mut v = owner.to_vec();
        v.extend_from_slice(&rtype.to_be_bytes());
        v.extend_from_slice(&1u16.to_be_bytes());
        v.extend_from_slice(&ttl.to_be_bytes());
        v.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        v.extend_from_slice(rdata);
        v
    }

    #[test]
    fn a_record_with_compression() {
        let mut m = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        m.extend(name("api.github.com"));
        m.extend_from_slice(&[0, 1, 0, 1]);
        m.extend(rr(&[0xc0, 12], 1, 60, &[140, 82, 112, 5]));
        let r = parse_response(&m);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].0, "140.82.112.5".parse::<IpAddr>().unwrap());
        assert_eq!(r[0].1, vec!["api.github.com".to_string()]);
        assert_eq!(r[0].2, 60);
    }

    #[test]
    fn cname_chain_and_aaaa() {
        let mut m = vec![0, 1, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0];
        m.extend(name("www.example.com"));
        m.extend_from_slice(&[0, 28, 0, 1]);
        m.extend(rr(&[0xc0, 12], 5, 300, &name("edge.cdn.net")));
        let v6: Ipv6Addr = "2606:2800::1".parse().unwrap();
        m.extend(rr(&name("edge.cdn.net"), 28, 20, &v6.octets()));
        let r = parse_response(&m);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].0, IpAddr::V6(v6));
        assert_eq!(
            r[0].1,
            vec!["www.example.com".to_string(), "edge.cdn.net".to_string()]
        );
    }

    #[test]
    fn rejects_queries_errors_and_loops() {
        let mut q = vec![0, 1, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        q.extend(name("a.com"));
        assert!(parse_response(&q).is_empty());
        let nx = vec![0, 1, 0x81, 0x83, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(parse_response(&nx).is_empty());
        // Self-referencing compression pointer.
        let mut l = vec![0, 1, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0];
        l.extend_from_slice(&[0xc0, 12]);
        assert!(parse_response(&l).is_empty());
        assert!(parse_response(&[1, 2, 3]).is_empty());
    }

    #[test]
    fn cache_orders_and_expires() {
        let mut c = DnsCache::new(2);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        c.insert(ip, vec!["a.com".into()], 60, 0);
        c.insert(ip, vec!["b.com".into()], 60, 1);
        assert_eq!(c.lookup(ip), vec!["b.com".to_string(), "a.com".to_string()]);
        assert_eq!(
            c.lookup("::ffff:1.2.3.4".parse().unwrap()),
            vec!["b.com".to_string(), "a.com".to_string()]
        );
        c.insert("5.5.5.5".parse().unwrap(), vec!["c.com".into()], 60, 2);
        c.insert("6.6.6.6".parse().unwrap(), vec!["d.com".into()], 60, 3);
        assert_eq!(c.len(), 2);
        c.prune(MIN_KEEP + 100);
        assert_eq!(c.len(), 0);
    }
}
