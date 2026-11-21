//! Rule evaluation.
//!
//! Precedence, strongest first (documented in the README):
//!   1. the more specific *server*: exact host > domain (deeper domain wins)
//!      > IP/network (longer prefix wins) > local network > any server
//!   2. the more specific *port*: one port > a range > any port
//!   3. a specific process beats "any process"
//!   4. a rule for one user beats a rule for every user
//!   5. your own rules beat blocklists and built-in defaults
//!   6. deny beats allow
//!
//! Blocklist entries behave like "deny any process → *.domain" rules.

use crate::model::*;
use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Score {
    remote: u32,
    port: u8,
    process: u8,
    user: u8,
    own: u8,
    deny: u8,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Match {
    pub action: Action,
    pub rule_id: Option<u64>,
    pub blocklist: Option<String>,
    pub score: Score,
}

/// Domains from enabled blocklists, mapped to the list that contributed them.
#[derive(Default, Clone)]
pub struct BlockSet {
    domains: HashMap<String, u16>,
    names: Vec<String>,
}

impl BlockSet {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn len(&self) -> usize {
        self.domains.len()
    }
    pub fn insert_list(&mut self, name: &str, domains: impl IntoIterator<Item = String>) {
        let idx = self.names.len() as u16;
        self.names.push(name.to_string());
        for d in domains {
            self.domains.entry(d).or_insert(idx);
        }
    }
    /// Longest blocked suffix of `host`, as (list name, label count).
    pub fn lookup(&self, host: &str) -> Option<(&str, u32)> {
        let host = host.trim_end_matches('.');
        let mut rest = host;
        loop {
            if let Some(&idx) = self.domains.get(rest) {
                let labels = rest.split('.').count() as u32;
                return Some((&self.names[idx as usize], labels));
            }
            match rest.split_once('.') {
                Some((_, tail)) if tail.contains('.') => rest = tail,
                _ => return None,
            }
        }
    }
}

fn host_in_domain(host: &str, domain: &str) -> bool {
    host == domain
        || (host.len() > domain.len()
            && host.ends_with(domain)
            && host.as_bytes()[host.len() - domain.len() - 1] == b'.')
}

fn remote_score(remote: &Remote, ip: IpAddr, hosts: &[String]) -> Option<u32> {
    match remote {
        Remote::Any => Some(0),
        Remote::Local => is_local_ip(ip).then_some(1000),
        Remote::Ip(net) => {
            let net: IpNet = net.parse().ok()?;
            net.contains(ip).then_some(2000 + net.prefix as u32)
        }
        Remote::Domain(d) => hosts
            .iter()
            .any(|h| host_in_domain(h, d))
            .then(|| 3000 + d.split('.').count() as u32),
        Remote::Host(h) => hosts.iter().any(|x| x == h).then_some(4000),
    }
}

/// Does `rule` apply to `conn`? Returns its precedence score when it does.
pub fn rule_score(
    rule: &Rule,
    conn: &Connection,
    active_profile: Option<&str>,
    now: u64,
) -> Option<Score> {
    if !rule.enabled || rule.direction != conn.direction || !rule.proto.matches(conn.proto) {
        return None;
    }
    if let Some(p) = &rule.profile
        && active_profile != Some(p.as_str())
    {
        return None;
    }
    if let Lifetime::Until { at } = rule.lifetime
        && now >= at
    {
        return None;
    }
    if let Lifetime::UntilQuit { pid, start_time } = rule.lifetime {
        // The rule is bound to one process instance.
        if conn.process.pid != pid || conn.process.start_time != start_time {
            return None;
        }
    }
    let process = if rule.is_any_process() {
        0
    } else if rule.process == conn.identity() {
        1
    } else {
        return None;
    };
    let user = match rule.uid {
        None => 0,
        Some(uid) if uid == conn.process.uid => 1,
        Some(_) => return None,
    };
    let port_of_interest = match conn.direction {
        Direction::Out => conn.remote_port,
        Direction::In => conn.local_port,
    };
    let port = match rule.port {
        None => 0,
        Some(r) if r.contains(port_of_interest) => {
            if r.lo == r.hi {
                2
            } else {
                1
            }
        }
        Some(_) => return None,
    };
    let remote = remote_score(&rule.remote, conn.remote_ip, &conn.hostnames)?;
    Some(Score {
        remote,
        port,
        process,
        user,
        own: (rule.source == RuleSource::User) as u8,
        deny: (rule.action == Action::Deny) as u8,
    })
}

/// Find the winning rule (or blocklist entry) for a connection.
pub fn evaluate(
    rules: &[Rule],
    blocks: &BlockSet,
    conn: &Connection,
    active_profile: Option<&str>,
    now: u64,
) -> Option<Match> {
    let mut best: Option<Match> = None;
    for rule in rules {
        if let Some(score) = rule_score(rule, conn, active_profile, now)
            && best.as_ref().is_none_or(|b| score > b.score)
        {
            best = Some(Match {
                action: rule.action,
                rule_id: Some(rule.id),
                blocklist: None,
                score,
            });
        }
    }
    if conn.direction == Direction::Out {
        for host in &conn.hostnames {
            if let Some((list, labels)) = blocks.lookup(host) {
                let score = Score {
                    remote: 3000 + labels,
                    port: 0,
                    process: 0,
                    user: 0,
                    own: 0,
                    deny: 1,
                };
                if best.as_ref().is_none_or(|b| score > b.score) {
                    best = Some(Match {
                        action: Action::Deny,
                        rule_id: None,
                        blocklist: Some(list.to_string()),
                        score,
                    });
                }
            }
        }
    }
    best
}

/// Turn an alert answer into a rule (None for "once").
pub fn rule_from_decision(
    prompt: &Prompt,
    d: &Decision,
    active_profile: Option<&str>,
    now: u64,
) -> Option<Rule> {
    let lifetime = match d.lifetime {
        DecisionLifetime::Once => return None,
        DecisionLifetime::Forever => Lifetime::Forever,
        DecisionLifetime::UntilQuit => Lifetime::UntilQuit {
            pid: prompt.conn.process.pid,
            start_time: prompt.conn.process.start_time,
        },
        DecisionLifetime::For(secs) => Lifetime::Until {
            at: now + secs.max(1),
        },
    };
    let conn = &prompt.conn;
    let known_host = conn.hostnames.first().cloned();
    let remote = match d.remote {
        RemoteScope::Any => Remote::Any,
        RemoteScope::Ip => Remote::Ip(canonical_ip(conn.remote_ip).to_string()),
        RemoteScope::Domain => match prompt.domain.clone() {
            Some(dom) => Remote::Domain(dom),
            None => match known_host {
                Some(h) => Remote::Host(h),
                None => Remote::Ip(canonical_ip(conn.remote_ip).to_string()),
            },
        },
        RemoteScope::Host => match known_host {
            Some(h) => Remote::Host(h),
            None => Remote::Ip(canonical_ip(conn.remote_ip).to_string()),
        },
    };
    let port = if d.port_only {
        Some(PortRange::single(match conn.direction {
            Direction::Out => conn.remote_port,
            Direction::In => conn.local_port,
        }))
    } else {
        None
    };
    let mut rule = Rule::new(
        d.action,
        if d.any_process {
            ANY_PROCESS.to_string()
        } else {
            conn.identity()
        },
        remote,
    );
    rule.direction = conn.direction;
    rule.port = port;
    rule.proto = if d.port_only { conn.proto } else { Proto::Any };
    rule.lifetime = lifetime;
    rule.profile = if d.in_profile {
        active_profile.map(str::to_string)
    } else {
        None
    };
    rule.created = now;
    Some(rule)
}

/// Rules that keep a stock Omarchy/Arch system online out of the box.
pub fn default_rules() -> Vec<Rule> {
    let mut out = Vec::new();
    let mut add = |process: &str, remote: Remote, proto: Proto, port: Option<u16>, note: &str| {
        let mut r = Rule::new(Action::Allow, process, remote);
        r.proto = proto;
        r.port = port.map(PortRange::single);
        r.note = note.into();
        r.source = RuleSource::Default;
        out.push(r);
    };
    add(
        "/usr/lib/systemd/systemd-resolved",
        Remote::Any,
        Proto::Any,
        Some(53),
        "DNS resolver",
    );
    add(
        "/usr/lib/systemd/systemd-resolved",
        Remote::Any,
        Proto::Tcp,
        Some(853),
        "DNS over TLS",
    );
    add(
        "/usr/lib/systemd/systemd-resolved",
        Remote::Local,
        Proto::Udp,
        Some(5355),
        "LLMNR",
    );
    add(
        "/usr/lib/systemd/systemd-timesyncd",
        Remote::Any,
        Proto::Udp,
        Some(123),
        "Time sync",
    );
    add(
        "/usr/bin/chronyd",
        Remote::Any,
        Proto::Udp,
        Some(123),
        "Time sync",
    );
    add(
        "/usr/bin/NetworkManager",
        Remote::Any,
        Proto::Udp,
        Some(67),
        "DHCP",
    );
    add(
        "/usr/bin/NetworkManager",
        Remote::Any,
        Proto::Udp,
        Some(547),
        "DHCPv6",
    );
    add(
        "/usr/lib/iwd/iwd",
        Remote::Any,
        Proto::Udp,
        Some(67),
        "DHCP",
    );
    add("/usr/bin/dhcpcd", Remote::Any, Proto::Udp, Some(67), "DHCP");
    add(
        "/usr/bin/dhcpcd",
        Remote::Any,
        Proto::Udp,
        Some(547),
        "DHCPv6",
    );
    add(
        "/usr/lib/systemd/systemd-networkd",
        Remote::Any,
        Proto::Udp,
        Some(67),
        "DHCP",
    );
    add(
        "/usr/bin/avahi-daemon",
        Remote::Local,
        Proto::Udp,
        Some(5353),
        "mDNS",
    );
    add(
        KERNEL_IDENTITY,
        Remote::Any,
        Proto::Any,
        None,
        "Kernel traffic (WireGuard, NFS, ICMP replies)",
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn(exe: &str, host: &str, ip: &str, port: u16) -> Connection {
        Connection {
            direction: Direction::Out,
            proto: Proto::Tcp,
            local_ip: "192.168.1.10".parse().unwrap(),
            local_port: 50000,
            remote_ip: ip.parse().unwrap(),
            remote_port: port,
            hostnames: if host.is_empty() {
                vec![]
            } else {
                vec![host.to_string()]
            },
            process: ProcessInfo {
                pid: 42,
                uid: 1000,
                exe: exe.into(),
                start_time: 7,
                ..Default::default()
            },
        }
    }

    fn rule(id: u64, action: Action, process: &str, remote: Remote, port: Option<u16>) -> Rule {
        let mut r = Rule::new(action, process, remote);
        r.id = id;
        r.port = port.map(PortRange::single);
        r
    }

    const FF: &str = "/usr/lib/firefox/firefox";

    fn eval(rules: &[Rule], c: &Connection) -> Option<Match> {
        evaluate(rules, &BlockSet::new(), c, None, 100)
    }

    #[test]
    fn no_rules_no_match() {
        assert_eq!(eval(&[], &conn(FF, "a.com", "1.1.1.1", 443)), None);
    }

    #[test]
    fn host_beats_domain_beats_any() {
        let rules = vec![
            rule(1, Action::Deny, FF, Remote::Any, None),
            rule(
                2,
                Action::Allow,
                FF,
                Remote::Domain("github.com".into()),
                None,
            ),
            rule(
                3,
                Action::Deny,
                FF,
                Remote::Host("evil.github.com".into()),
                None,
            ),
        ];
        let m = eval(&rules, &conn(FF, "api.github.com", "1.2.3.4", 443)).unwrap();
        assert_eq!((m.action, m.rule_id), (Action::Allow, Some(2)));
        let m = eval(&rules, &conn(FF, "evil.github.com", "1.2.3.4", 443)).unwrap();
        assert_eq!((m.action, m.rule_id), (Action::Deny, Some(3)));
        let m = eval(&rules, &conn(FF, "example.org", "1.2.3.4", 443)).unwrap();
        assert_eq!((m.action, m.rule_id), (Action::Deny, Some(1)));
    }

    #[test]
    fn domain_matching_respects_label_boundary() {
        let rules = vec![rule(
            1,
            Action::Allow,
            FF,
            Remote::Domain("hub.com".into()),
            None,
        )];
        assert!(eval(&rules, &conn(FF, "github.com", "1.2.3.4", 443)).is_none());
        assert!(eval(&rules, &conn(FF, "hub.com", "1.2.3.4", 443)).is_some());
        assert!(eval(&rules, &conn(FF, "x.hub.com", "1.2.3.4", 443)).is_some());
    }

    #[test]
    fn deeper_domain_wins() {
        let rules = vec![
            rule(
                1,
                Action::Allow,
                FF,
                Remote::Domain("google.com".into()),
                None,
            ),
            rule(
                2,
                Action::Deny,
                FF,
                Remote::Domain("ads.google.com".into()),
                None,
            ),
        ];
        let m = eval(&rules, &conn(FF, "x.ads.google.com", "1.2.3.4", 443)).unwrap();
        assert_eq!(m.rule_id, Some(2));
    }

    #[test]
    fn port_specific_beats_any_port_and_deny_wins_ties() {
        let rules = vec![
            rule(1, Action::Allow, FF, Remote::Any, None),
            rule(2, Action::Deny, FF, Remote::Any, Some(80)),
        ];
        assert_eq!(
            eval(&rules, &conn(FF, "a.com", "1.1.1.1", 80))
                .unwrap()
                .rule_id,
            Some(2)
        );
        assert_eq!(
            eval(&rules, &conn(FF, "a.com", "1.1.1.1", 443))
                .unwrap()
                .rule_id,
            Some(1)
        );
        let tie = vec![
            rule(1, Action::Allow, FF, Remote::Any, None),
            rule(2, Action::Deny, FF, Remote::Any, None),
        ];
        assert_eq!(
            eval(&tie, &conn(FF, "a.com", "1.1.1.1", 443))
                .unwrap()
                .action,
            Action::Deny
        );
    }

    #[test]
    fn specific_process_beats_any_process_at_same_server() {
        let rules = vec![
            rule(
                1,
                Action::Deny,
                ANY_PROCESS,
                Remote::Host("a.com".into()),
                None,
            ),
            rule(2, Action::Allow, FF, Remote::Host("a.com".into()), None),
        ];
        assert_eq!(
            eval(&rules, &conn(FF, "a.com", "1.1.1.1", 443))
                .unwrap()
                .rule_id,
            Some(2)
        );
        assert_eq!(
            eval(&rules, &conn("/usr/bin/curl", "a.com", "1.1.1.1", 443))
                .unwrap()
                .rule_id,
            Some(1)
        );
    }

    #[test]
    fn server_specificity_outranks_process_specificity() {
        // "deny everything to tracker.com" still applies to firefox even
        // though firefox has an allow-any rule.
        let rules = vec![
            rule(1, Action::Allow, FF, Remote::Any, None),
            rule(
                2,
                Action::Deny,
                ANY_PROCESS,
                Remote::Domain("tracker.com".into()),
                None,
            ),
        ];
        assert_eq!(
            eval(&rules, &conn(FF, "t.tracker.com", "1.1.1.1", 443))
                .unwrap()
                .rule_id,
            Some(2)
        );
    }

    #[test]
    fn ip_rules_and_prefix_length() {
        let rules = vec![
            rule(1, Action::Allow, FF, Remote::Ip("10.0.0.0/8".into()), None),
            rule(2, Action::Deny, FF, Remote::Ip("10.1.0.0/16".into()), None),
        ];
        assert_eq!(
            eval(&rules, &conn(FF, "", "10.1.2.3", 22)).unwrap().rule_id,
            Some(2)
        );
        assert_eq!(
            eval(&rules, &conn(FF, "", "10.2.2.3", 22)).unwrap().rule_id,
            Some(1)
        );
        assert!(eval(&rules, &conn(FF, "", "11.0.0.1", 22)).is_none());
    }

    #[test]
    fn local_network_rule() {
        let rules = vec![rule(1, Action::Allow, FF, Remote::Local, None)];
        assert!(eval(&rules, &conn(FF, "", "192.168.0.5", 8080)).is_some());
        assert!(eval(&rules, &conn(FF, "", "8.8.8.8", 8080)).is_none());
    }

    #[test]
    fn disabled_expired_and_profile_rules() {
        let mut r1 = rule(1, Action::Allow, FF, Remote::Any, None);
        r1.enabled = false;
        let mut r2 = rule(2, Action::Allow, FF, Remote::Any, None);
        r2.lifetime = Lifetime::Until { at: 50 };
        let mut r3 = rule(3, Action::Allow, FF, Remote::Any, None);
        r3.profile = Some("Work".into());
        let c = conn(FF, "a.com", "1.1.1.1", 443);
        assert!(evaluate(&[r1, r2, r3.clone()], &BlockSet::new(), &c, None, 100).is_none());
        assert_eq!(
            evaluate(&[r3], &BlockSet::new(), &c, Some("Work"), 100)
                .unwrap()
                .rule_id,
            Some(3)
        );
    }

    #[test]
    fn until_quit_binds_to_process_instance() {
        let mut r = rule(1, Action::Allow, FF, Remote::Any, None);
        r.lifetime = Lifetime::UntilQuit {
            pid: 42,
            start_time: 7,
        };
        let mut c = conn(FF, "a.com", "1.1.1.1", 443);
        assert!(eval(&[r.clone()], &c).is_some());
        c.process.start_time = 8; // pid reused by a new process
        assert!(eval(&[r], &c).is_none());
    }

    #[test]
    fn uid_and_direction_and_proto() {
        let mut r = rule(1, Action::Allow, FF, Remote::Any, None);
        r.uid = Some(1001);
        assert!(eval(&[r], &conn(FF, "a.com", "1.1.1.1", 443)).is_none());
        let mut r = rule(1, Action::Allow, FF, Remote::Any, None);
        r.direction = Direction::In;
        assert!(eval(&[r], &conn(FF, "a.com", "1.1.1.1", 443)).is_none());
        let mut r = rule(1, Action::Allow, FF, Remote::Any, None);
        r.proto = Proto::Udp;
        assert!(eval(&[r], &conn(FF, "a.com", "1.1.1.1", 443)).is_none());
    }

    #[test]
    fn blocklists() {
        let mut b = BlockSet::new();
        b.insert_list("ads", vec!["doubleclick.net".to_string()]);
        let c = conn(FF, "stats.g.doubleclick.net", "1.1.1.1", 443);
        let m = evaluate(&[], &b, &c, None, 0).unwrap();
        assert_eq!(
            (m.action, m.blocklist.as_deref()),
            (Action::Deny, Some("ads"))
        );
        // Firefox allowed everywhere: the blocklist still wins (more specific server).
        let rules = vec![rule(1, Action::Allow, FF, Remote::Any, None)];
        assert_eq!(
            evaluate(&rules, &b, &c, None, 0).unwrap().action,
            Action::Deny
        );
        // An explicit allow for that domain beats the list.
        let rules = vec![rule(
            1,
            Action::Allow,
            ANY_PROCESS,
            Remote::Domain("doubleclick.net".into()),
            None,
        )];
        assert_eq!(
            evaluate(&rules, &b, &c, None, 0).unwrap().action,
            Action::Allow
        );
        assert!(b.lookup("notdoubleclick.net").is_none());
    }

    #[test]
    fn decision_to_rule() {
        let p = Prompt {
            id: 1,
            conn: conn(FF, "api.github.com", "140.82.1.1", 443),
            created: 0,
            deadline: 60,
            attempts: 1,
            domain: Some("github.com".into()),
            service: Some("https".into()),
            geo: None,
        };
        let d = Decision {
            action: Action::Allow,
            remote: RemoteScope::Domain,
            port_only: true,
            any_process: false,
            lifetime: DecisionLifetime::Forever,
            in_profile: false,
        };
        let r = rule_from_decision(&p, &d, None, 10).unwrap();
        assert_eq!(r.remote, Remote::Domain("github.com".into()));
        assert_eq!(r.port, Some(PortRange::single(443)));
        assert_eq!(r.proto, Proto::Tcp);
        assert_eq!(r.process, FF);
        let once = Decision {
            lifetime: DecisionLifetime::Once,
            ..d.clone()
        };
        assert!(rule_from_decision(&p, &once, None, 10).is_none());
        // The rule must match the connection it was made for.
        let mut r = r;
        r.id = 9;
        assert_eq!(eval(&[r], &p.conn).unwrap().rule_id, Some(9));
    }
}
