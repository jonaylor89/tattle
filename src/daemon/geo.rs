//! Offline IP geolocation for the map and alerts.
//!
//! Lookups never leave this machine: they read a MaxMind-format database
//! (DB-IP Lite or GeoLite2) from disk. The only network access is the opt-in
//! download of DB-IP's free database, which the user starts explicitly.

use super::core::{Core, log};
use crate::model::*;
use anyhow::{Context, Result, bail};
use maxminddb::{Mmap, Reader, geoip2};
use std::collections::HashMap;
use std::fs;
use std::io::{self, Read};
use std::net::IpAddr;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

pub const CITY_FILE: &str = "city.mmdb";
pub const ASN_FILE: &str = "asn.mmdb";
const CACHE_CAP: usize = 65_536;
/// DB-IP City Lite is ~130 MB unpacked; leave room for growth, not abuse.
const MAX_DB_BYTES: u64 = 600 << 20;

/// Databases other tools may have installed (geoipupdate, distro packages).
const SYSTEM_CITY: &[&str] = &[
    "/usr/share/GeoIP/GeoLite2-City.mmdb",
    "/var/lib/GeoIP/GeoLite2-City.mmdb",
    "/usr/share/GeoIP/GeoIP2-City.mmdb",
    "/var/lib/GeoIP/GeoIP2-City.mmdb",
    "/usr/share/GeoIP/dbip-city-lite.mmdb",
];
const SYSTEM_ASN: &[&str] = &[
    "/usr/share/GeoIP/GeoLite2-ASN.mmdb",
    "/var/lib/GeoIP/GeoLite2-ASN.mmdb",
    "/usr/share/GeoIP/dbip-asn-lite.mmdb",
];

/// Identifies one version of a file, so replacing it is noticed.
type Stamp = (u64, u64, i64);

struct Db {
    reader: Reader<Mmap>,
    path: PathBuf,
    stamp: Stamp,
}

fn stamp(path: &Path) -> Option<Stamp> {
    let m = fs::metadata(path).ok()?;
    m.is_file().then(|| (m.dev(), m.ino(), m.mtime()))
}

fn open(path: &Path, want: &str) -> Result<Db> {
    let stamp = stamp(path).context("not a file")?;
    // SAFETY: the map is read-only. Tattle replaces its own databases by
    // renaming a new file into place, which leaves this mapping intact, and
    // package managers and geoipupdate do the same.
    let reader = unsafe { Reader::open_mmap(path) }?;
    let kind = &reader.metadata().database_type;
    if !kind.to_ascii_lowercase().contains(want) {
        bail!("{} is a {kind} database, not a {want} one", path.display());
    }
    Ok(Db {
        reader,
        path: path.to_path_buf(),
        stamp,
    })
}

/// Database text is data from the internet: keep it short and printable.
fn clean(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(80).collect()
}

fn year_month(epoch: u64) -> (i64, u32) {
    // Howard Hinnant's civil_from_days.
    let z = (epoch / 86_400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m)
}

/// "IP geolocation by DB-IP.com (2026-11)" — the attribution to show.
fn source_label(db: &Db) -> String {
    let md = db.reader.metadata();
    let (y, m) = year_month(md.build_epoch);
    let kind = md.database_type.to_ascii_lowercase();
    if kind.contains("dbip") || kind.contains("db-ip") {
        format!("IP geolocation by DB-IP.com ({y}-{m:02})")
    } else if kind.contains("geolite") {
        format!("GeoLite2 data created by MaxMind ({y}-{m:02})")
    } else {
        format!("{} ({y}-{m:02})", clean(&md.database_type))
    }
}

pub struct Geo {
    dir: PathBuf,
    city: Option<Db>,
    asn: Option<Db>,
    cache: HashMap<IpAddr, Option<GeoInfo>>,
    pub downloading: bool,
    pub error: Option<String>,
    tz_home: Option<Home>,
}

impl Geo {
    pub fn new(state_dir: &Path) -> Geo {
        let mut g = Geo {
            dir: state_dir.join("geo"),
            city: None,
            asn: None,
            cache: HashMap::new(),
            downloading: false,
            error: None,
            tz_home: timezone_home(Path::new("/usr/share/zoneinfo")),
        };
        g.reload();
        g
    }

    fn candidates(&self, own: &str, system: &[&str]) -> Vec<PathBuf> {
        let mut v = vec![self.dir.join(own)];
        v.extend(system.iter().map(PathBuf::from));
        v
    }

    /// Pick up databases that appeared, changed or went away. Cheap enough
    /// to call every minute. Returns true when anything changed.
    pub fn reload(&mut self) -> bool {
        let mut changed = false;
        for (own, system, want) in [
            (CITY_FILE, SYSTEM_CITY, "city"),
            (ASN_FILE, SYSTEM_ASN, "asn"),
        ] {
            let found = self
                .candidates(own, system)
                .into_iter()
                .find_map(|p| stamp(&p).map(|s| (p, s)));
            let slot = if want == "city" {
                &mut self.city
            } else {
                &mut self.asn
            };
            let current = slot.as_ref().map(|d| (d.path.clone(), d.stamp));
            if current == found {
                continue;
            }
            changed = true;
            *slot = match found {
                None => None,
                Some((p, _)) => match open(&p, want) {
                    Ok(db) => {
                        log::info(&format!(
                            "location database: {} ({})",
                            p.display(),
                            db.reader.metadata().database_type
                        ));
                        Some(db)
                    }
                    Err(e) => {
                        log::warn(&format!("ignoring {}: {e:#}", p.display()));
                        None
                    }
                },
            };
        }
        if changed {
            self.cache.clear();
        }
        changed
    }

    pub fn lookup(&mut self, ip: IpAddr) -> Option<GeoInfo> {
        let ip = canonical_ip(ip);
        if self.city.is_none() || is_local_ip(ip) {
            return None;
        }
        if let Some(hit) = self.cache.get(&ip) {
            return hit.clone();
        }
        let info = self.lookup_uncached(ip);
        if self.cache.len() >= CACHE_CAP {
            self.cache.clear();
        }
        self.cache.insert(ip, info.clone());
        info
    }

    fn lookup_uncached(&self, ip: IpAddr) -> Option<GeoInfo> {
        let city = self.city.as_ref()?;
        let res = city.reader.lookup(ip).ok()?;
        let rec: geoip2::City = res.decode().ok()??;
        let lat = rec.location.latitude?;
        let lon = rec.location.longitude?;
        if !lat.is_finite() || !lon.is_finite() || lat.abs() > 90.0 || lon.abs() > 180.0 {
            return None;
        }
        let country = if rec.country.iso_code.is_some() {
            &rec.country
        } else {
            &rec.registered_country
        };
        let mut g = GeoInfo {
            lat,
            lon,
            cc: clean(country.iso_code.unwrap_or_default()),
            country: clean(country.names.english.unwrap_or_default()),
            // DB-IP adds districts: "San Francisco (South Beach)".
            city: clean(
                rec.city
                    .names
                    .english
                    .unwrap_or_default()
                    .split(" (")
                    .next()
                    .unwrap_or_default(),
            ),
            asn: None,
            org: None,
        };
        if let Some(asn) = &self.asn
            && let Ok(r) = asn.reader.lookup(ip)
            && let Ok(Some(a)) = r.decode::<geoip2::Asn>()
        {
            g.asn = a.autonomous_system_number;
            g.org = a
                .autonomous_system_organization
                .map(clean)
                .filter(|s| !s.is_empty());
        }
        Some(g)
    }

    pub fn status(&self) -> GeoStatus {
        GeoStatus {
            state: if self.downloading {
                GeoState::Downloading
            } else if self.city.is_some() {
                GeoState::Ready
            } else {
                GeoState::Missing
            },
            source: self.city.as_ref().map(source_label),
            path: self.city.as_ref().map(|d| d.path.display().to_string()),
            has_asn: self.asn.is_some(),
            error: self.error.clone(),
        }
    }

    pub fn home(&self, settings: &Settings) -> Option<Home> {
        match settings.home {
            Some(c) => Some(Home {
                lat: c.lat,
                lon: c.lon,
                label: "set by you".into(),
            }),
            None => self.tz_home.clone(),
        }
    }

    /// True when the database is one we downloaded and it's a month old.
    pub fn update_due(&self) -> bool {
        let own = self.dir.join(CITY_FILE);
        match fs::metadata(&own).and_then(|m| m.modified()) {
            Ok(t) => t
                .elapsed()
                .map(|e| e.as_secs() > 32 * 86_400)
                .unwrap_or(false),
            Err(_) => false,
        }
    }
}

// ------------------------------------------------------------ home

/// The machine's time zone, e.g. "Europe/Berlin".
fn local_zone() -> Option<String> {
    if let Ok(t) = fs::read_link("/etc/localtime") {
        let s = t.to_string_lossy();
        if let Some(i) = s.find("zoneinfo/") {
            let z = &s[i + "zoneinfo/".len()..];
            return Some(
                z.trim_start_matches("posix/")
                    .trim_start_matches("right/")
                    .to_string(),
            );
        }
    }
    fs::read_to_string("/etc/timezone")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Where the map puts you by default: your time zone's city, from the tz
/// database's own coordinates. Nothing is looked up online.
pub fn timezone_home(zoneinfo: &Path) -> Option<Home> {
    zone_home(&local_zone()?, zoneinfo)
}

pub fn zone_home(zone: &str, zoneinfo: &Path) -> Option<Home> {
    let label = format!(
        "{} (time zone)",
        zone.rsplit('/').next().unwrap_or(zone).replace('_', " ")
    );
    let tabs: Vec<String> = ["zone.tab", "zone1970.tab"]
        .iter()
        .filter_map(|f| fs::read_to_string(zoneinfo.join(f)).ok())
        .collect();
    let zi = fs::read_to_string(zoneinfo.join("tzdata.zi")).unwrap_or_default();
    let mut name = zone.to_string();
    // Follow links ("US/Eastern" → "America/New_York") a few hops.
    for _ in 0..4 {
        for tab in &tabs {
            for line in tab.lines().filter(|l| !l.starts_with('#')) {
                let cols: Vec<&str> = line.split('\t').collect();
                if cols.len() >= 3
                    && cols[2] == name
                    && let Some((lat, lon)) = parse_iso6709(cols[1])
                {
                    return Some(Home { lat, lon, label });
                }
            }
        }
        name = zi.lines().find_map(|l| {
            let mut it = l.split_whitespace();
            (it.next() == Some("L")).then_some(())?;
            let target = it.next()?;
            (it.next() == Some(name.as_str())).then(|| target.to_string())
        })?;
    }
    None
}

/// ISO 6709 as used by zone.tab: "+4043-07400" or "+404251-0740023".
pub fn parse_iso6709(s: &str) -> Option<(f64, f64)> {
    if !s.is_ascii() || s.len() < 2 {
        return None;
    }
    let split = s[1..].find(['+', '-'])? + 1;
    let (a, b) = s.split_at(split);
    Some((dms(a, 2)?, dms(b, 3)?))
}

fn dms(s: &str, deg: usize) -> Option<f64> {
    let sign = match s.as_bytes().first()? {
        b'+' => 1.0,
        b'-' => -1.0,
        _ => return None,
    };
    let d = &s[1..];
    if !d.bytes().all(|b| b.is_ascii_digit()) || (d.len() != deg + 2 && d.len() != deg + 4) {
        return None;
    }
    let num = |r: std::ops::Range<usize>| d[r].parse::<f64>().ok();
    let sec = if d.len() == deg + 4 {
        num(deg + 2..deg + 4)?
    } else {
        0.0
    };
    Some(sign * (num(0..deg)? + num(deg..deg + 2)? / 60.0 + sec / 3600.0))
}

// ------------------------------------------------------------ download

/// Fetch DB-IP's free City and ASN databases (CC BY 4.0) into the state
/// directory, then switch to them. Runs on its own thread.
pub fn download(core: Arc<Mutex<Core>>) {
    let dir = {
        let mut c = core.lock().unwrap();
        if c.geo.downloading {
            return;
        }
        c.geo.downloading = true;
        c.geo.error = None;
        c.broadcast_status();
        c.geo.dir.clone()
    };
    log::info("downloading the location database from db-ip.com");
    let city = fetch(&dir, "city", CITY_FILE);
    let asn = if city.is_ok() {
        fetch(&dir, "asn", ASN_FILE)
    } else {
        Ok(())
    };
    let mut c = core.lock().unwrap();
    c.geo.downloading = false;
    match city {
        Ok(()) => {
            if let Err(e) = asn {
                log::warn(&format!("owner database: {e:#}"));
            }
            c.geo.reload();
            c.backfill_geo();
            if !c.settings.geo_auto_update {
                c.settings.geo_auto_update = true;
                c.save_settings();
            }
            log::info("location database ready");
        }
        Err(e) => {
            log::warn(&format!("location database download failed: {e:#}"));
            c.geo.error = Some(format!("{e:#}"));
        }
    }
    c.broadcast_status();
}

fn fetch(dir: &Path, kind: &str, file: &str) -> Result<()> {
    fs::create_dir_all(dir)?;
    let gz = dir.join(format!(".{file}.gz.part"));
    let tmp = dir.join(format!(".{file}.part"));
    let res = (|| {
        // A month's file appears early on the 1st; fall back to last month's.
        let (y, m) = year_month(now());
        let (py, pm) = if m == 1 { (y - 1, 12) } else { (y, m - 1) };
        let mut err = None;
        for (y, m) in [(y, m), (py, pm)] {
            let url =
                format!("https://download.db-ip.com/free/dbip-{kind}-lite-{y}-{m:02}.mmdb.gz");
            match curl(&url, &gz) {
                Ok(()) => {
                    err = None;
                    break;
                }
                Err(e) => err = Some(e),
            }
        }
        if let Some(e) = err {
            return Err(e);
        }
        let mut dec = flate2::read::GzDecoder::new(io::BufReader::new(fs::File::open(&gz)?));
        let mut out = fs::File::create(&tmp)?;
        let n = io::copy(&mut (&mut dec).take(MAX_DB_BYTES + 1), &mut out).context("unpacking")?;
        if n > MAX_DB_BYTES {
            bail!("the database is unexpectedly large");
        }
        out.sync_all()?;
        drop(out);
        let db = open(&tmp, kind).context("checking the download")?;
        let probe: IpAddr = "1.1.1.1".parse().unwrap();
        if !db.reader.lookup(probe)?.has_data() {
            bail!("the downloaded database looks empty");
        }
        drop(db);
        fs::rename(&tmp, dir.join(file))?;
        Ok(())
    })();
    let _ = fs::remove_file(&gz);
    let _ = fs::remove_file(&tmp);
    res
}

fn curl(url: &str, to: &Path) -> Result<()> {
    let out = Command::new("curl")
        .args([
            "-fsSL",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--max-time",
            "900",
            "--max-filesize",
            "300000000",
            "--retry",
            "2",
            "-A",
            concat!("tattle/", env!("CARGO_PKG_VERSION")),
            "-o",
        ])
        .arg(to)
        .args(["--", url])
        .output()
        .context("running curl")?;
    if !out.status.success() {
        bail!("{url}: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso6709() {
        let (lat, lon) = parse_iso6709("+404251-0740023").unwrap();
        assert!((lat - 40.714).abs() < 0.01 && (lon + 74.006).abs() < 0.01);
        let (lat, lon) = parse_iso6709("+5230+01322").unwrap();
        assert!((lat - 52.5).abs() < 0.01 && (lon - 13.367).abs() < 0.01);
        assert!(parse_iso6709("+52x0+01322").is_none());
        assert!(parse_iso6709("").is_none());
    }

    #[test]
    fn months() {
        assert_eq!(year_month(0), (1970, 1));
        assert_eq!(year_month(1_798_761_600), (2027, 1)); // 2027-01-01
        assert_eq!(year_month(1_798_761_599), (2026, 12));
    }

    #[test]
    fn zones_from_tzdata() {
        let dir = std::env::temp_dir().join(format!("tattle-tz-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("zone.tab"),
            "# comment\nUS\t+404251-0740023\tAmerica/New_York\tEastern\nNO\t+5955+01045\tEurope/Oslo\n",
        )
        .unwrap();
        fs::write(dir.join("tzdata.zi"), "L America/New_York US/Eastern\n").unwrap();
        let h = zone_home("Europe/Oslo", &dir).unwrap();
        assert!((h.lat - 59.92).abs() < 0.01);
        assert_eq!(h.label, "Oslo (time zone)");
        let h = zone_home("US/Eastern", &dir).unwrap();
        assert!((h.lon + 74.0).abs() < 0.1);
        assert!(zone_home("Etc/UTC", &dir).is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn download_from_dbip() {
        // Touches the network: set TATTLE_TEST_DOWNLOAD=1 to run.
        if std::env::var_os("TATTLE_TEST_DOWNLOAD").is_none() {
            return;
        }
        let dir = std::env::temp_dir().join(format!("tattle-dl-{}", std::process::id()));
        fetch(&dir, "asn", ASN_FILE).unwrap();
        let db = open(&dir.join(ASN_FILE), "asn").unwrap();
        let a: geoip2::Asn = db
            .reader
            .lookup("1.1.1.1".parse().unwrap())
            .unwrap()
            .decode()
            .unwrap()
            .unwrap();
        assert_eq!(a.autonomous_system_number, Some(13335));
        // Nothing half-written is left behind.
        let names: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from(ASN_FILE)]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn real_database_if_present() {
        // Set TATTLE_TEST_GEO_DIR to a folder with city.mmdb/asn.mmdb to run.
        let Some(dir) = std::env::var_os("TATTLE_TEST_GEO_DIR") else {
            return;
        };
        let mut g = Geo::new(Path::new("/nonexistent"));
        g.dir = PathBuf::from(dir);
        g.reload();
        assert_eq!(g.status().state, GeoState::Ready);
        let info = g.lookup("1.1.1.1".parse().unwrap()).unwrap();
        assert!(!info.cc.is_empty());
        assert!(g.lookup("192.168.1.1".parse().unwrap()).is_none());
        assert!(g.status().source.unwrap().contains("20"));
    }
}
