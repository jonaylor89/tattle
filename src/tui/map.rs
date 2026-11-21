//! The Map tab: every place your apps talk to, with an arc from you to it.
//!
//! The land is a 0.5° mask rasterized from Natural Earth (tools/gen-land.py),
//! drawn as braille: a solid coastline with a lighter fill inside.

use super::draw::{
    ACCENT, BAD, DIM, INFO, OK, UP, ago, centered, dim, filter_title, panel, sel_style,
};
use super::*;
use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Margin, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::symbols::Marker;
use ratatui::text::{Line, Span};
use ratatui::widgets::canvas::{Canvas, Context, Line as Segment, Painter, Shape};
use ratatui::widgets::{Cell, Clear, Paragraph, Row, Table, TableState, Wrap};
use std::collections::HashSet;

static LAND: &[u8] = include_bytes!("land.bin");
const STEP: f64 = 0.5;
const COLS: usize = 720;
const ROWS: usize = 360;
/// The map leaves out Antarctica and the high Arctic.
const SOUTH: f64 = -56.0;
const NORTH: f64 = 78.0;
/// Terminal cells are roughly 2.2 times taller than wide.
const CELL_ASPECT: f64 = 2.2;
const IDLE: Color = Color::Blue;
const MAX_ARCS: usize = 120;

pub fn is_land(lon: f64, lat: f64) -> bool {
    let col = ((lon + 180.0) / STEP).floor();
    let row = ((90.0 - lat) / STEP).floor();
    if !(0.0..COLS as f64).contains(&col) || !(0.0..ROWS as f64).contains(&row) {
        return false;
    }
    let i = row as usize * COLS + col as usize;
    LAND[i >> 3] & (0x80 >> (i & 7)) != 0
}

pub fn place_key(p: &MapPlace) -> (i64, i64) {
    ((p.lat * 10.0).round() as i64, (p.lon * 10.0).round() as i64)
}

/// Does the query name this place (city, country, network owner, app)?
pub fn place_matches(p: &MapPlace, q: &str) -> bool {
    p.city.to_lowercase().contains(q)
        || p.country.to_lowercase().contains(q)
        || p.cc.to_lowercase() == q
        || p.orgs.iter().any(|o| o.to_lowercase().contains(q))
}

/// Canvas bounds that keep the world's proportions on a `w`×`h`-cell
/// braille canvas, centred, with any slack left empty.
pub fn bounds(w: u16, h: u16) -> ([f64; 2], [f64; 2]) {
    let (dw, dh) = (f64::from(w.max(1)) * 2.0, f64::from(h.max(1)) * 4.0);
    // A braille dot is (cell width / 2) by (cell height / 4).
    let dot_aspect = CELL_ASPECT / 2.0;
    let lon_per_dot = (360.0 / dw).max((NORTH - SOUTH) / (dh * dot_aspect));
    let (xs, ys) = (lon_per_dot * dw, lon_per_dot * dot_aspect * dh);
    let cy = (NORTH + SOUTH) / 2.0;
    ([-xs / 2.0, xs / 2.0], [cy - ys / 2.0, cy + ys / 2.0])
}

/// Points along a gentle arc from `a` to `b` (lon, lat), taking the short
/// way round: the points may run past ±180°, which the caller wraps.
pub fn arc(a: (f64, f64), b: (f64, f64)) -> Vec<(f64, f64)> {
    let mut bx = b.0;
    if bx - a.0 > 180.0 {
        bx -= 360.0;
    } else if a.0 - bx > 180.0 {
        bx += 360.0;
    }
    let (dx, dy) = (bx - a.0, b.1 - a.1);
    let d = dx.hypot(dy);
    if d < 0.5 {
        return vec![a, (bx, b.1)];
    }
    // Bow upwards like a flight path; longer hops bow more.
    let (mut nx, mut ny) = (-dy / d, dx / d);
    if ny < 0.0 || (ny == 0.0 && nx < 0.0) {
        (nx, ny) = (-nx, -ny);
    }
    let bow = (d * 0.22).min(26.0);
    let c = ((a.0 + bx) / 2.0 + nx * bow, (a.1 + b.1) / 2.0 + ny * bow);
    let n = ((d / 2.5) as usize).clamp(6, 64);
    (0..=n)
        .map(|i| {
            let t = i as f64 / n as f64;
            let u = 1.0 - t;
            (
                u * u * a.0 + 2.0 * u * t * c.0 + t * t * bx,
                u * u * a.1 + 2.0 * u * t * c.1 + t * t * b.1,
            )
        })
        .collect()
}

/// The same path, plus copies shifted by a full turn wherever it crosses
/// the date line, so it leaves one edge and comes back in on the other.
fn wrapped(pts: &[(f64, f64)]) -> Vec<Vec<(f64, f64)>> {
    let mut out = vec![pts.to_vec()];
    if pts.iter().any(|p| p.0 > 180.0) {
        out.push(pts.iter().map(|p| (p.0 - 360.0, p.1)).collect());
    }
    if pts.iter().any(|p| p.0 < -180.0) {
        out.push(pts.iter().map(|p| (p.0 + 360.0, p.1)).collect());
    }
    out
}

fn wrap_lon(x: f64) -> f64 {
    (x + 180.0).rem_euclid(360.0) - 180.0
}

/// Land as braille: every coastal dot, and a light stipple inland.
struct Land {
    w: usize,
    h: usize,
    x: [f64; 2],
    y: [f64; 2],
}

impl Shape for Land {
    fn draw(&self, painter: &mut Painter) {
        let (gw, gh) = (self.w * 2, self.h * 4);
        if gw < 2 || gh < 2 {
            return;
        }
        let sx = (self.x[1] - self.x[0]) / (gw - 1) as f64;
        let sy = (self.y[1] - self.y[0]) / (gh - 1) as f64;
        for gy in 0..gh {
            let lat = self.y[1] - gy as f64 * sy;
            for gx in 0..gw {
                let lon = self.x[0] + gx as f64 * sx;
                if !is_land(lon, lat) {
                    continue;
                }
                let coast = !is_land(lon - sx, lat)
                    || !is_land(lon + sx, lat)
                    || !is_land(lon, lat - sy)
                    || !is_land(lon, lat + sy);
                if coast || (gx % 2 == 0 && gy % 2 == 0) {
                    painter.paint(gx, gy, DIM);
                }
            }
        }
    }
}

fn polyline(ctx: &mut Context, pts: &[(f64, f64)], color: Color) {
    for path in wrapped(pts) {
        for w in path.windows(2) {
            ctx.draw(&Segment::new(w[0].0, w[0].1, w[1].0, w[1].1, color));
        }
    }
}

fn place_color(p: &MapPlace) -> Color {
    if p.blocked() {
        BAD
    } else if p.live() {
        INFO
    } else {
        IDLE
    }
}

fn place_glyph(p: &MapPlace) -> (&'static str, Style) {
    if p.blocked() {
        ("×", Style::new().fg(BAD).bold())
    } else if p.live() {
        ("●", Style::new().fg(INFO).bold())
    } else {
        ("•", Style::new().fg(IDLE))
    }
}

fn short_place(p: &MapPlace) -> String {
    if p.city.is_empty() {
        if p.country.is_empty() {
            p.cc.clone()
        } else {
            p.country.clone()
        }
    } else {
        p.city.clone()
    }
}

fn clip(s: &str, n: usize) -> String {
    if s.chars().count() > n {
        s.chars().take(n.saturating_sub(1)).collect::<String>() + "…"
    } else {
        s.to_string()
    }
}

fn distance(app: &App, p: &MapPlace) -> Option<f64> {
    app.map.home.as_ref().map(|h| {
        Coord {
            lat: h.lat,
            lon: h.lon,
        }
        .distance_km(Coord {
            lat: p.lat,
            lon: p.lon,
        })
    })
}

fn km(d: f64) -> String {
    if d < 10.0 {
        "nearby".into()
    } else if d < 10_000.0 {
        format!("{} km", (d / 10.0).round() as u64 * 10)
    } else {
        format!("{:.1}k km", d / 1000.0)
    }
}

pub fn draw_map(f: &mut Frame, app: &App, area: Rect) {
    let places = app.filtered_places();
    let sel = places
        .get(app.place_sel.min(places.len().saturating_sub(1)))
        .copied();
    let list_w = if area.width >= 130 { 40 } else { 32 };
    let [left, list_area] =
        Layout::horizontal([Constraint::Fill(1), Constraint::Length(list_w)]).areas(area);
    // Exactly as tall as the world needs at this width; the rest lists servers.
    let (xb, _) = bounds(left.width.saturating_sub(2), 1000);
    let lat_per_row = (xb[1] - xb[0]) / f64::from(left.width.saturating_sub(2).max(1)) / 2.0
        * (CELL_ASPECT / 2.0)
        * 4.0;
    let rows_needed = ((NORTH - SOUTH) / lat_per_row).ceil() as u16 + 2;
    let map_h = rows_needed.clamp(8, left.height.saturating_sub(7).max(8));
    let [map_area, details] =
        Layout::vertical([Constraint::Length(map_h), Constraint::Fill(1)]).areas(left);
    draw_world(f, app, &places, sel, map_area);
    draw_places(f, app, &places, list_area);
    draw_details(f, app, sel, details);
}

fn draw_world(f: &mut Frame, app: &App, places: &[&MapPlace], sel: Option<&MapPlace>, area: Rect) {
    let live = places.iter().filter(|p| p.live()).count();
    let countries = places
        .iter()
        .map(|p| p.cc.as_str())
        .filter(|c| !c.is_empty())
        .collect::<HashSet<_>>()
        .len();
    let mut title = vec![
        Span::raw(" Map "),
        Span::styled(
            format!(
                "{} place{} in {} countr{} ",
                places.len(),
                if places.len() == 1 { "" } else { "s" },
                countries,
                if countries == 1 { "y" } else { "ies" }
            ),
            dim(),
        ),
    ];
    if live > 0 {
        title.push(Span::styled(
            format!("· {live} live "),
            Style::new().fg(INFO),
        ));
    }
    title.push(filter_title(app));
    let mut block = panel(Line::from(title), false);
    if let Some(src) = &app.map.geo.source {
        block =
            block.title_bottom(Line::from(Span::styled(format!(" {src} "), dim())).right_aligned());
    }
    let inner = block.inner(area);
    f.render_widget(block, area);
    if inner.width < 10 || inner.height < 4 {
        return;
    }

    let (xb, yb) = bounds(inner.width, inner.height);
    let cell_w = (xb[1] - xb[0]) / f64::from(inner.width);
    let cell_h = (yb[1] - yb[0]) / f64::from(inner.height);
    let t = app.epoch.elapsed().as_secs_f64();
    let home = app.map.home.as_ref().map(|h| (h.lon, h.lat));
    let sel_key = sel.map(place_key);

    // Quiet places first, so the busy and the selected end up on top.
    let mut order: Vec<&MapPlace> = places.to_vec();
    order.truncate(MAX_ARCS.max(1));
    if let Some(s) = sel
        && !order.iter().any(|p| place_key(p) == place_key(s))
    {
        order.push(s);
    }
    order.reverse();
    // Blocked places go on top of everything but the selection: they matter most.
    order.sort_by_key(|p| (Some(place_key(p)) == sel_key, p.blocked(), p.live()));

    let canvas = Canvas::default()
        .marker(Marker::Braille)
        .x_bounds(xb)
        .y_bounds(yb)
        .paint(|ctx| {
            ctx.draw(&Land {
                w: inner.width as usize,
                h: inner.height as usize,
                x: xb,
                y: yb,
            });
            ctx.layer();
            if let Some(h) = home {
                for p in &order {
                    let color = if Some(place_key(p)) == sel_key {
                        ACCENT
                    } else {
                        place_color(p)
                    };
                    polyline(ctx, &arc(h, (p.lon, p.lat)), color);
                }
                ctx.layer();
            }
            for p in &order {
                let (g, st) = place_glyph(p);
                ctx.print(p.lon, p.lat, Span::styled(g, st));
            }
            // Packets: data in flight, heading the way most bytes go.
            if let Some(h) = home {
                for p in order.iter().filter(|p| p.live() && !p.blocked()) {
                    let bytes = p.tx_rate + p.rx_rate;
                    let n = match bytes {
                        0..1_000 => 1,
                        1_000..1_000_000 => 2,
                        _ => 3,
                    };
                    let pts = arc(h, (p.lon, p.lat));
                    let seed =
                        (place_key(p).0.unsigned_abs() * 31 + place_key(p).1.unsigned_abs()) % 97;
                    for k in 0..n {
                        let mut phase =
                            (t / 2.4 + k as f64 / n as f64 + seed as f64 / 97.0).fract();
                        if p.rx_rate >= p.tx_rate {
                            phase = 1.0 - phase;
                        }
                        let (x, y) = pts[((pts.len() - 1) as f64 * phase).round() as usize];
                        ctx.print(
                            wrap_lon(x),
                            y,
                            Span::styled("•", Style::new().add_modifier(Modifier::BOLD)),
                        );
                    }
                }
            }
            if let Some((hx, hy)) = home {
                ctx.print(hx, hy, Span::styled("◉", Style::new().fg(UP).bold()));
                if sel.is_none_or(|s| (s.lon - hx).abs() > cell_w * 8.0 || (s.lat - hy).abs() > 3.0)
                {
                    ctx.print(hx + cell_w, hy, Span::styled(" you", Style::new().fg(UP)));
                }
            }
            if let Some(s) = sel {
                ctx.print(
                    s.lon,
                    s.lat,
                    Span::styled("◆", Style::new().fg(ACCENT).bold()),
                );
                let label = format!(" {} ", clip(&short_place(s), 24));
                let w = label.chars().count() as f64 * cell_w;
                // Right of the marker, unless that runs off the map or over "you".
                let covers_home = |x0: f64| {
                    home.is_some_and(|(hx, hy)| {
                        (hy - s.lat).abs() < cell_h * 1.5
                            && hx >= x0 - cell_w
                            && hx <= x0 + w + cell_w
                    })
                };
                let (right, left) = (s.lon + cell_w, s.lon - w);
                let (x, y) = if right + w <= xb[1] && !covers_home(right) {
                    (right, s.lat)
                } else if left >= xb[0] && !covers_home(left) {
                    (left, s.lat)
                } else {
                    ((s.lon - w / 2.0).clamp(xb[0], xb[1] - w), s.lat + cell_h)
                };
                ctx.print(
                    x,
                    y,
                    Span::styled(label, Style::new().fg(Color::Black).bg(ACCENT).bold()),
                );
            }
        });
    f.render_widget(canvas, inner);

    // Tell people how to get a map worth looking at.
    let geo = &app.map.geo;
    let msg: Option<Vec<Line>> = match geo.state {
        GeoState::Ready if places.is_empty() && app.map.places.is_empty() => Some(vec![
            Line::from("Nothing to show yet").bold(),
            Line::from(""),
            Line::styled(
                format!(
                    "No connections in the {}. Press w for a longer window.",
                    app.map_window.label()
                ),
                dim(),
            ),
        ]),
        GeoState::Ready => None,
        GeoState::Downloading => Some(vec![
            Line::from(format!(
                "{}  Fetching the location database…",
                ["◐", "◓", "◑", "◒"][(app.tick % 4) as usize]
            ))
            .bold(),
            Line::from(""),
            Line::styled("About 60 MB from db-ip.com; this takes a minute.", dim()),
        ]),
        GeoState::Missing => {
            let mut v = vec![
                Line::from("Where in the world are your apps connecting?").bold(),
                Line::from(""),
                Line::from("Tattle places servers on this map with an offline IP-location"),
                Line::from("database. Lookups stay on this machine."),
                Line::from(""),
                Line::from(vec![
                    Span::styled("u", Style::new().fg(ACCENT).bold()),
                    Span::raw("  download DB-IP City Lite (free, CC BY 4.0, about 60 MB)"),
                ]),
                Line::styled(
                    "   or install a GeoLite2-City database in /usr/share/GeoIP",
                    dim(),
                ),
            ];
            if let Some(e) = &geo.error {
                v.push(Line::from(""));
                v.push(Line::styled(
                    clip(&format!("Last try failed: {e}"), 70),
                    Style::new().fg(BAD),
                ));
            }
            Some(v)
        }
    };
    if let Some(lines) = msg {
        let h = lines.len() as u16 + 2;
        let r = centered(inner, 72.min(inner.width), h);
        f.render_widget(Clear, r);
        f.render_widget(
            Paragraph::new(lines)
                .alignment(Alignment::Center)
                .wrap(Wrap { trim: true })
                .block(panel("", true)),
            r,
        );
    }
}

fn draw_places(f: &mut Frame, app: &App, places: &[&MapPlace], area: Rect) {
    let mut block = panel(
        Line::from(vec![
            Span::raw(format!(" Places {} ", places.len())),
            Span::styled(format!("· {} ", app.map_window.label()), dim()),
        ]),
        !app.map_servers,
    );
    let (local, unlocated) = (app.map.local, app.map.unlocated);
    if local + unlocated > 0 {
        let mut parts = Vec::new();
        if local > 0 {
            parts.push(format!("{local} local"));
        }
        if unlocated > 0 {
            parts.push(format!("{unlocated} unplaced"));
        }
        block = block.title_bottom(Line::from(Span::styled(
            format!(" {} ", parts.join(" · ")),
            dim(),
        )));
    }
    let rows: Vec<Row> = places
        .iter()
        .map(|p| {
            let (g, st) = place_glyph(p);
            let bytes = p.tx + p.rx;
            Row::new(vec![
                Cell::from(Span::styled(g, st)),
                Cell::from(Span::styled(p.cc.clone(), dim())),
                Cell::from(short_place(p)),
                Cell::from(
                    Line::from(if bytes > 0 {
                        human_bytes(bytes)
                    } else if p.denied > 0 {
                        format!("{}✗", p.denied)
                    } else {
                        "—".into()
                    })
                    .alignment(Alignment::Right)
                    .fg(if p.blocked() { BAD } else { DIM }),
                ),
            ])
        })
        .collect();
    let t = Table::new(
        rows,
        [
            Constraint::Length(1),
            Constraint::Length(2),
            Constraint::Fill(1),
            Constraint::Length(8),
        ],
    )
    .row_highlight_style(if app.map_servers {
        Style::new().fg(ACCENT)
    } else {
        sel_style()
    })
    .column_spacing(1);
    let mut st = TableState::default().with_selected(if places.is_empty() {
        None
    } else {
        Some(app.place_sel.min(places.len() - 1))
    });
    f.render_stateful_widget(t.block(block), area, &mut st);
}

fn draw_details(f: &mut Frame, app: &App, sel: Option<&MapPlace>, area: Rect) {
    let Some(p) = sel else {
        let hint = if app.map.home.is_none() {
            "Your time zone has no city, so the map can't draw arcs from you. Set your spot with: tattle geo home LAT,LON"
        } else {
            "Pick a place to see who your apps talk to there."
        };
        f.render_widget(
            Paragraph::new(Line::styled(hint, dim()))
                .wrap(Wrap { trim: true })
                .block(panel(" Servers ", false)),
            area,
        );
        return;
    };
    let mut title = vec![Span::styled(
        format!(" {} ", p.place()),
        Style::new().bold(),
    )];
    if let Some(d) = distance(app, p) {
        title.push(Span::styled(format!("· {} ", km(d)), dim()));
    }
    if !p.orgs.is_empty() {
        let mut orgs = clip(&p.orgs[0], 36);
        if p.orgs.len() > 1 {
            orgs.push_str(&format!(" +{}", p.orgs.len() - 1));
        }
        title.push(Span::styled(format!("· {orgs} "), dim()));
    }
    let servers = app.place_servers(p);
    let mut block = panel(Line::from(title), app.map_servers);
    if p.more > 0 {
        block = block.title_bottom(Line::from(Span::styled(
            format!(" and {} more ", p.more),
            dim(),
        )));
    }
    let rows: Vec<Row> = servers
        .iter()
        .map(|s| {
            let (g, c) = match s.last_action {
                Some(Action::Deny) => ("✗", BAD),
                _ if s.active > 0 => ("●", INFO),
                _ => ("✓", OK),
            };
            let mut ports: Vec<String> = s.ports.iter().map(|p| p.to_string()).collect();
            if ports.len() > 3 {
                ports.truncate(3);
                ports.push("…".into());
            }
            Row::new(vec![
                Cell::from(Span::styled(g, Style::new().fg(c))),
                Cell::from(Span::styled(clip(&s.app, 18), Style::new().bold())),
                Cell::from(s.host.clone()),
                Cell::from(Span::styled(ports.join(","), dim())),
                Cell::from(
                    Line::from(human_bytes(s.tx))
                        .alignment(Alignment::Right)
                        .fg(UP),
                ),
                Cell::from(
                    Line::from(human_bytes(s.rx))
                        .alignment(Alignment::Right)
                        .fg(INFO),
                ),
                Cell::from(
                    Line::from(ago(s.last_seen))
                        .alignment(Alignment::Right)
                        .fg(DIM),
                ),
            ])
        })
        .collect();
    let t = Table::new(
        rows,
        [
            Constraint::Length(1),
            Constraint::Length(18),
            Constraint::Fill(1),
            Constraint::Length(12),
            Constraint::Length(8),
            Constraint::Length(8),
            Constraint::Length(8),
        ],
    )
    .header(Row::new(vec!["", "app", "server", "port", "sent", "recv", "seen"]).style(dim()))
    .row_highlight_style(if app.map_servers {
        sel_style()
    } else {
        Style::new()
    })
    .column_spacing(1);
    let mut st = TableState::default().with_selected(if app.map_servers && !servers.is_empty() {
        Some(app.server_sel.min(servers.len() - 1))
    } else {
        None
    });
    let inner = block.inner(area);
    f.render_widget(block, area);
    f.render_stateful_widget(
        t,
        inner.inner(Margin {
            horizontal: 1,
            vertical: 0,
        }),
        &mut st,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn land_mask() {
        assert!(is_land(13.4, 52.5)); // Berlin
        assert!(is_land(-98.0, 39.0)); // Kansas
        assert!(is_land(134.0, -25.0)); // Australia
        assert!(!is_land(-40.0, 30.0)); // mid-Atlantic
        assert!(!is_land(-150.0, 0.0)); // Pacific
        assert!(!is_land(200.0, 0.0));
    }

    #[test]
    fn bounds_keep_proportions() {
        for (w, h) in [(120u16, 30u16), (60, 40), (200, 20)] {
            let (x, y) = bounds(w, h);
            assert!(x[0] <= -180.0 && x[1] >= 180.0);
            assert!(y[0] <= SOUTH + 0.01 && y[1] >= NORTH - 0.01);
            let lon_per_dot = (x[1] - x[0]) / (f64::from(w) * 2.0);
            let lat_per_dot = (y[1] - y[0]) / (f64::from(h) * 4.0);
            assert!((lat_per_dot / lon_per_dot - CELL_ASPECT / 2.0).abs() < 1e-9);
        }
    }

    #[test]
    fn arcs_take_the_short_way() {
        // Tokyo → San Francisco crosses the date line, not Europe.
        let pts = arc((139.7, 35.7), (-122.4, 37.8));
        assert!(pts.iter().all(|p| p.0 >= 139.0));
        assert!((pts.last().unwrap().0 - 237.6).abs() < 1e-9);
        assert_eq!(wrapped(&pts).len(), 2);
        // Arcs bow upwards and end where they should.
        let pts = arc((-74.0, 40.7), (13.4, 52.5));
        assert_eq!(pts[0], (-74.0, 40.7));
        assert_eq!(*pts.last().unwrap(), (13.4, 52.5));
        assert!(pts[pts.len() / 2].1 > 52.5);
        assert_eq!(arc((1.0, 1.0), (1.0, 1.0)).len(), 2);
    }
}
