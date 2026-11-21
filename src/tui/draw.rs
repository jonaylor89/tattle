use super::editor::FIELDS;
use super::*;
use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Flex, Layout, Margin, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::symbols;
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, BorderType, Borders, Cell, Clear, LineGauge, Paragraph, Row, Sparkline, Table,
    TableState, Tabs, Wrap,
};

// The palette is the terminal's own, so Omarchy themes restyle us for free.
pub(super) const ACCENT: Color = Color::Yellow;
pub(super) const OK: Color = Color::Green;
pub(super) const BAD: Color = Color::Red;
pub(super) const INFO: Color = Color::Cyan;
pub(super) const UP: Color = Color::Magenta;
pub(super) const DIM: Color = Color::DarkGray;

const RAT: &str = "ᘛ⁐ᕐᐷ";

const TAGLINES: &[&str] = &[
    "nobody phones home unnoticed",
    "I saw that.",
    "every packet has a story",
    "snitching since boot",
    "your apps are chatty today",
    "trust, but verify",
    "keeping an ear to the wire",
    "who said you could do that?",
];

pub(super) fn dim() -> Style {
    Style::new().fg(DIM)
}

pub(super) fn sel_style() -> Style {
    Style::new().add_modifier(Modifier::REVERSED)
}

pub use crate::cli::local_time;

pub(super) fn rate(b: u64) -> String {
    if b == 0 {
        "—".into()
    } else {
        format!("{}/s", human_bytes(b))
    }
}

fn spark(h: Option<&VecDeque<u64>>, width: usize) -> String {
    const BARS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    let Some(h) = h else { return " ".repeat(width) };
    let vals: Vec<u64> = h.iter().rev().take(width).rev().copied().collect();
    let max = vals.iter().copied().max().unwrap_or(0);
    let mut s: String = " ".repeat(width.saturating_sub(vals.len()));
    for v in vals {
        if max == 0 || v == 0 {
            s.push(' ');
        } else {
            // Log scale keeps a trickle visible next to a download.
            let f = ((v as f64).ln_1p() / (max as f64).ln_1p() * 7.0).round() as usize;
            s.push(BARS[f.min(7)]);
        }
    }
    s
}

pub(super) fn ago(ts: u64) -> String {
    if ts == 0 {
        return "—".into();
    }
    let d = now().saturating_sub(ts);
    if d < 5 {
        "now".into()
    } else {
        crate::cli::ago(d)
    }
}

pub(super) fn panel<'a>(title: impl Into<Line<'a>>, focused: bool) -> Block<'a> {
    Block::new()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(if focused {
            Style::new().fg(ACCENT)
        } else {
            dim()
        })
        .title(title)
}

pub(super) fn centered(area: Rect, w: u16, h: u16) -> Rect {
    let [v] = Layout::vertical([Constraint::Length(h.min(area.height))])
        .flex(Flex::Center)
        .areas(area);
    let [r] = Layout::horizontal([Constraint::Length(w.min(area.width))])
        .flex(Flex::Center)
        .areas(v);
    r
}

pub fn draw(f: &mut Frame, app: &App) {
    let area = f.area();
    let [header, tabs, body, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Fill(1),
        Constraint::Length(1),
    ])
    .areas(area);
    draw_header(f, app, header);
    draw_tabs(f, app, tabs);
    match app.tab {
        Tab::Monitor => draw_monitor(f, app, body),
        Tab::Map => super::map::draw_map(f, app, body),
        Tab::Rules => draw_rules(f, app, body),
        Tab::Log => draw_log(f, app, body),
        Tab::Blocklists => draw_blocklists(f, app, body),
        Tab::Settings => draw_settings(f, app, body),
    }
    draw_footer(f, app, footer);

    if !app.connected {
        let r = centered(area, 56, 5);
        f.render_widget(Clear, r);
        f.render_widget(
            Paragraph::new(vec![
                Line::from(format!("{RAT}  lost the daemon")).bold().fg(BAD),
                Line::from("reconnecting… (sudo systemctl status tattle)").fg(DIM),
            ])
            .alignment(Alignment::Center)
            .block(panel(" disconnected ", true)),
            r,
        );
    }

    match &app.modal {
        Modal::None => {}
        Modal::Help => draw_help(f, area),
        Modal::Editor(ed) => draw_editor(f, ed, area),
        Modal::Confirm { text, .. } => {
            let r = centered(area, (text.chars().count() as u16 + 8).clamp(40, 90), 5);
            f.render_widget(Clear, r);
            f.render_widget(
                Paragraph::new(vec![
                    Line::from(text.as_str()),
                    Line::from(vec![
                        Span::raw("y").bold().fg(OK),
                        Span::raw(" yes   "),
                        Span::raw("n").bold().fg(BAD),
                        Span::raw(" no"),
                    ]),
                ])
                .alignment(Alignment::Center)
                .wrap(Wrap { trim: true })
                .block(panel(" confirm ", true)),
                r,
            );
        }
        Modal::Input {
            title,
            fields,
            focus,
            ..
        } => {
            let r = centered(area, 70, fields.len() as u16 * 2 + 4);
            f.render_widget(Clear, r);
            let block = panel(format!(" {title} "), true);
            let inner = block.inner(r);
            f.render_widget(block, r);
            for (i, (label, input)) in fields.iter().enumerate() {
                let y = inner.y + i as u16 * 2;
                let row = Rect {
                    x: inner.x + 1,
                    y,
                    width: inner.width.saturating_sub(2),
                    height: 1,
                };
                let focused = i == *focus;
                let line = Line::from(vec![
                    Span::styled(
                        format!("{label:>10}  "),
                        if focused {
                            Style::new().fg(ACCENT).bold()
                        } else {
                            dim()
                        },
                    ),
                    Span::raw(input.value.clone()),
                ]);
                f.render_widget(Paragraph::new(line), row);
                if focused {
                    let cx = row.x + 12 + input.value.chars().take(input.cursor).count() as u16;
                    f.set_cursor_position((cx.min(row.right().saturating_sub(1)), y));
                }
            }
            let hint = Rect {
                x: inner.x + 1,
                y: inner.bottom().saturating_sub(1),
                width: inner.width.saturating_sub(2),
                height: 1,
            };
            f.render_widget(
                Paragraph::new("enter save · tab next field · esc cancel").fg(DIM),
                hint,
            );
        }
        Modal::Presets { sel } => {
            let presets = crate::daemon::blocklist::PRESETS;
            let r = centered(area, 86, presets.len() as u16 * 2 + 4);
            f.render_widget(Clear, r);
            let lines: Vec<Line> = presets
                .iter()
                .enumerate()
                .flat_map(|(i, (n, u))| {
                    let s = if i == *sel { sel_style() } else { Style::new() };
                    vec![
                        Line::styled(format!(" {n} "), s.bold()),
                        Line::styled(format!("   {u}"), dim()),
                    ]
                })
                .collect();
            f.render_widget(
                Paragraph::new(lines)
                    .block(panel(" well-known blocklists · enter subscribe ", true)),
                r,
            );
        }
    }

    if !app.prompts.is_empty() && !app.alert_hidden {
        draw_alert(f, app, area);
    }
}

fn draw_header(f: &mut Frame, app: &App, area: Rect) {
    let s = &app.status;
    let tag = TAGLINES[(app.tick / 120) as usize % TAGLINES.len()];
    let left = Line::from(vec![
        Span::styled(format!(" {RAT} "), Style::new().fg(ACCENT).bold()),
        Span::styled("tattle", Style::new().bold()),
        Span::styled(format!("  {tag}"), dim().add_modifier(Modifier::ITALIC)),
    ]);
    let (mode_txt, mode_col) = if !s.settings.enabled {
        ("○ OFF".to_string(), DIM)
    } else {
        match s.settings.mode {
            Mode::Alert => ("● ALERT".to_string(), ACCENT),
            Mode::SilentAllow => ("● SILENT·ALLOW".to_string(), OK),
            Mode::SilentDeny => ("● SILENT·DENY".to_string(), BAD),
        }
    };
    let mut right = vec![
        Span::styled(format!("↑ {} ", rate(s.tx_rate)), Style::new().fg(UP)),
        Span::styled(format!("↓ {}  ", rate(s.rx_rate)), Style::new().fg(INFO)),
        Span::styled(format!("✓{} ", s.allowed), Style::new().fg(OK)),
        Span::styled(format!("✗{}  ", s.denied), Style::new().fg(BAD)),
    ];
    if let Some(p) = &s.settings.active_profile {
        right.push(Span::styled(format!("◆ {p}  "), Style::new().fg(INFO)));
    }
    if !app.prompts.is_empty() {
        let blink = if app.tick % 4 < 2 {
            Modifier::BOLD
        } else {
            Modifier::DIM
        };
        right.push(Span::styled(
            format!("⚑ {} waiting  ", app.prompts.len()),
            Style::new().fg(ACCENT).add_modifier(blink),
        ));
    }
    right.push(Span::styled(
        format!("{mode_txt} "),
        Style::new().fg(mode_col).bold(),
    ));
    let right = Line::from(right);
    let rw = right.width() as u16;
    let [l, r] = Layout::horizontal([Constraint::Fill(1), Constraint::Length(rw)]).areas(area);
    f.render_widget(Paragraph::new(left), l);
    f.render_widget(Paragraph::new(right), r);
}

fn draw_tabs(f: &mut Frame, app: &App, area: Rect) {
    let titles: Vec<Line> = Tab::ALL
        .iter()
        .enumerate()
        .map(|(i, t)| {
            let mut spans = vec![
                Span::styled(format!("{} ", i + 1), dim()),
                Span::raw(t.title()),
            ];
            if *t == Tab::Rules {
                spans.push(Span::styled(format!(" {}", app.rules.len()), dim()));
            }
            Line::from(spans)
        })
        .collect();
    let idx = Tab::ALL.iter().position(|t| *t == app.tab).unwrap_or(0);
    f.render_widget(
        Tabs::new(titles)
            .select(idx)
            .highlight_style(
                Style::new()
                    .fg(ACCENT)
                    .bold()
                    .add_modifier(Modifier::UNDERLINED),
            )
            .divider(Span::styled("│", dim()))
            .padding(" ", " "),
        area,
    );
}

pub(super) fn filter_title(app: &App) -> Span<'static> {
    if app.filtering || !app.filter.value.is_empty() {
        Span::styled(
            format!(
                " /{}{} ",
                app.filter.value,
                if app.filtering { "▏" } else { "" }
            ),
            Style::new().fg(ACCENT),
        )
    } else {
        Span::raw("")
    }
}

fn draw_monitor(f: &mut Frame, app: &App, area: Rect) {
    let [top, chart] = Layout::vertical([Constraint::Fill(1), Constraint::Length(6)]).areas(area);
    let [left, right] =
        Layout::horizontal([Constraint::Percentage(44), Constraint::Percentage(56)]).areas(top);

    // Apps.
    let apps = app.sorted_apps();
    let rows: Vec<Row> = apps
        .iter()
        .map(|a| {
            let r = app.rates.get(&a.identity);
            let total = r.map(|r| r.tx_rate + r.rx_rate).unwrap_or(0);
            let live = r.map(|r| r.active).unwrap_or(a.active);
            let name_style = if live > 0 {
                Style::new().bold()
            } else {
                Style::new()
            };
            Row::new(vec![
                Cell::from(Line::from(vec![
                    Span::styled(if live > 0 { "● " } else { "  " }, Style::new().fg(OK)),
                    Span::styled(a.name.clone(), name_style),
                ])),
                Cell::from(Span::styled(
                    spark(app.app_history.get(&a.identity), 10),
                    Style::new().fg(INFO),
                )),
                Cell::from(Line::from(rate(total)).alignment(Alignment::Right)),
                Cell::from(Line::from(vec![
                    Span::styled(format!("{:>4}", a.allowed), Style::new().fg(OK)),
                    Span::raw(" "),
                    Span::styled(
                        format!(
                            "{:<4}",
                            if a.denied > 0 {
                                a.denied.to_string()
                            } else {
                                String::new()
                            }
                        ),
                        Style::new().fg(BAD),
                    ),
                ])),
            ])
        })
        .collect();
    let focused = app.focus == Focus::Apps;
    let title = Line::from(vec![
        Span::raw(" Apps "),
        Span::styled(
            format!("{} · sorted by {} ", apps.len(), app.sort.label()),
            dim(),
        ),
        filter_title(app),
    ]);
    let table = Table::new(
        rows,
        [
            Constraint::Fill(1),
            Constraint::Length(10),
            Constraint::Length(11),
            Constraint::Length(9),
        ],
    )
    .header(Row::new(["  app", "activity", "rate", "  ✓    ✗"]).style(dim()))
    .row_highlight_style(if focused {
        sel_style()
    } else {
        Style::new().add_modifier(Modifier::BOLD)
    })
    .block(panel(title, focused));
    let mut st = TableState::default().with_selected(if apps.is_empty() {
        None
    } else {
        Some(app.app_sel.min(apps.len() - 1))
    });
    f.render_stateful_widget(table, left, &mut st);
    if apps.is_empty() {
        let msg = if app.filter.value.is_empty() {
            format!("{RAT}\n\nall quiet… nothing has talked to the network yet")
        } else {
            "no app matches the filter".into()
        };
        f.render_widget(
            Paragraph::new(msg).alignment(Alignment::Center).fg(DIM),
            centered(left, 40, 4),
        );
    }

    // Detail.
    let block = panel(" Connections ", app.focus == Focus::Remotes);
    let inner = block.inner(right);
    f.render_widget(block, right);
    if let Some(a) = app.selected_app() {
        let [info, list] =
            Layout::vertical([Constraint::Length(4), Constraint::Fill(1)]).areas(inner);
        let r = app.rates.get(&a.identity);
        let lines = vec![
            Line::from(vec![
                Span::styled(a.name.clone(), Style::new().bold().fg(ACCENT)),
                Span::styled(format!("   pid {} · {}", a.last_pid, a.user), dim()),
            ]),
            Line::styled(a.identity.clone(), dim()),
            Line::from(vec![
                Span::styled(format!("↑ {} ", human_bytes(a.tx)), Style::new().fg(UP)),
                Span::styled(format!("↓ {}   ", human_bytes(a.rx)), Style::new().fg(INFO)),
                Span::styled(
                    format!(
                        "now ↑ {} ↓ {}   ",
                        rate(r.map_or(0, |r| r.tx_rate)),
                        rate(r.map_or(0, |r| r.rx_rate))
                    ),
                    dim(),
                ),
                Span::styled(format!("{} live", r.map_or(a.active, |r| r.active)), dim()),
            ]),
        ];
        f.render_widget(
            Paragraph::new(lines),
            info.inner(Margin {
                horizontal: 1,
                vertical: 0,
            }),
        );
        let rows: Vec<Row> = a
            .remotes
            .iter()
            .map(|rm| {
                let (g, c) = match rm.last_action {
                    Some(Action::Deny) => ("✗", BAD),
                    _ => ("✓", OK),
                };
                let mut ports: Vec<String> = rm.ports.iter().map(|p| p.to_string()).collect();
                if ports.len() > 3 {
                    ports.truncate(3);
                    ports.push("…".into());
                }
                Row::new(vec![
                    Cell::from(Span::styled(g, Style::new().fg(c))),
                    Cell::from(rm.host.clone()),
                    Cell::from(Span::styled(
                        rm.geo.as_ref().map(|g| g.cc.clone()).unwrap_or_default(),
                        dim(),
                    )),
                    Cell::from(Span::styled(
                        format!("{}/{}", rm.proto, ports.join(",")),
                        dim(),
                    )),
                    Cell::from(
                        Line::from(human_bytes(rm.tx))
                            .alignment(Alignment::Right)
                            .fg(UP),
                    ),
                    Cell::from(
                        Line::from(human_bytes(rm.rx))
                            .alignment(Alignment::Right)
                            .fg(INFO),
                    ),
                    Cell::from(
                        Line::from(ago(rm.last_seen))
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
                Constraint::Fill(1),
                Constraint::Length(2),
                Constraint::Length(12),
                Constraint::Length(8),
                Constraint::Length(8),
                Constraint::Length(8),
            ],
        )
        .header(Row::new(vec!["", "server", "", "port", "sent", "recv", "seen"]).style(dim()))
        .row_highlight_style(if app.focus == Focus::Remotes {
            sel_style()
        } else {
            Style::new()
        })
        .column_spacing(1);
        let mut st = TableState::default().with_selected(
            if app.focus == Focus::Remotes && !a.remotes.is_empty() {
                Some(app.remote_sel.min(a.remotes.len() - 1))
            } else {
                None
            },
        );
        f.render_stateful_widget(
            t,
            list.inner(Margin {
                horizontal: 1,
                vertical: 0,
            }),
            &mut st,
        );
    }

    // Traffic chart.
    let block = panel(
        Line::from(vec![
            Span::raw(" Traffic "),
            Span::styled(
                format!("↑ {} ", rate(app.status.tx_rate)),
                Style::new().fg(UP),
            ),
            Span::styled(
                format!("↓ {} ", rate(app.status.rx_rate)),
                Style::new().fg(INFO),
            ),
            Span::styled(format!("· last {} min ", HISTORY * 2 / 60), dim()),
        ]),
        false,
    );
    let inner = block.inner(chart);
    f.render_widget(block, chart);
    let [up, down] = Layout::vertical([Constraint::Length(2), Constraint::Length(2)]).areas(inner);
    let w = inner.width as usize;
    let tail = |h: &VecDeque<u64>| -> Vec<u64> { h.iter().rev().take(w).rev().copied().collect() };
    f.render_widget(
        Sparkline::default()
            .data(tail(&app.tx_hist))
            .style(Style::new().fg(UP))
            .bar_set(symbols::bar::NINE_LEVELS),
        up,
    );
    f.render_widget(
        Sparkline::default()
            .data(tail(&app.rx_hist))
            .style(Style::new().fg(INFO))
            .bar_set(symbols::bar::NINE_LEVELS),
        down,
    );
}

fn lifetime_text(r: &Rule) -> String {
    match r.lifetime {
        Lifetime::Forever => String::new(),
        Lifetime::UntilQuit { pid, .. } => format!("until pid {pid} quits"),
        Lifetime::Until { at } => {
            let left = at.saturating_sub(now());
            if left >= 3600 {
                format!("{}h left", left.div_ceil(3600))
            } else {
                format!("{}m left", left.div_ceil(60))
            }
        }
    }
}

fn draw_rules(f: &mut Frame, app: &App, area: Rect) {
    let rules = app.filtered_rules();
    let rows: Vec<Row> = rules
        .iter()
        .map(|r| {
            let base = if r.enabled {
                Style::new()
            } else {
                dim().add_modifier(Modifier::CROSSED_OUT)
            };
            let (act, col) = match r.action {
                Action::Allow => ("allow", OK),
                Action::Deny => ("deny", BAD),
            };
            let port = match (r.port, r.proto) {
                (None, Proto::Any) => "any".to_string(),
                (None, p) => p.to_string(),
                (Some(p), Proto::Any) => p.to_string(),
                (Some(p), pr) => format!("{pr}/{p}"),
            };
            let mut scope = Vec::new();
            if r.direction == Direction::In {
                scope.push("← in".to_string());
            }
            if let Some(p) = &r.profile {
                scope.push(format!("◆ {p}"));
            }
            let lt = lifetime_text(r);
            if !lt.is_empty() {
                scope.push(lt);
            }
            if r.source == RuleSource::Default {
                scope.push("built-in".into());
            }
            Row::new(vec![
                Cell::from(Span::styled(
                    if r.enabled { "●" } else { "○" },
                    Style::new().fg(if r.enabled { col } else { DIM }),
                )),
                Cell::from(Span::styled(act, Style::new().fg(col).bold())),
                Cell::from(Span::styled(
                    display_name(&r.process),
                    base.add_modifier(Modifier::BOLD),
                )),
                Cell::from(Span::styled(r.remote.describe(), base)),
                Cell::from(Span::styled(port, base)),
                Cell::from(Span::styled(scope.join(" · "), Style::new().fg(INFO))),
                Cell::from(Line::from(r.hits.to_string()).alignment(Alignment::Right)),
                Cell::from(
                    Line::from(r.last_hit.map(ago).unwrap_or_else(|| "—".into()))
                        .alignment(Alignment::Right)
                        .fg(DIM),
                ),
            ])
            .style(if r.source == RuleSource::Default {
                dim()
            } else {
                Style::new()
            })
        })
        .collect();
    let [list, detail] = Layout::vertical([Constraint::Fill(1), Constraint::Length(4)]).areas(area);
    let title = Line::from(vec![
        Span::raw(" Rules "),
        Span::styled(format!("{} ", rules.len()), dim()),
        filter_title(app),
    ]);
    let t = Table::new(
        rows,
        [
            Constraint::Length(1),
            Constraint::Length(5),
            Constraint::Length(20),
            Constraint::Fill(2),
            Constraint::Length(11),
            Constraint::Fill(1),
            Constraint::Length(6),
            Constraint::Length(8),
        ],
    )
    .header(
        Row::new(vec![
            "", "", "process", "server", "port", "scope", "hits", "last",
        ])
        .style(dim()),
    )
    .row_highlight_style(sel_style())
    .block(panel(title, true));
    let mut st = TableState::default().with_selected(if rules.is_empty() {
        None
    } else {
        Some(app.rule_sel.min(rules.len() - 1))
    });
    f.render_stateful_widget(t, list, &mut st);
    if let Some(r) = rules.get(app.rule_sel) {
        let mut lines = vec![Line::from(vec![Span::styled(
            r.summary(),
            Style::new().bold(),
        )])];
        lines.push(Line::styled(
            format!(
                "{}  ·  created {}{}",
                r.process,
                local_time(r.created, true),
                if r.note.is_empty() {
                    String::new()
                } else {
                    format!("  ·  {}", r.note)
                }
            ),
            dim(),
        ));
        f.render_widget(
            Paragraph::new(lines).block(panel(format!(" rule #{} ", r.id), false)),
            detail,
        );
    }
}

fn reason_text(e: &ConnEvent) -> String {
    match e.reason {
        Reason::Rule => e
            .rule_id
            .map(|r| format!("rule #{r}"))
            .unwrap_or_else(|| "rule".into()),
        Reason::Blocklist => "blocklist".into(),
        Reason::Prompt => "you said so".into(),
        Reason::Mode => "silent mode".into(),
        Reason::NoUi => "no alert UI".into(),
        Reason::Timeout => "alert timed out".into(),
        Reason::Disabled => "filter off".into(),
        Reason::Own => "tattle itself".into(),
    }
}

fn draw_log(f: &mut Frame, app: &App, area: Rect) {
    let events = app.filtered_log();
    let rows: Vec<Row> = events
        .iter()
        .take(2000)
        .map(|e| {
            let (g, c) = if e.action == Action::Allow {
                ("✓", OK)
            } else {
                ("✗", BAD)
            };
            let port = if e.conn.direction == Direction::Out {
                e.conn.remote_port
            } else {
                e.conn.local_port
            };
            Row::new(vec![
                Cell::from(Span::styled(local_time(e.ts, false), dim())),
                Cell::from(Span::styled(g, Style::new().fg(c).bold())),
                Cell::from(Span::styled(e.conn.process.name(), Style::new().bold())),
                Cell::from(if e.conn.direction == Direction::Out {
                    "→"
                } else {
                    "←"
                }),
                Cell::from(e.conn.host()),
                Cell::from(Span::styled(format!("{}/{}", e.conn.proto, port), dim())),
                Cell::from(Span::styled(
                    reason_text(e),
                    if e.action == Action::Deny {
                        Style::new().fg(BAD)
                    } else {
                        dim()
                    },
                )),
            ])
        })
        .collect();
    let title = Line::from(vec![
        Span::raw(" Log "),
        Span::styled(
            if app.log_sel.is_none() {
                "● live "
            } else {
                "‖ paused "
            },
            Style::new().fg(if app.log_sel.is_none() { OK } else { ACCENT }),
        ),
        Span::styled(
            if app.log_denied_only {
                "· denied only "
            } else {
                ""
            },
            Style::new().fg(BAD),
        ),
        filter_title(app),
    ]);
    let t = Table::new(
        rows,
        [
            Constraint::Length(8),
            Constraint::Length(1),
            Constraint::Length(20),
            Constraint::Length(1),
            Constraint::Fill(1),
            Constraint::Length(10),
            Constraint::Length(16),
        ],
    )
    .header(Row::new(vec!["time", "", "app", "", "server", "port", "why"]).style(dim()))
    .row_highlight_style(sel_style())
    .block(panel(title, true));
    let mut st = TableState::default().with_selected(app.log_sel);
    f.render_stateful_widget(t, area, &mut st);
}

fn draw_blocklists(f: &mut Frame, app: &App, area: Rect) {
    let lists = &app.status.settings.blocklists;
    let block = panel(
        Line::from(vec![
            Span::raw(" Blocklists "),
            Span::styled(
                format!("{} domains blocked ", app.status.blocked_domains),
                dim(),
            ),
        ]),
        true,
    );
    if lists.is_empty() {
        let inner = block.inner(area);
        f.render_widget(block, area);
        f.render_widget(
            Paragraph::new(vec![
                Line::from(RAT).fg(ACCENT),
                Line::from(""),
                Line::from("No blocklists yet."),
                Line::from("Subscribe to one and tattle will refuse ads, trackers and malware hosts for every app."),
                Line::from(""),
                Line::from(vec![Span::styled("p", Style::new().fg(ACCENT).bold()), Span::raw(" pick a well-known list   "), Span::styled("n", Style::new().fg(ACCENT).bold()), Span::raw(" add your own URL")]),
            ])
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: true }),
            centered(inner, 70, 7),
        );
        return;
    }
    let rows: Vec<Row> = lists
        .iter()
        .map(|b| {
            let status = match (&b.error, b.updated) {
                (Some(e), _) => Span::styled(format!("⚠ {e}"), Style::new().fg(BAD)),
                (None, Some(u)) => Span::styled(format!("updated {}", ago(u)), dim()),
                (None, None) => Span::styled("downloading…", Style::new().fg(ACCENT)),
            };
            Row::new(vec![
                Cell::from(Span::styled(
                    if b.enabled { "●" } else { "○" },
                    Style::new().fg(if b.enabled { OK } else { DIM }),
                )),
                Cell::from(Span::styled(b.name.clone(), Style::new().bold())),
                Cell::from(Line::from(format!("{}", b.entries)).alignment(Alignment::Right)),
                Cell::from(status),
                Cell::from(Span::styled(b.url.clone(), dim())),
            ])
            .height(1)
        })
        .collect();
    let t = Table::new(
        rows,
        [
            Constraint::Length(1),
            Constraint::Length(24),
            Constraint::Length(9),
            Constraint::Length(22),
            Constraint::Fill(1),
        ],
    )
    .header(Row::new(vec!["", "name", "domains", "status", "source"]).style(dim()))
    .row_highlight_style(sel_style())
    .block(block);
    let mut st = TableState::default().with_selected(Some(app.list_sel.min(lists.len() - 1)));
    f.render_stateful_widget(t, area, &mut st);
}

fn draw_settings(f: &mut Frame, app: &App, area: Rect) {
    let rows = app.settings_rows();
    let lines: Vec<Row> = rows
        .iter()
        .map(|(k, v, hint)| {
            let vstyle = match v.as_str() {
                "on" | "yes" | "allow" | "active" => Style::new().fg(OK).bold(),
                "off" | "no" | "deny" => Style::new().fg(BAD).bold(),
                _ => Style::new().fg(ACCENT).bold(),
            };
            Row::new(vec![
                Cell::from(k.clone()),
                Cell::from(Span::styled(v.clone(), vstyle)),
                Cell::from(Span::styled(*hint, dim())),
            ])
        })
        .collect();
    let [list, about] = Layout::vertical([Constraint::Fill(1), Constraint::Length(5)]).areas(area);
    let t = Table::new(
        lines,
        [
            Constraint::Length(32),
            Constraint::Length(22),
            Constraint::Fill(1),
        ],
    )
    .row_highlight_style(sel_style())
    .block(panel(" Settings ", true));
    let mut st = TableState::default().with_selected(Some(app.setting_sel.min(rows.len() - 1)));
    f.render_stateful_widget(t, list, &mut st);
    let s = &app.status;
    f.render_widget(
        Paragraph::new(vec![
            Line::from(vec![
                Span::styled(
                    format!("{RAT} tattle {}", s.version),
                    Style::new().fg(ACCENT).bold(),
                ),
                Span::styled(
                    format!(
                        "   daemon pid {} · up {}",
                        s.pid,
                        crate::cli::ago(s.uptime).replace(" ago", "")
                    ),
                    dim(),
                ),
            ]),
            Line::styled(
                format!(
                    "{} names learned from DNS · {} alert UI(s) connected · inbound {}",
                    s.dns_cache,
                    s.ui_clients,
                    if s.inbound_active {
                        "filtered"
                    } else {
                        "not filtered"
                    }
                ),
                dim(),
            ),
            Line::styled(
                "Rules and settings live in /var/lib/tattle. `tattle export` backs up your rules.",
                dim(),
            ),
        ])
        .block(panel(" about ", false)),
        about,
    );
}

fn draw_footer(f: &mut Frame, app: &App, area: Rect) {
    if let Some((msg, is_err, _)) = &app.toast {
        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(
                    if *is_err { " ✗ " } else { " ✓ " },
                    Style::new().fg(if *is_err { BAD } else { OK }).bold(),
                ),
                Span::raw(msg.clone()),
            ])),
            area,
        );
        return;
    }
    let keys: &[(&str, &str)] = match app.tab {
        Tab::Monitor => &[
            ("↑↓", "select"),
            ("tab", "pane"),
            ("a/d", "allow/deny"),
            ("A/D", "whole app"),
            ("n", "new rule"),
            ("s", "sort"),
        ],
        Tab::Map if app.map_servers => &[
            ("↑↓", "server"),
            ("←", "places"),
            ("a/d", "allow/deny"),
            ("w", "time window"),
        ],
        Tab::Map => &[
            ("↑↓", "place"),
            ("→", "servers"),
            ("w", "time window"),
            ("u", "update location data"),
        ],
        Tab::Rules => &[
            ("↑↓", "select"),
            ("enter", "edit"),
            ("n", "new"),
            ("space", "on/off"),
            ("t", "flip"),
            ("x", "delete"),
        ],
        Tab::Log => &[
            ("↑↓", "pause & select"),
            ("esc", "live"),
            ("a/d", "allow/deny"),
            ("b", "denied only"),
        ],
        Tab::Blocklists => &[
            ("p", "presets"),
            ("n", "add url"),
            ("space", "on/off"),
            ("r", "refresh"),
            ("x", "remove"),
        ],
        Tab::Settings => &[("↑↓", "select"), ("←→/space", "change")],
    };
    let mut spans = vec![Span::raw(" ")];
    for (k, v) in keys
        .iter()
        .chain([("/", "filter"), ("m", "mode"), ("?", "help"), ("q", "quit")].iter())
    {
        spans.push(Span::styled(*k, Style::new().fg(ACCENT).bold()));
        spans.push(Span::styled(format!(" {v}  "), dim()));
    }
    if app.alert_hidden && !app.prompts.is_empty() {
        spans.insert(
            0,
            Span::styled(
                format!(" ! {} alert(s) waiting ", app.prompts.len()),
                Style::new().fg(Color::Black).bg(ACCENT).bold(),
            ),
        );
    }
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn draw_help(f: &mut Frame, area: Rect) {
    let r = centered(area, 72, 27);
    f.render_widget(Clear, r);
    let k = |key: &str, what: &str| {
        Line::from(vec![
            Span::styled(format!("{key:>12}  "), Style::new().fg(ACCENT).bold()),
            Span::raw(what.to_string()),
        ])
    };
    let lines = vec![
        Line::from(format!(
            "{RAT}  tattle — an application firewall that snitches"
        ))
        .bold(),
        Line::from(""),
        k("1-6 / ⇧tab", "switch tabs"),
        k("/", "filter the current list"),
        k("m", "cycle mode: alert → silent allow → silent deny"),
        k("F", "turn filtering on or off"),
        k("!", "show waiting alerts"),
        Line::from(""),
        Line::styled("  in an alert", dim()),
        k("a / d", "allow / deny"),
        k("↑↓ ←→", "pick server, port, process and duration"),
        k("s p o f", "cycle server / port / process / duration"),
        k("esc", "decide later (the countdown keeps running)"),
        Line::from(""),
        Line::styled("  on the map", dim()),
        k("w", "time window: last minute, hour, day, since start"),
        k("→ then a / d", "allow / deny one app → server from a place"),
        Line::from(""),
        Line::styled("  rule precedence (strongest first)", dim()),
        Line::from("    exact host › domain › IP range › local network › any server"),
        Line::from("    then: one port › port range › any port"),
        Line::from("    then: one app › any app,  your rules › built-ins,  deny › allow"),
        Line::from(""),
        Line::styled("  press any key to close", dim()),
    ];
    f.render_widget(Paragraph::new(lines).block(panel(" help ", true)), r);
}

fn draw_editor(f: &mut Frame, ed: &RuleEditor, area: Rect) {
    let r = centered(area, 78, FIELDS.len() as u16 + 6);
    f.render_widget(Clear, r);
    let title = if ed.base.is_some() {
        " edit rule "
    } else {
        " new rule "
    };
    let block = panel(title, true);
    let inner = block.inner(r);
    f.render_widget(block, r);
    for (i, name) in FIELDS.iter().enumerate() {
        let row = Rect {
            x: inner.x + 1,
            y: inner.y + i as u16,
            width: inner.width.saturating_sub(2),
            height: 1,
        };
        let focused = ed.field == i;
        let value = ed.value(i);
        let vstyle = match (i, value.as_str()) {
            (0, "allow") => Style::new().fg(OK).bold(),
            (0, "deny") => Style::new().fg(BAD).bold(),
            _ if !ed.is_text(i) => Style::new().fg(ACCENT),
            _ => Style::new(),
        };
        let mut spans = vec![
            Span::styled(
                format!("{name:>11}  "),
                if focused {
                    Style::new().fg(ACCENT).bold()
                } else {
                    dim()
                },
            ),
            Span::styled(
                if !ed.is_text(i) {
                    format!("‹ {value} ›")
                } else {
                    value.clone()
                },
                vstyle,
            ),
        ];
        if focused {
            spans.push(Span::styled(format!("   {}", ed.hint(i)), dim()));
        }
        f.render_widget(Paragraph::new(Line::from(spans)), row);
        if focused && ed.is_text(i) {
            let cur = match i {
                2 => ed.process.cursor,
                3 => ed.remote.cursor,
                4 => ed.port.cursor,
                7 => ed.expires.cursor,
                _ => ed.note.cursor,
            };
            let x = row.x + 13 + cur as u16;
            f.set_cursor_position((x.min(row.right().saturating_sub(1)), row.y));
        }
    }
    let y = inner.y + FIELDS.len() as u16 + 1;
    let msg = match &ed.error {
        Some(e) => Line::styled(format!(" ✗ {e}"), Style::new().fg(BAD)),
        None => Line::styled(" enter save · tab/↑↓ move · ←→ change · esc cancel", dim()),
    };
    f.render_widget(
        Paragraph::new(msg),
        Rect {
            x: inner.x,
            y,
            width: inner.width,
            height: 1,
        },
    );
}

fn chips<'a>(opts: &[String], sel: usize, focused: bool) -> Vec<Span<'a>> {
    let mut v = Vec::new();
    for (i, o) in opts.iter().enumerate() {
        let st = if i == sel {
            if focused {
                Style::new().fg(Color::Black).bg(ACCENT).bold()
            } else {
                Style::new()
                    .fg(ACCENT)
                    .bold()
                    .add_modifier(Modifier::UNDERLINED)
            }
        } else {
            dim()
        };
        v.push(Span::styled(format!(" {o} "), st));
        v.push(Span::raw(" "));
    }
    v
}

fn draw_alert(f: &mut Frame, app: &App, area: Rect) {
    let p = &app.prompts[0];
    let c = &p.conn;
    // 5 rows of header, 4 of choices, 2 of buttons, spacing, borders and margins.
    let r = centered(area, 100, 17);
    f.render_widget(Clear, r);
    let title = if app.prompts.len() > 1 {
        format!(" ⚑ connection alert · 1 of {} ", app.prompts.len())
    } else {
        " ⚑ connection alert ".to_string()
    };
    let block = Block::new()
        .borders(Borders::ALL)
        .border_type(BorderType::Thick)
        .border_style(Style::new().fg(ACCENT))
        .title(title);
    let inner = block.inner(r).inner(Margin {
        horizontal: 2,
        vertical: 1,
    });
    f.render_widget(block, r);

    let port = if c.direction == Direction::Out {
        c.remote_port
    } else {
        c.local_port
    };
    let service = p
        .service
        .as_ref()
        .map(|s| format!(" ({s})"))
        .unwrap_or_default();
    let verb = if c.direction == Direction::Out {
        "wants to connect to"
    } else {
        "is being contacted by"
    };
    let mut who = vec![
        Span::styled(c.process.name(), Style::new().bold().fg(ACCENT)),
        Span::raw(format!(" {verb}")),
    ];
    if p.attempts > 1 {
        who.push(Span::styled(format!("  ×{}", p.attempts), dim()));
    }
    let host_line = Line::from(vec![
        Span::styled(c.host(), Style::new().bold()),
        Span::raw(format!(
            " on {} port {port}{service}",
            c.proto.to_string().to_uppercase()
        )),
    ]);
    let mut meta = format!(
        "{} · pid {} · {}",
        c.process.exe, c.process.pid, c.process.user
    );
    if !c.hostnames.is_empty() {
        meta.push_str(&format!(" · {}", canonical_ip(c.remote_ip)));
    }
    let mut head = vec![Line::from(who), host_line];
    if let Some(g) = &p.geo {
        let mut spans = vec![
            Span::styled("in ", dim()),
            Span::styled(g.place(), Style::new().fg(INFO)),
        ];
        if let Some(org) = &g.org {
            spans.push(Span::styled(format!(" · {org}"), dim()));
        }
        head.push(Line::from(spans));
    }
    head.push(Line::styled(meta, dim()));
    if c.process.exe_deleted {
        head.push(Line::styled(
            "⚠ this program's file changed since it started",
            Style::new().fg(BAD),
        ));
    }
    if let Some(s) = &c.process.script {
        head.push(Line::styled(format!("script: {s}"), dim()));
    }
    let [h, _, opts, _, buttons] = Layout::vertical([
        Constraint::Length(5),
        Constraint::Length(1),
        Constraint::Length(4),
        Constraint::Length(1),
        Constraint::Length(2),
    ])
    .areas(inner);
    let [face, text] = Layout::horizontal([Constraint::Length(7), Constraint::Fill(1)]).areas(h);
    let wiggle = if app.tick % 8 < 4 {
        "ᘛ⁐ᕐᐷ"
    } else {
        "ᘛ⁐ᕐᐷ'"
    };
    f.render_widget(
        Paragraph::new(vec![
            Line::from(""),
            Line::styled(wiggle, Style::new().fg(ACCENT).bold()),
        ]),
        face,
    );
    f.render_widget(Paragraph::new(head).wrap(Wrap { trim: true }), text);

    let clip = |s: String| {
        if s.chars().count() > 23 {
            format!("{}…", s.chars().take(22).collect::<String>())
        } else {
            s
        }
    };
    let ropts: Vec<String> = remote_options(p)
        .into_iter()
        .map(|(_, s)| clip(s))
        .collect();
    let rows: [(&str, Vec<String>, usize); 4] = [
        ("server", ropts, app.alert.remote),
        (
            "port",
            vec![format!("only {port}"), "any port".into()],
            app.alert.port,
        ),
        (
            "app",
            vec![format!("only {}", c.process.name()), "any app".into()],
            app.alert.process,
        ),
        (
            "for",
            LIFETIMES.iter().map(|(l, _)| l.to_string()).collect(),
            app.alert.lifetime,
        ),
    ];
    let lines: Vec<Line> = rows
        .iter()
        .enumerate()
        .map(|(i, (label, o, sel))| {
            let focused = i == app.alert.row;
            let mut spans = vec![Span::styled(
                format!("{label:>7}  "),
                if focused {
                    Style::new().fg(ACCENT).bold()
                } else {
                    dim()
                },
            )];
            spans.extend(chips(o, (*sel).min(o.len() - 1), focused));
            Line::from(spans)
        })
        .collect();
    f.render_widget(Paragraph::new(lines), opts);

    let [b, g] = Layout::horizontal([Constraint::Length(36), Constraint::Fill(1)]).areas(buttons);
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(" a  Allow ", Style::new().fg(Color::Black).bg(OK).bold()),
            Span::raw("   "),
            Span::styled(" d  Deny ", Style::new().fg(Color::Black).bg(BAD).bold()),
            Span::styled("   esc later", dim()),
        ])),
        b,
    );
    let total = p.deadline.saturating_sub(p.created).max(1);
    let left = p.deadline.saturating_sub(now());
    f.render_widget(
        LineGauge::default()
            .ratio((left as f64 / total as f64).clamp(0.0, 1.0))
            .label(Span::styled(format!("{left:>2}s "), dim()))
            .filled_style(Style::new().fg(if left < 10 { BAD } else { ACCENT }))
            .unfilled_style(dim())
            .filled_symbol(symbols::line::THICK_HORIZONTAL)
            .unfilled_symbol(symbols::line::THICK_HORIZONTAL),
        Rect { height: 1, ..g },
    );
}
