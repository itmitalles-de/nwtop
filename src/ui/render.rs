//! Snapshot rendering; input and runtime preference changes belong to App.

use super::{App, Overlay, format_bytes, format_rate, pid, totals};
use crate::{config::PlotColor, i18n::Lang};
use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Cell, Paragraph, Row, Table},
};

mod graph;
mod overlays;

use graph::draw_graph;
use overlays::{draw_help, draw_interfaces, draw_setup, draw_sort};

const RX: Color = Color::Green;
const TX: Color = Color::Yellow;
const KEY: Color = Color::Cyan;
const DIM: Color = Color::DarkGray;
fn inverse(color: Color) -> Style {
    // ncurses A_STANDOUT: reverse the terminal's own foreground/background.
    Style::default().fg(color).add_modifier(Modifier::REVERSED)
}

fn plot_color(color: PlotColor) -> Color {
    match color {
        PlotColor::Green => Color::Green,
        PlotColor::Yellow => Color::Yellow,
        PlotColor::Cyan => Color::Cyan,
        PlotColor::Red => Color::Red,
        PlotColor::Blue => Color::Blue,
        PlotColor::Magenta => Color::Magenta,
        PlotColor::White => Color::White,
    }
}

fn number_cell(text: String) -> Cell<'static> {
    Cell::from(Line::from(text).alignment(Alignment::Right))
}

pub fn draw(frame: &mut Frame<'_>, app: &mut App) {
    let area = frame.area();
    if area.width < 36 || area.height < 16 {
        frame.render_widget(
            Paragraph::new(app.lang().pick(
                "nwtop\nTerminal too small.\nUse at least 36 x 16.\nq / F10 to quit.",
                "nwtop\nTerminal zu klein.\nMindestens 36 x 16.\nq / F10 beendet.",
            ))
            .style(Style::default().fg(if app.settings.color {
                KEY
            } else {
                Color::Reset
            })),
            area,
        );
        return;
    }
    let graph_height = if app.settings.show_graph {
        ((area.height.saturating_sub(9)) / 2).clamp(6, 13)
    } else {
        0
    };
    let status = status_line(app);
    let layout = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(3),
        Constraint::Length(graph_height),
        Constraint::Length(u16::from(status.is_some())),
        Constraint::Min(4),
        Constraint::Length(1),
    ])
    .split(area);
    draw_title(frame, app, layout[0]);
    draw_device(frame, app, layout[1]);
    draw_graph(frame, app, layout[2]);
    if let Some((text, color)) = status {
        frame.render_widget(
            Paragraph::new(text).style(Style::default().fg(color)),
            layout[3],
        );
    }
    draw_table(frame, app, layout[4]);
    draw_footer(frame, app, layout[5]);
    match app.overlay {
        Overlay::Help => draw_help(frame, app, area),
        Overlay::Interfaces => draw_interfaces(frame, app, area),
        Overlay::Setup => draw_setup(frame, app, area),
        Overlay::Sort => draw_sort(frame, app, area),
        Overlay::None => {}
    }
    if !app.settings.color {
        for cell in &mut frame.buffer_mut().content {
            cell.set_fg(Color::Reset).set_bg(Color::Reset);
        }
    }
}

fn draw_title(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let index = app
        .snapshot
        .interfaces
        .iter()
        .position(|iface| Some(&iface.name) == app.interface.as_ref());
    let lang = app.lang();
    let mut spans = vec![
        Span::styled(lang.pick("Device ", "Gerät "), Style::default().fg(RX)),
        Span::raw(index.map_or_else(
            || lang.pick("all", "alle").into(),
            |index| index.to_string(),
        )),
        Span::raw(" ["),
        Span::raw(
            app.interface
                .as_deref()
                .unwrap_or(lang.pick("all interfaces", "alle Schnittstellen")),
        ),
        Span::raw("]"),
    ];
    if app.demo {
        spans.push(Span::styled("  DEMO", Style::default().fg(Color::Magenta)));
    }
    if app.paused {
        spans.push(Span::styled(
            lang.pick("  PAUSED", "  PAUSIERT"),
            Style::default().fg(TX),
        ));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn draw_device(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let device = app
        .snapshot
        .interfaces
        .iter()
        .find(|iface| Some(iface.name.as_str()) == app.interface.as_deref());
    let (rx, tx, rx_total, tx_total) = totals(&app.snapshot, app.interface.as_deref());
    let lang = app.lang();
    let summary = if let Some(iface) = device {
        let mut text = format!("[{}]", iface.state.to_uppercase());
        if let Some(speed) = iface.speed_mbps {
            text.push_str(&format!("  {speed} Mbit/s"));
        }
        if area.width >= 60 {
            if let Some(mtu) = iface.mtu {
                text.push_str(&format!("  MTU {mtu}"));
            }
            if let Some(address) = &iface.address {
                text.push_str(&format!("  {address}"));
            }
        }
        text
    } else if app.interface.is_some() {
        lang.pick("[device unavailable]", "[Gerät nicht verfügbar]")
            .into()
    } else {
        lang.pick(
            "[ALL]  includes virtual interfaces",
            "[ALLE]  inkl. virtueller Schnittstellen",
        )
        .into()
    };
    let peak = app
        .history
        .iter()
        .flat_map(|sample| [sample.rx, sample.tx])
        .fold(1024.0f64, f64::max);
    let line_speed = device
        .and_then(|iface| iface.speed_mbps)
        .filter(|speed| *speed > 0)
        .map(|speed| speed as f64 * 1_000_000.0 / 8.0);
    let scale = line_speed.unwrap_or(peak);
    let lines = vec![
        // Default foreground keeps the summary readable on light and dark themes.
        Line::from(Span::raw(summary)),
        rate_line(
            "RX",
            rx,
            rx_total,
            plot_color(app.settings.rx_color),
            area.width,
            scale,
            line_speed.is_some(),
            app.settings.bits,
            lang,
        ),
        rate_line(
            "TX",
            tx,
            tx_total,
            plot_color(app.settings.tx_color),
            area.width,
            scale,
            line_speed.is_some(),
            app.settings.bits,
            lang,
        ),
    ];
    frame.render_widget(Paragraph::new(lines), area);
}

#[allow(clippy::too_many_arguments)]
fn rate_line(
    label: &str,
    rate: f64,
    total: u64,
    color: Color,
    width: u16,
    scale: f64,
    link: bool,
    bits: bool,
    lang: Lang,
) -> Line<'static> {
    let rate_text = format_rate(rate, bits);
    let suffix = if width >= 78 {
        format!(
            "  {} {}",
            lang.pick("total", "gesamt"),
            format_bytes(total as f64)
        )
    } else {
        String::new()
    };
    let percent = if link && width >= 52 {
        format!(" {:>4.1}%", (rate / scale * 100.0).min(100.0))
    } else {
        String::new()
    };
    let bar_width = (usize::from(width)
        .saturating_sub(label.len() + rate_text.len() + suffix.len() + percent.len() + 6))
    .min(54);
    let fill = ((rate / scale).clamp(0.0, 1.0) * bar_width as f64).round() as usize;
    Line::from(vec![
        Span::styled(label.to_owned(), Style::default().fg(color)),
        Span::raw("["),
        Span::styled("|".repeat(fill), Style::default().fg(color)),
        Span::styled(
            " ".repeat(bar_width.saturating_sub(fill)),
            Style::default().fg(DIM),
        ),
        Span::raw(format!("] {rate_text}{percent}")),
        Span::styled(suffix, Style::default().fg(DIM)),
    ])
}

pub(super) fn status_line(app: &App) -> Option<(String, Color)> {
    let lang = app.lang();
    if let Some(notice) = &app.notice {
        return Some((
            notice.clone(),
            if app.notice_error { Color::Red } else { KEY },
        ));
    }
    if app.searching {
        return Some((
            match lang {
                Lang::En => format!("Search: {}_  Enter apply / Esc clear", app.filter),
                Lang::De => format!("Suche: {}_  Enter übernimmt / Esc leert", app.filter),
            },
            KEY,
        ));
    }
    if !app.filter.is_empty() {
        return Some((
            format!(
                "Filter: {}  {}",
                app.filter,
                lang.pick("Esc clears", "Esc leert")
            ),
            KEY,
        ));
    }
    if app.demo {
        return None; // The device header already identifies synthetic data.
    }
    let capture = &app.snapshot.capture;
    if !capture.active {
        let message = if let Some(message) = lang.capture_status(capture, true) {
            message
        } else if capture.message.is_empty() {
            lang.pick(
                "Interface mode | enable process rates with scripts/setup-capture.sh",
                "Schnittstellenmodus | Prozessraten mit scripts/setup-capture.sh aktivieren",
            )
            .into()
        } else {
            capture.message.clone()
        };
        return Some((message, TX));
    }
    if app.snapshot.capture.dropped > 0 {
        return Some((
            match lang {
                Lang::En => format!(
                    "Capture: {} dropped packets | rates incomplete",
                    app.snapshot.capture.dropped
                ),
                Lang::De => format!(
                    "Capture: {} verworfene Pakete | Raten unvollständig",
                    app.snapshot.capture.dropped
                ),
            },
            TX,
        ));
    }
    // The routine explanation stays in F1 Help; runtime warnings are shown.
    if let Some(message) = lang.capture_status(capture, false) {
        return (!message.is_empty()).then_some((message, TX));
    }
    // Helpers without structured notes send one English text; strip the
    // explanation and preserve any appended warning.
    let message = app.snapshot.capture.message.strip_prefix(
        "Process rates: captured IP bytes; socket/PID owners sampled, brief sockets may be unattributed"
    ).unwrap_or(&app.snapshot.capture.message).trim_start_matches("; ");
    (!message.is_empty()).then(|| (message.to_string(), TX))
}

fn draw_table(frame: &mut Frame<'_>, app: &mut App, area: Rect) {
    app.visible_rows = usize::from(area.height.saturating_sub(1));
    let wide = area.width >= 94;
    let medium = area.width >= 52;
    let captured = app.snapshot.capture.active || app.demo;
    let lang = app.lang();
    let user = lang.pick("USER", "BENUTZER");
    let command = lang.pick("COMMAND", "BEFEHL");
    let remote = lang.pick("REMOTE", "FERN");
    let receive_color = plot_color(app.settings.rx_color);
    let send_color = plot_color(app.settings.tx_color);
    let rate = |value| {
        if captured {
            // The column header already carries /s; retain the whole unit at 40 columns.
            format_rate(value, app.settings.bits)
                .trim_end_matches("/s")
                .to_string()
        } else {
            "-".to_string()
        }
    };
    let total = |value| {
        if captured {
            format_bytes(value as f64)
        } else {
            "-".to_string()
        }
    };
    let (headers, widths, rows): (Vec<&str>, Vec<Constraint>, Vec<Row<'_>>) = if app
        .settings
        .connections
    {
        let records = app.connection_rows();
        if wide {
            (
                vec![
                    "PID",
                    "PROTO",
                    "RX/s",
                    "TX/s",
                    lang.pick("LOCAL", "LOKAL"),
                    remote,
                    command,
                ],
                vec![
                    Constraint::Length(7),
                    Constraint::Length(5),
                    Constraint::Length(12),
                    Constraint::Length(12),
                    Constraint::Percentage(25),
                    Constraint::Percentage(25),
                    Constraint::Min(8),
                ],
                records
                    .into_iter()
                    .map(|row| {
                        Row::new(vec![
                            number_cell(pid(row.pid)),
                            Cell::from(row.protocol.clone()),
                            number_cell(rate(row.rx_rate))
                                .style(Style::default().fg(receive_color)),
                            number_cell(rate(row.tx_rate)).style(Style::default().fg(send_color)),
                            Cell::from(row.local.clone()),
                            Cell::from(row.remote.clone()),
                            Cell::from(row.process.clone()),
                        ])
                    })
                    .collect(),
            )
        } else {
            (
                vec!["PID", "RX/s", "TX/s", remote],
                vec![
                    Constraint::Length(7),
                    Constraint::Length(if medium { 12 } else { 10 }),
                    Constraint::Length(if medium { 12 } else { 10 }),
                    Constraint::Min(6),
                ],
                records
                    .into_iter()
                    .map(|row| {
                        Row::new(vec![
                            number_cell(pid(row.pid)),
                            number_cell(rate(row.rx_rate))
                                .style(Style::default().fg(receive_color)),
                            number_cell(rate(row.tx_rate)).style(Style::default().fg(send_color)),
                            Cell::from(row.remote.clone()),
                        ])
                    })
                    .collect(),
            )
        }
    } else {
        let records = app.process_rows();
        if wide {
            (
                vec![
                    "PID",
                    user,
                    "RX/s",
                    "TX/s",
                    lang.pick("TOTAL", "GESAMT"),
                    lang.pick("CONN", "VERB"),
                    command,
                ],
                vec![
                    Constraint::Length(7),
                    Constraint::Length(10),
                    Constraint::Length(12),
                    Constraint::Length(12),
                    Constraint::Length(12),
                    Constraint::Length(5),
                    Constraint::Min(8),
                ],
                records
                    .into_iter()
                    .map(|row| {
                        Row::new(vec![
                            number_cell(pid(row.pid)),
                            Cell::from(row.user.clone()),
                            number_cell(rate(row.rx_rate))
                                .style(Style::default().fg(receive_color)),
                            number_cell(rate(row.tx_rate)).style(Style::default().fg(send_color)),
                            number_cell(total(row.rx_bytes.saturating_add(row.tx_bytes))),
                            number_cell(row.connections.to_string()),
                            Cell::from(row.name.clone()),
                        ])
                    })
                    .collect(),
            )
        } else if medium {
            (
                vec!["PID", user, "RX/s", "TX/s", command],
                vec![
                    Constraint::Length(7),
                    Constraint::Length(8),
                    Constraint::Length(if area.width >= 64 { 12 } else { 10 }),
                    Constraint::Length(if area.width >= 64 { 12 } else { 10 }),
                    Constraint::Min(6),
                ],
                records
                    .into_iter()
                    .map(|row| {
                        Row::new(vec![
                            number_cell(pid(row.pid)),
                            Cell::from(row.user.clone()),
                            number_cell(rate(row.rx_rate))
                                .style(Style::default().fg(receive_color)),
                            number_cell(rate(row.tx_rate)).style(Style::default().fg(send_color)),
                            Cell::from(row.name.clone()),
                        ])
                    })
                    .collect(),
            )
        } else {
            (
                vec!["PID", "RX/s", "TX/s", command],
                vec![
                    Constraint::Length(7),
                    Constraint::Length(10),
                    Constraint::Length(10),
                    Constraint::Min(5),
                ],
                records
                    .into_iter()
                    .map(|row| {
                        Row::new(vec![
                            number_cell(pid(row.pid)),
                            number_cell(rate(row.rx_rate))
                                .style(Style::default().fg(receive_color)),
                            number_cell(rate(row.tx_rate)).style(Style::default().fg(send_color)),
                            Cell::from(row.name.clone()),
                        ])
                    })
                    .collect(),
            )
        }
    };
    let count = rows.len();
    let header = Row::new(headers.into_iter().map(|header| {
        if matches!(
            header,
            "PID" | "RX/s" | "TX/s" | "TOTAL" | "CONN" | "GESAMT" | "VERB"
        ) {
            number_cell(header.into())
        } else {
            Cell::from(header)
        }
    }))
    .style(inverse(Color::Green));
    let table = Table::new(rows, widths)
        .header(header)
        .column_spacing(1)
        .row_highlight_style(inverse(KEY));
    frame.render_stateful_widget(table, area, &mut app.table);
    if count == 0 && area.height > 1 {
        let message = if app.filter.is_empty() {
            lang.pick(
                "Waiting for network activity...",
                "Warte auf Netzwerkaktivität...",
            )
        } else {
            lang.pick(
                "No matching processes or connections.",
                "Keine passenden Prozesse oder Verbindungen.",
            )
        };
        frame.render_widget(
            Paragraph::new(message).style(Style::default().fg(DIM)),
            Rect {
                x: area.x,
                y: area.y + 1,
                width: area.width,
                height: 1,
            },
        );
    }
}

fn draw_footer(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let lang = app.lang();
    // German labels are abbreviated like Midnight Commander's on narrow
    // terminals, so every required key fits at 36 columns.
    let wide = area.width >= 60;
    let mut keys = vec![
        ("F1", lang.pick("Help", "Hilfe")),
        ("F2", lang.pick("Setup", "Setup")),
    ];
    if area.width >= 44 {
        keys.push(("F3", lang.pick("Search", "Suche")));
    }
    if area.width >= 80 {
        keys.extend([
            ("F4", lang.pick("View", "Ansicht")),
            ("F5", lang.pick("Iface", "Gerät")),
        ]);
    }
    keys.push((
        "F6",
        if wide {
            lang.pick("Sort", "Sortieren")
        } else {
            lang.pick("Sort", "Sort")
        },
    ));
    if area.width >= 94 {
        keys.push((
            "F9",
            if app.paused {
                lang.pick("Resume", "Weiter")
            } else {
                lang.pick("Pause", "Pause")
            },
        ));
    }
    keys.push(("F10", lang.pick("Quit", "Ende")));
    keys.push((
        "F12",
        if wide {
            lang.pick("SaveConfig", "Speichern")
        } else {
            lang.pick("Save", "Speich")
        },
    ));
    draw_key_bar(frame, area, &keys);
}

fn draw_key_bar(frame: &mut Frame<'_>, area: Rect, keys: &[(&str, &str)]) {
    let used: usize = keys
        .iter()
        .map(|(key, label)| key.chars().count() + label.chars().count())
        .sum();
    let padding = usize::from(area.width).saturating_sub(used);
    let mut spans = Vec::new();
    for (index, (key, label)) in keys.iter().enumerate() {
        let spaces = padding / keys.len() + usize::from(index < padding % keys.len());
        spans.push(Span::raw((*key).to_owned()));
        spans.push(Span::styled(
            format!("{label}{}", " ".repeat(spaces)),
            inverse(KEY),
        ));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}
