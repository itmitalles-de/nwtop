//! Setup, sorting, help and interface pickers.

use super::{KEY, draw_key_bar, inverse};
use crate::{
    config::{GraphStyle, Language, PlotColor},
    i18n::Lang,
    ui::{App, SORTS, categories, format_rate},
};
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::Line,
    widgets::{Block, Borders, Clear, Paragraph, Row, Table, TableState, Wrap},
};

fn plot_color_label(color: PlotColor, lang: Lang) -> &'static str {
    match (color, lang) {
        (_, Lang::En) | (PlotColor::Cyan | PlotColor::Magenta, _) => color.label(),
        (PlotColor::Green, Lang::De) => "Grün",
        (PlotColor::Yellow, Lang::De) => "Gelb",
        (PlotColor::Red, Lang::De) => "Rot",
        (PlotColor::Blue, Lang::De) => "Blau",
        (PlotColor::White, Lang::De) => "Weiß",
    }
}

pub(super) fn draw_setup(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let lang = app.lang();
    let names = categories(lang);
    frame.render_widget(Clear, area);
    let vertical = Layout::vertical([
        Constraint::Min(6),
        Constraint::Length(3),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .split(area);
    // Room for the longest category and the focus marker " >".
    let category_width = names
        .iter()
        .map(|name| name.chars().count() as u16 + 2)
        .max()
        .unwrap_or(0)
        .max(12);
    let panes = Layout::horizontal([
        Constraint::Length(category_width),
        Constraint::Length(1),
        Constraint::Min(20),
    ])
    .split(vertical[0]);
    frame.render_widget(
        Paragraph::new("Setup").style(inverse(Color::Green)),
        Rect::new(panes[0].x, panes[0].y, panes[0].width, 1),
    );
    for (index, name) in names.iter().enumerate() {
        let current = app.setup_category == index;
        let style = if current && !app.setup_focus {
            inverse(KEY)
        } else if current {
            Style::default().fg(KEY).add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };
        let text = if current && app.setup_focus {
            format!("{name} >")
        } else {
            (*name).into()
        };
        frame.render_widget(
            Paragraph::new(text).style(style),
            Rect::new(panes[0].x, panes[0].y + index as u16 + 1, panes[0].width, 1),
        );
    }
    let check = |enabled| if enabled { "[*]" } else { "[ ]" };
    let options: Vec<String> = match app.setup_category {
        0 => vec![
            format!(
                "{} {}",
                check(app.settings.color),
                lang.pick("Color", "Farbe")
            ),
            format!(
                "[{:.1}s] {}",
                app.settings.interval_ms as f64 / 1000.0,
                lang.pick("Update interval", "Aktualisierung")
            ),
            format!(
                "{} {}",
                check(app.settings.bits),
                lang.pick("Rates in bits/s", "Raten in Bit/s")
            ),
            format!(
                "[{}] {}",
                match app.settings.language {
                    Language::Auto => "Auto",
                    Language::En => "English",
                    Language::De => "Deutsch",
                },
                lang.pick("Language", "Sprache")
            ),
        ],
        1 => {
            let mut rows = vec![
                format!(
                    "{} Auto ({})",
                    check(app.settings.interface.is_none()),
                    app.auto_interface
                        .as_deref()
                        .unwrap_or(lang.pick("all", "alle"))
                ),
                format!(
                    "{} {}",
                    check(app.settings.interface.as_deref() == Some("all")),
                    lang.pick("All interfaces", "Alle")
                ),
            ];
            rows.extend(app.snapshot.interfaces.iter().map(|iface| {
                format!(
                    "{} {} ({})",
                    check(app.settings.interface.as_deref() == Some(&iface.name)),
                    iface.name,
                    iface.state
                )
            }));
            rows
        }
        2 => vec![
            format!(
                "{} {}",
                check(app.settings.show_graph),
                lang.pick("Show graph", "Diagramm zeigen")
            ),
            format!(
                "[{}s] {}",
                app.settings.history_seconds,
                lang.pick("History", "Verlauf")
            ),
            format!(
                "[{}] {}",
                match (app.settings.graph_style, lang) {
                    (GraphStyle::Steps, Lang::De) => "Stufen",
                    (style, _) => style.label(),
                },
                lang.pick("Drawing", "Zeichnung")
            ),
            format!(
                "[{}] {}",
                plot_color_label(app.settings.rx_color, lang),
                lang.pick("Receive color", "Empfangsfarbe")
            ),
            format!(
                "[{}] {}",
                plot_color_label(app.settings.tx_color, lang),
                lang.pick("Send color", "Sendefarbe")
            ),
        ],
        _ => vec![
            format!(
                "[{}] {}",
                if app.settings.connections {
                    lang.pick("Connections", "Verbindungen")
                } else {
                    lang.pick("Processes", "Prozesse")
                },
                lang.pick("View", "Ansicht")
            ),
            format!(
                "[{}] {}",
                app.settings.sort.label(lang),
                lang.pick("Sort by", "Sortierung")
            ),
            format!(
                "{} {}",
                check(app.settings.show_idle),
                lang.pick("Show idle rows", "Inaktive Zeilen zeigen")
            ),
        ],
    };
    let name = names[app.setup_category];
    let header = match lang {
        Lang::En => format!("{name} Options"),
        Lang::De => format!("Optionen: {name}"),
    };
    // Narrow terminals show just the category rather than a cut-off header.
    let header = if header.chars().count() > usize::from(panes[2].width) {
        name.to_owned()
    } else {
        header
    };
    let mut state =
        TableState::default().with_selected(app.setup_focus.then_some(app.setup_option));
    let table = Table::new(
        options.into_iter().map(|row| Row::new([row])),
        [Constraint::Min(1)],
    )
    .header(Row::new([header]).style(inverse(Color::Green)))
    .row_highlight_style(inverse(KEY));
    frame.render_stateful_widget(table, panes[2], &mut state);
    let description = match (app.setup_category, app.setup_option) {
        (0, 0) => lang.pick(
            "Use the terminal's own ANSI palette. Selection stays visible in monochrome.",
            "Nutzt die ANSI-Palette des Terminals. Die Auswahl bleibt auch einfarbig sichtbar.",
        ),
        (0, 1) => lang.pick(
            "Refresh the display every 0.1 to 60 seconds. +/- changes by 0.1s.",
            "Aktualisiert alle 0,1 bis 60 Sekunden. +/- ändert um 0,1 s.",
        ),
        (0, 2) => lang.pick(
            "Switch between bytes per second (KiB/s) and bits per second (Mbit/s).",
            "Wechselt zwischen Byte pro Sekunde (KiB/s) und Bit pro Sekunde (Mbit/s).",
        ),
        (0, _) => lang.pick(
            "Auto follows the system language (LANG). English or German can be fixed here.",
            "Auto folgt der Systemsprache (LANG). Englisch oder Deutsch lässt sich festlegen.",
        ),
        (1, _) => lang.pick(
            "Enter selects an interface. Auto follows the default route at startup. All can count virtual links twice.",
            "Enter wählt eine Schnittstelle. Auto folgt beim Start der Standardroute. Alle kann virtuelle Links doppelt zählen.",
        ),
        (2, 0) => lang.pick(
            "Hide the graph to give the process table more space.",
            "Blendet das Diagramm aus, damit die Prozesstabelle mehr Platz hat.",
        ),
        (2, 1) => lang.pick(
            "Show 10 to 600 seconds of history. +/- changes by 10 seconds.",
            "Zeigt 10 bis 600 Sekunden Verlauf. +/- ändert um 10 Sekunden.",
        ),
        (2, 2) => lang.pick(
            "Steps uses nvtop-style terminal lines. Braille draws a finer curve.",
            "Stufen nutzt Terminal-Linien wie nvtop. Braille zeichnet eine feinere Kurve.",
        ),
        (2, _) => lang.pick(
            "Cycle through the terminal's standard colors with Enter or +/-.",
            "Wechselt mit Enter oder +/- durch die Standardfarben des Terminals.",
        ),
        (3, 0) => lang.pick(
            "Group traffic by process, or inspect individual connections.",
            "Gruppiert den Verkehr nach Prozess oder zeigt einzelne Verbindungen.",
        ),
        (3, 1) => lang.pick(
            "Choose the table's sort order. F6 opens the same choices in the monitor.",
            "Wählt die Sortierung der Tabelle. F6 bietet dieselbe Auswahl im Monitor.",
        ),
        _ => lang.pick(
            "Include sockets and processes with no traffic in the current sample.",
            "Zeigt auch Sockets und Prozesse ohne Verkehr in der aktuellen Messung.",
        ),
    };
    frame.render_widget(
        // Default foreground keeps the description readable on light themes.
        Paragraph::new(description).wrap(Wrap { trim: true }),
        vertical[1],
    );
    let message = app.notice.clone().unwrap_or_else(|| {
        if app.settings_dirty() {
            lang.pick(
                "Unsaved changes - F12 saves for next start",
                "Ungespeichert - F12 speichert für den nächsten Start",
            )
            .into()
        } else {
            lang.pick(
                "Arrows navigate | Enter / +/- change",
                "Pfeile wählen | Enter / +/- ändern",
            )
            .into()
        }
    });
    frame.render_widget(
        Paragraph::new(message).style(Style::default().fg(
            if app.notice_error && app.notice.is_some() {
                Color::Red
            } else {
                Color::Yellow
            },
        )),
        vertical[2],
    );
    draw_key_bar(
        frame,
        vertical[3],
        &[
            ("Tab", lang.pick("Panel", "Feld")),
            ("Ent", lang.pick("Change", "Ändern")),
            ("F10", lang.pick("Done", "Fertig")),
            (
                "F12",
                if area.width >= 40 {
                    lang.pick("Save", "Speichern")
                } else {
                    lang.pick("Save", "Speich")
                },
            ),
        ],
    );
}

pub(super) fn draw_sort(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let area = popup(area, 32, 10);
    frame.render_widget(Clear, area);
    let lang = app.lang();
    let mut state = TableState::default().with_selected(app.picker.min(SORTS.len() - 1));
    let rows = SORTS.iter().map(|sort| Row::new([sort.label(lang)]));
    let table = Table::new(rows, [Constraint::Min(1)])
        .header(Row::new([lang.pick("Sort by", "Sortieren nach")]).style(inverse(Color::Green)))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(lang.pick(" Enter select / Esc close ", " Enter wählt / Esc schließt ")),
        )
        .row_highlight_style(inverse(KEY));
    frame.render_stateful_widget(table, area, &mut state);
}

fn popup(area: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(area.width.saturating_sub(2));
    let height = height.min(area.height.saturating_sub(2));
    Rect {
        x: area.x + (area.width - width) / 2,
        y: area.y + (area.height - height) / 2,
        width,
        height,
    }
}

pub(super) fn draw_help(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let area = popup(area, 76, 23);
    frame.render_widget(Clear, area);
    let lang = app.lang();
    let lines: &[&str] = match lang {
        Lang::En => &[
            "F1 / ?         Help     Esc closes",
            "F2             Setup: General, Interface, Chart, Processes",
            "F5 / i         Choose interface",
            "Tab / Shift-Tab Cycle up interfaces",
            "F3 / /         Search PID, user, command, endpoint",
            "F6             Choose sorting; s cycles sort order",
            "F12            Save current settings for next start",
            "F4 / c         Processes / connections",
            "b              Bytes/s / bits/s",
            "F9 / Space     Pause / resume display",
            "Up / Down      Select; PgUp / PgDn scroll",
            "q / F10 / Ctrl-C Quit",
            "",
            "RX: receive. TX: send. Default colors: green / yellow.",
            "Graph scale follows the visible peak.",
            "Bars use link speed, or visible peak when unknown.",
            "Interface totals are kernel counters since boot.",
            "Process totals are observed IP bytes this session.",
            "Shared, short-lived or inaccessible sockets can be unattributed.",
            "In all mode, virtual links can count forwarded traffic more than once.",
            "Command-line options and NO_COLOR apply only to this run.",
            "Enable process rates once: ./scripts/setup-capture.sh",
            "After setup, start nwtop without sudo.",
            "",
        ],
        Lang::De => &[
            "F1 / ?         Hilfe    Esc schließt",
            "F2             Setup: Allgemein, Schnittstelle, Diagramm, Prozesse",
            "F5 / i         Schnittstelle wählen",
            "Tab / Shift-Tab Aktive Schnittstellen durchlaufen",
            "F3 / /         PID, Benutzer, Befehl, Endpunkt suchen",
            "F6             Sortierung wählen; s wechselt die Sortierung",
            "F12            Aktuelle Einstellungen für den nächsten Start speichern",
            "F4 / c         Prozesse / Verbindungen",
            "b              Byte/s / Bit/s",
            "F9 / Leertaste Anzeige anhalten / fortsetzen",
            "Hoch / Runter  Auswählen; Bild hoch / runter blättert",
            "q / F10 / Strg-C Beenden",
            "",
            "RX: Empfang. TX: Senden. Standardfarben: grün / gelb.",
            "Die Diagrammskala folgt dem sichtbaren Spitzenwert.",
            "Balken nutzen die Link-Geschwindigkeit, sonst den sichtbaren Spitzenwert.",
            "Schnittstellensummen sind Kernel-Zähler seit dem Systemstart.",
            "Prozesssummen sind in dieser Sitzung beobachtete IP-Bytes.",
            "Geteilte, kurzlebige oder unzugängliche Sockets bleiben evtl. unzugeordnet.",
            "Im Modus Alle können virtuelle Links Weitergeleitetes mehrfach zählen.",
            "Kommandozeilenoptionen und NO_COLOR gelten nur für diesen Lauf.",
            "Prozessraten einmalig aktivieren: ./scripts/setup-capture.sh",
            "Danach nwtop ohne sudo starten.",
            "",
        ],
    };
    let mut text: Vec<Line<'_>> = lines.iter().map(|line| Line::from(*line)).collect();
    text.push(Line::from(
        lang.capture_status(&app.snapshot.capture, true)
            .unwrap_or_else(|| app.snapshot.capture.message.clone()),
    ));
    frame.render_widget(
        Paragraph::new(text)
            .wrap(Wrap { trim: false })
            .scroll((app.help_scroll, 0))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(KEY))
                    .title(lang.pick(
                        " Help  Up/Down scroll / Esc close ",
                        " Hilfe  Hoch/Runter blättert / Esc schließt ",
                    )),
            )
            .style(Style::default()),
        area,
    );
}

pub(super) fn draw_interfaces(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let area = popup(area, 72, (app.snapshot.interfaces.len() as u16 + 5).min(26));
    frame.render_widget(Clear, area);
    let lang = app.lang();
    let mut rows = vec![Row::new(vec![
        lang.pick("all", "alle").to_string(),
        lang.pick("includes virtual links", "inkl. virtueller Links")
            .to_string(),
    ])];
    rows.extend(app.snapshot.interfaces.iter().map(|iface| {
        Row::new(vec![
            iface.name.clone(),
            format!(
                "{}  RX {}  TX {}",
                iface.state,
                format_rate(iface.rx_rate, app.settings.bits),
                format_rate(iface.tx_rate, app.settings.bits)
            ),
        ])
    }));
    let mut state = TableState::default().with_selected(app.picker);
    let table = Table::new(rows, [Constraint::Length(16), Constraint::Min(10)])
        .header(
            Row::new([
                lang.pick("INTERFACE", "SCHNITTSTELLE"),
                lang.pick("STATE / TRAFFIC", "STATUS / VERKEHR"),
            ])
            .style(inverse(Color::Green)),
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(lang.pick(
                    " Interface  Enter select / Esc close ",
                    " Schnittstelle  Enter wählt / Esc schließt ",
                ))
                .border_style(Style::default().fg(KEY)),
        )
        .style(Style::default())
        .row_highlight_style(inverse(KEY));
    frame.render_stateful_widget(table, area, &mut state);
}
