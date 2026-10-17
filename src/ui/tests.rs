use super::render::status_line;
use super::*;
use crate::config::{GraphStyle, Language};
use ratatui::{Terminal, backend::TestBackend, style::Color};

fn app() -> App {
    let mut app = App::new(Some("enp112s0".into()), 60, false, true);
    for tick in 0..61 {
        app.update(demo_snapshot(tick, tick as f64));
    }
    app
}

fn screen(terminal: &Terminal<TestBackend>) -> String {
    let buffer = terminal.backend().buffer();
    let width = usize::from(buffer.area.width);
    buffer
        .content
        .chunks(width)
        .map(|row| row.iter().map(|cell| cell.symbol()).collect::<String>() + "\n")
        .collect()
}

#[test]
fn layouts_fit_narrow_and_wide_terminals_in_both_languages() {
    for (language, device, quit, done, save) in [
        (Language::En, "Device ", "F10Quit", "Done", "Save"),
        (Language::De, "Gerät ", "F10Ende", "Fertig", "Speich"),
    ] {
        for (width, height) in [(36, 16), (40, 24), (52, 18), (80, 24), (120, 36)] {
            let mut app = app();
            app.settings.language = language;
            let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
            terminal.draw(|frame| draw(frame, &mut app)).unwrap();
            let text = screen(&terminal);
            let at = format!("{language:?} at {width}x{height}");
            assert!(text.contains(device), "title missing {at}");
            assert!(text.contains("RX/s"), "rates missing {at}");
            let footer = text.lines().last().unwrap();
            // Every required function key must be complete on the bottom row.
            for key in ["F1", "F2", "F6", quit, "F12"] {
                assert!(footer.contains(key), "{key} missing {at}: {footer:?}");
            }
            assert!(
                footer.trim_end().ends_with(save) || footer.contains(save),
                "save label cut {at}: {footer:?}"
            );
            for overlay in [
                Overlay::Help,
                Overlay::Interfaces,
                Overlay::Setup,
                Overlay::Sort,
            ] {
                app.overlay = overlay;
                terminal.draw(|frame| draw(frame, &mut app)).unwrap();
            }
            app.overlay = Overlay::Setup;
            for (category, name) in categories(app.lang()).iter().enumerate() {
                app.setup_category = category;
                app.setup_focus = true;
                app.setup_option = app.setup_len() - 1;
                terminal.draw(|frame| draw(frame, &mut app)).unwrap();
                let text = screen(&terminal);
                assert!(
                    text.contains(&format!("{name} >")),
                    "category {name} cut {at}"
                );
                let keys = text.lines().last().unwrap();
                assert!(keys.contains(done), "setup exit missing {at}: {keys:?}");
                assert!(keys.contains(save), "setup save missing {at}: {keys:?}");
            }
        }
    }
}

#[test]
fn german_text_covers_monitor_overlays_and_language_setup_row() {
    let mut app = app();
    app.system_lang = Lang::De;
    let mut terminal = Terminal::new(TestBackend::new(120, 36)).unwrap();
    terminal.draw(|frame| draw(frame, &mut app)).unwrap();
    let text = screen(&terminal);
    for expected in [
        "Gerät ",
        "BENUTZER",
        "BEFEHL",
        "Hilfe",
        "Speichern",
        "gesamt",
    ] {
        assert!(text.contains(expected), "{expected} missing: {text}");
    }
    for (overlay, expected) in [
        (
            Overlay::Help,
            "Aktuelle Einstellungen für den nächsten Start",
        ),
        (Overlay::Sort, "Sortieren nach"),
        (Overlay::Interfaces, "SCHNITTSTELLE"),
        (Overlay::Setup, "Optionen: Allgemein"),
    ] {
        app.overlay = overlay;
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        assert!(screen(&terminal).contains(expected), "{expected} missing");
    }
    // The fourth General row switches the language at runtime.
    app.overlay = Overlay::None;
    app.handle_key(KeyCode::F(2).into());
    app.handle_key(KeyCode::Right.into());
    for _ in 0..3 {
        app.handle_key(KeyCode::Down.into());
    }
    assert_eq!(
        app.handle_key(KeyCode::Enter.into()),
        Action::SettingsChanged
    );
    assert_eq!(app.settings.language, Language::En);
    assert_eq!(app.lang(), Lang::En);
    assert_eq!(app.settings_to_save().language, Language::En);
    terminal.draw(|frame| draw(frame, &mut app)).unwrap();
    assert!(screen(&terminal).contains("[English] Language"));
}

#[test]
fn sort_search_and_pause_preserve_expected_behavior() {
    let mut app = app();
    app.handle_key(KeyCode::F(3).into());
    for c in "curl".chars() {
        app.handle_key(KeyCode::Char(c).into());
    }
    app.handle_key(KeyCode::Enter.into());
    assert_eq!(app.process_rows().len(), 1);
    assert_eq!(app.process_rows()[0].name, "curl");
    app.handle_key(KeyCode::Esc.into());
    assert_eq!(app.process_rows().len(), 6);
    app.settings.sort = Sort::Pid;
    assert_eq!(app.process_rows()[0].pid, Some(4823));
    app.handle_key(KeyCode::Char(' ').into());
    app.update(demo_snapshot(100, 100.0));
    assert_eq!(app.snapshot.elapsed, 60.0);
    app.handle_key(KeyCode::Char(' ').into());
    app.update(demo_snapshot(101, 101.0));
    assert_eq!(app.snapshot.elapsed, 101.0);
    assert!(app.history.iter().all(|sample| sample.at >= 41.0));
}

#[test]
fn interface_switch_clears_mixed_history() {
    let mut app = app();
    assert_eq!(
        app.handle_key(KeyCode::Tab.into()),
        Action::InterfaceChanged
    );
    assert_eq!(app.interface.as_deref(), Some("tailscale0"));
    assert!(app.history.is_empty());
    app.set_interface(None);
    app.handle_key(KeyCode::Tab.into());
    assert_eq!(app.interface.as_deref(), Some("enp112s0"));
    app.set_interface(None);
    app.handle_key(KeyCode::BackTab.into());
    assert_eq!(app.interface.as_deref(), Some("lo"));
}

#[test]
fn narrow_table_keeps_full_pids_and_bit_units() {
    let mut app = app();
    app.settings.bits = true;
    app.snapshot.processes[2].rx_rate = 12_500_000.0;
    let mut terminal = Terminal::new(TestBackend::new(40, 24)).unwrap();
    terminal.draw(|frame| draw(frame, &mut app)).unwrap();
    let text: String = terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|cell| cell.symbol())
        .collect();
    assert!(text.contains("1005126"));
    assert!(text.contains("100.0 Mbit"));
    // 999.97 Mbit/s once rendered as "1000.0 Mbit" and lost its first digit.
    app.snapshot.processes[2].rx_rate = 999.97e6 / 8.0;
    app.settings.sort = Sort::Receive;
    terminal.draw(|frame| draw(frame, &mut app)).unwrap();
    let text = screen(&terminal);
    assert!(text.contains("1.0 Gbit"), "{text}");
    assert!(!text.contains("000.0"), "{text}");
}

#[test]
fn plain_text_uses_the_terminal_default_foreground() {
    let mut app = app();
    let mut terminal = Terminal::new(TestBackend::new(120, 36)).unwrap();
    terminal.draw(|frame| draw(frame, &mut app)).unwrap();
    app.overlay = Overlay::Setup;
    terminal.draw(|frame| draw(frame, &mut app)).unwrap();
    assert!(
        terminal
            .backend()
            .buffer()
            .content
            .iter()
            .all(|cell| cell.fg != Color::White),
        "white text is unreadable on light terminal themes"
    );
    app.overlay = Overlay::None;
    terminal.draw(|frame| draw(frame, &mut app)).unwrap();
    let buffer = terminal.backend().buffer();
    // The device summary ("[UP]  2500 Mbit/s ...") is the second row.
    let summary = (0..10).map(|x| &buffer[(x, 1)]).collect::<Vec<_>>();
    assert_eq!(summary[0].symbol(), "[");
    assert!(summary.iter().all(|cell| cell.fg == Color::Reset));
}

#[test]
fn explicit_interface_choice_is_saved_even_when_it_matches_a_fallback() {
    let saved = Settings {
        interface: Some("gone0".into()),
        ..Settings::default()
    };
    let runtime = Settings {
        interface: None,
        ..saved.clone()
    };
    let mut app = App::with_saved(Some("enp112s0".into()), runtime, saved.clone(), true);
    app.update(demo_snapshot(1, 1.0));
    assert_eq!(app.settings_to_save(), saved);
    // Setup > Interface > Auto explicitly replaces the stale saved choice.
    app.handle_key(KeyCode::F(2).into());
    app.handle_key(KeyCode::Down.into());
    app.handle_key(KeyCode::Right.into());
    assert_eq!(
        app.handle_key(KeyCode::Enter.into()),
        Action::InterfaceChanged
    );
    assert_eq!(app.settings_to_save().interface, None);
    assert!(app.settings_dirty());
}

#[test]
fn units_are_distinct_and_unknown_capture_does_not_show_fake_rates() {
    assert_eq!(format_rate(125_000.0, true), "1.0 Mbit/s");
    assert_eq!(format_bytes(1024.0), "1.0 KiB");
    // Rounding to the displayed precision may reach the next unit.
    assert_eq!(format_bytes(1023.6), "1.0 KiB");
    assert_eq!(format_bytes(1023.4), "1023 B");
    assert_eq!(format_bytes(1023.96 * 1024.0), "1.0 MiB");
    assert_eq!(format_bytes(1023.94 * 1024.0), "1023.9 KiB");
    assert_eq!(format_rate(999.97e6 / 8.0, true), "1.0 Gbit/s");
    assert_eq!(format_rate(999.96 / 8.0, true), "1.0 kbit/s");
    assert_eq!(format_rate(f64::NAN, false), "0 B/s");
    // Below the last unit, table cells and graph labels need 10 columns.
    let mut value = 0.5;
    while value < 1e14 {
        for bits in [false, true] {
            let text = format_rate(value, bits);
            let trimmed = text.trim_end_matches("/s");
            assert!(trimmed.len() <= 10, "{trimmed:?} is too wide");
        }
        assert!(format_bytes(value).len() <= 10);
        value *= 1.0007;
    }
    let mut app = app();
    app.demo = false;
    app.snapshot.capture.active = false;
    app.snapshot.capture.message = "Process rates unavailable; run scripts/setup-capture.sh".into();
    app.snapshot.processes[0].rx_rate = 9_000_000_000.0;
    let mut terminal = Terminal::new(TestBackend::new(120, 36)).unwrap();
    terminal.draw(|frame| draw(frame, &mut app)).unwrap();
    let text: String = terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|cell| cell.symbol())
        .collect();
    assert!(text.contains("setup-capture.sh"));
    assert!(!text.contains(format_rate(9_000_000_000.0, false).trim_end_matches("/s")));
}

#[test]
fn setup_changes_apply_without_quitting_or_implicitly_saving() {
    let mut app = app();
    assert_eq!(app.handle_key(KeyCode::F(2).into()), Action::None);
    assert_eq!(app.overlay, Overlay::Setup);
    app.handle_key(KeyCode::Right.into());
    app.handle_key(KeyCode::Down.into());
    assert_eq!(
        app.handle_key(KeyCode::Char('+').into()),
        Action::SettingsChanged
    );
    assert_eq!(app.settings.interval_ms, 1100);
    assert!(app.settings_dirty());
    assert_eq!(app.handle_key(KeyCode::F(10).into()), Action::None);
    assert_eq!(app.overlay, Overlay::None);
    assert!(app.settings_dirty());
    assert_eq!(app.handle_key(KeyCode::F(12).into()), Action::SaveSettings);
    app.settings_saved("Saved test preferences".into());
    assert!(!app.settings_dirty());
    app.handle_key(KeyCode::F(6).into());
    app.handle_key(KeyCode::Down.into());
    app.handle_key(KeyCode::Enter.into());
    assert_eq!(app.settings.sort, Sort::Receive);
    assert_eq!(app.overlay, Overlay::None);
    assert_eq!(app.handle_key(KeyCode::F(10).into()), Action::Quit);
}

#[test]
fn collector_status_follows_the_ui_language() {
    use crate::model::CaptureNote;
    let mut app = app();
    app.demo = false;
    app.settings.language = crate::config::Language::De;
    app.snapshot.capture.message = "English text from the collector".into();
    app.snapshot.capture.notes = vec![CaptureNote::Sampled, CaptureNote::OwnersInaccessible];
    let (line, _) = status_line(&app).unwrap();
    assert_eq!(line, "einige /proc-Besitzer unzugänglich");
    app.snapshot.capture.notes = vec![CaptureNote::Sampled];
    assert!(status_line(&app).is_none(), "the routine note stays in F1");
    app.snapshot.capture.active = false;
    app.snapshot.capture.notes = vec![CaptureNote::InterfaceMissing {
        name: "eth9".into(),
    }];
    assert_eq!(
        status_line(&app).unwrap().0,
        "F2: Schnittstelle wählen; eth9 ist nicht verfügbar"
    );
    // An older helper without notes: its text is shown as sent.
    app.snapshot.capture.notes.clear();
    assert_eq!(
        status_line(&app).unwrap().0,
        "English text from the collector"
    );
}

#[test]
fn unavailable_rates_are_not_treated_as_idle() {
    let mut app = app();
    app.demo = false;
    app.settings.show_idle = false;
    for row in &mut app.snapshot.processes {
        row.rx_rate = 0.0;
        row.tx_rate = 0.0;
    }
    for row in &mut app.snapshot.connections {
        row.rx_rate = 0.0;
        row.tx_rate = 0.0;
    }
    assert!(app.process_rows().is_empty());
    assert!(app.connection_rows().is_empty());
    app.snapshot.capture.active = false;
    assert_eq!(app.process_rows().len(), app.snapshot.processes.len());
    assert_eq!(app.connection_rows().len(), app.snapshot.connections.len());
}

#[test]
fn monochrome_covers_small_windows_and_all_overlays() {
    let mut app = app();
    app.settings.color = false;
    for (width, height) in [(20, 10), (36, 16), (52, 18), (120, 36)] {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        for overlay in [
            Overlay::None,
            Overlay::Help,
            Overlay::Setup,
            Overlay::Sort,
            Overlay::Interfaces,
        ] {
            app.overlay = overlay;
            terminal.draw(|frame| draw(frame, &mut app)).unwrap();
            assert!(
                terminal
                    .backend()
                    .buffer()
                    .content
                    .iter()
                    .all(|cell| cell.fg == Color::Reset && cell.bg == Color::Reset),
                "colored cell in {overlay:?} at {width}x{height}"
            );
        }
    }
}

#[test]
fn graph_time_labels_stay_visible_and_hiding_graph_frees_rows() {
    let mut app = app();
    let mut terminal = Terminal::new(TestBackend::new(52, 18)).unwrap();
    terminal.draw(|frame| draw(frame, &mut app)).unwrap();
    let text: String = terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|cell| cell.symbol())
        .collect();
    assert!(text.contains("-60s"));
    assert!(text.contains("-30s"));
    let with_graph = app.visible_rows;
    app.settings.show_graph = false;
    terminal.draw(|frame| draw(frame, &mut app)).unwrap();
    assert!(app.visible_rows > with_graph);
}

const FNV_OFFSET: u64 = 0xcbf29ce484222325;

/// FNV-1a keeps recorded hashes independent of Rust's DefaultHasher.
fn fnv(hash: u64, text: &str) -> u64 {
    text.bytes().fold(hash, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x100000001b3)
    })
}

fn draw_hash(hash: u64, app: &mut App, width: u16, height: u16) -> u64 {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal.draw(|frame| draw(frame, app)).unwrap();
    // Symbols, colors and modifiers of every cell, plus the derived row count.
    let cells = format!(
        "{:?} {}",
        terminal.backend().buffer().content,
        app.visible_rows
    );
    fnv(hash, &cells)
}

#[test]
fn table_layouts_render_the_same_cells_at_every_width_breakpoint() {
    // Recorded on the unmodified renderer at 1f3af1c.
    let mut hash = FNV_OFFSET;
    for language in [Language::En, Language::De] {
        for width in [36, 40, 51, 52, 63, 64, 93, 94, 120] {
            for connections in [false, true] {
                for captured in [true, false] {
                    for rows in ["all", "filtered", "none"] {
                        let mut app = app();
                        app.settings.language = language;
                        app.settings.connections = connections;
                        app.settings.bits = width % 2 == 1;
                        if !captured {
                            app.demo = false;
                            app.snapshot.capture.active = false;
                        }
                        match rows {
                            "filtered" => app.filter = "no-such-row".into(),
                            "none" => {
                                app.snapshot.processes.clear();
                                app.snapshot.connections.clear();
                            }
                            _ => app.table.select(Some(2)),
                        }
                        hash = draw_hash(hash, &mut app, width, 20);
                    }
                }
            }
        }
    }
    assert_eq!(hash, 10712350386198292355);
}

#[test]
fn step_and_braille_graphs_render_the_same_cells_for_edge_histories() {
    // Recorded on the unmodified renderer at 1f3af1c.
    let mut hash = FNV_OFFSET;
    for style in [GraphStyle::Steps, GraphStyle::Braille] {
        for (width, height) in [(36, 16), (40, 24), (44, 20), (60, 30), (120, 40)] {
            for history in ["demo", "empty", "single", "stale", "extremes", "long"] {
                let mut app = app();
                app.settings.graph_style = style;
                app.settings.bits = height % 2 == 0;
                match history {
                    "empty" => app.history.clear(),
                    "single" => {
                        app.history.clear();
                        app.history.push_back(Sample {
                            at: 5.0,
                            rx: 2_000.0,
                            tx: 500.0,
                        });
                    }
                    "stale" => {
                        // Samples outside the window are skipped, not clamped.
                        app.history.push_front(Sample {
                            at: -500.0,
                            rx: 9e9,
                            tx: 9e9,
                        });
                        app.history.push_back(Sample {
                            at: 1e9,
                            rx: 1.0,
                            tx: 1.0,
                        });
                    }
                    "extremes" => {
                        for (index, sample) in app.history.iter_mut().enumerate() {
                            let high = index % 3 == 0;
                            sample.rx = if high { 50e6 } else { 0.0 };
                            sample.tx = if high { 0.0 } else { 50e6 };
                        }
                    }
                    "long" => app.settings.history_seconds = 600,
                    _ => {}
                }
                hash = draw_hash(hash, &mut app, width, height);
            }
        }
    }
    assert_eq!(hash, 8757548152055282732);
}

#[test]
fn main_key_handling_keeps_the_recorded_state_trace() {
    use crossterm::event::KeyModifiers;

    let ctrl = |c| KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL);
    let key = |code| KeyEvent::from(code);
    let mut app = app();
    app.visible_rows = 3;
    app.snapshot.interfaces[0].state = "down".into();
    let mut script = vec![
        key(KeyCode::F(12)),
        key(KeyCode::Down),
        key(KeyCode::Char('j')),
        key(KeyCode::PageDown),
        key(KeyCode::PageDown),
        key(KeyCode::Up),
        key(KeyCode::Char('k')),
        key(KeyCode::PageUp),
        key(KeyCode::End),
        key(KeyCode::Home),
        key(KeyCode::Char('x')),
        key(KeyCode::Char('s')),
        key(KeyCode::Char('s')),
        key(KeyCode::Char('c')),
        key(KeyCode::F(4)),
        key(KeyCode::Char('b')),
        key(KeyCode::Char('b')),
        key(KeyCode::Char(' ')),
        key(KeyCode::F(9)),
        key(KeyCode::F(1)),
        key(KeyCode::Down),
        key(KeyCode::Esc),
        key(KeyCode::Char('?')),
        ctrl('c'),
        key(KeyCode::F(12)),
        key(KeyCode::F(10)),
        key(KeyCode::Char('q')),
        key(KeyCode::F(5)),
        key(KeyCode::Down),
        key(KeyCode::Esc),
        key(KeyCode::Char('i')),
        key(KeyCode::Esc),
        key(KeyCode::F(6)),
        key(KeyCode::Down),
        key(KeyCode::Enter),
        key(KeyCode::F(2)),
        key(KeyCode::F(10)),
        key(KeyCode::Tab),
        key(KeyCode::Tab),
        key(KeyCode::BackTab),
        key(KeyCode::BackTab),
        key(KeyCode::F(5)),
        key(KeyCode::Home),
        key(KeyCode::Enter),
        key(KeyCode::BackTab),
        key(KeyCode::F(3)),
        key(KeyCode::Char('q')),
        key(KeyCode::Char('/')),
        ctrl('x'),
        key(KeyCode::F(12)),
        key(KeyCode::Down),
        key(KeyCode::Backspace),
        key(KeyCode::Backspace),
        key(KeyCode::Backspace),
        key(KeyCode::Char('d')),
        key(KeyCode::Enter),
        key(KeyCode::Down),
        key(KeyCode::Esc),
        key(KeyCode::Char('/')),
        key(KeyCode::Char('s')),
        key(KeyCode::Esc),
        key(KeyCode::Char('/')),
        ctrl('c'),
    ];
    // The search filter is bounded even for pasted input.
    script.extend(std::iter::repeat_n(key(KeyCode::Char('z')), 260));
    script.extend([key(KeyCode::Enter), key(KeyCode::F(10))]);
    let mut trace = String::new();
    for (step, event) in script.into_iter().enumerate() {
        if step % 7 == 0 {
            app.notice = Some(format!("notice {step}"));
        }
        let action = app.handle_key(event);
        trace.push_str(&format!(
            "{step} {event:?} -> {action:?} {:?} picker={} scroll={} search={} {:?} paused={} \
             selected={:?} iface={:?} notice={:?} history={} {:?} {:?}\n",
            app.overlay,
            app.picker,
            app.help_scroll,
            app.searching,
            app.filter,
            app.paused,
            app.table.selected(),
            app.interface,
            app.notice,
            app.history.len(),
            app.settings,
            app.touched,
        ));
    }
    // Tab skips non-up interfaces; with none left it changes nothing.
    for iface in &mut app.snapshot.interfaces {
        iface.state = "down".into();
        iface.name = format!("x{}", iface.name);
    }
    for event in [key(KeyCode::Tab), key(KeyCode::BackTab)] {
        let action = app.handle_key(event);
        trace.push_str(&format!("{action:?} {:?}\n", app.interface));
    }
    assert_eq!(fnv(FNV_OFFSET, &trace), 6960483453550570688);
}

#[test]
fn setup_sort_row_steps_through_sorts_and_wraps_both_ways() {
    let mut app = app();
    assert_eq!(app.settings.sort, Sort::Traffic);
    app.handle_key(KeyCode::F(2).into());
    for _ in 0..3 {
        app.handle_key(KeyCode::Down.into());
    }
    app.handle_key(KeyCode::Right.into());
    app.handle_key(KeyCode::Down.into());
    let mut sorts = Vec::new();
    for code in ['+', '-', '-', '-', '=', '+'] {
        assert_eq!(
            app.handle_key(KeyCode::Char(code).into()),
            Action::SettingsChanged
        );
        sorts.push(app.settings.sort);
    }
    assert_eq!(
        sorts,
        [
            Sort::Receive,
            Sort::Traffic,
            Sort::Name,
            Sort::Pid,
            Sort::Name,
            Sort::Traffic
        ]
    );
}

/// Distinct Setup values per profile so every label variant is rendered.
fn setup_profile(app: &mut App, profile: usize, lang: Lang) {
    use crate::config::PlotColor;

    app.system_lang = lang;
    let fixed = match lang {
        Lang::En => Language::En,
        Lang::De => Language::De,
    };
    match profile {
        0 => app.settings.language = fixed,
        1 => {
            app.settings.language = fixed;
            app.settings.color = false;
            app.settings.bits = true;
            app.settings.interval_ms = 100;
            app.settings.show_graph = false;
            app.settings.history_seconds = 600;
            app.settings.graph_style = GraphStyle::Braille;
            app.settings.rx_color = PlotColor::Red;
            app.settings.tx_color = PlotColor::White;
            app.settings.connections = true;
            app.settings.sort = Sort::Name;
            app.settings.show_idle = true;
            app.settings.interface = Some("all".into());
            app.auto_interface = None;
            app.touched.insert(Field::Color);
        }
        2 => {
            app.settings.language = Language::Auto;
            app.settings.interval_ms = 60_000;
            app.settings.rx_color = PlotColor::Blue;
            app.settings.tx_color = PlotColor::Magenta;
            app.settings.interface = Some("lo".into());
            app.auto_interface = Some("enp112s0".into());
            app.notice = Some("Could not save settings".into());
            app.notice_error = true;
        }
        _ => {
            app.settings.language = fixed;
            app.settings.rx_color = PlotColor::Cyan;
            app.settings.tx_color = PlotColor::Green;
            app.settings.interface = None;
            app.settings.sort = Sort::Pid;
            app.notice = Some("Settings saved".into());
            app.notice_error = false;
        }
    }
}

#[test]
fn setup_renders_the_same_cells_for_every_row_value_and_size() {
    // Recorded on the unmodified overlay renderer.
    let mut hash = FNV_OFFSET;
    for lang in [Lang::En, Lang::De] {
        for (width, height) in [(36, 16), (40, 24), (60, 20), (120, 36)] {
            for profile in 0..4 {
                for category in 0..CATEGORY_COUNT {
                    let mut app = app();
                    setup_profile(&mut app, profile, lang);
                    app.overlay = Overlay::Setup;
                    app.setup_category = category;
                    // Unfocused, the description still follows the option.
                    for option in [0, 1] {
                        app.setup_focus = false;
                        app.setup_option = option;
                        hash = draw_hash(hash, &mut app, width, height);
                    }
                    app.setup_focus = true;
                    for option in 0..app.setup_len() {
                        app.setup_option = option;
                        hash = draw_hash(hash, &mut app, width, height);
                    }
                }
            }
        }
    }
    assert_eq!(hash, 2320896944122356148);
}

#[test]
fn help_renders_the_same_cells_for_scroll_positions_and_capture_states() {
    // Recorded on the unmodified overlay renderer.
    let mut hash = FNV_OFFSET;
    for lang in [Language::En, Language::De] {
        for (width, height) in [(36, 16), (40, 24), (80, 24), (120, 36)] {
            for captured in [true, false] {
                for scroll in [0, 7, 60] {
                    let mut app = app();
                    app.settings.language = lang;
                    app.overlay = Overlay::Help;
                    app.help_scroll = scroll;
                    if !captured {
                        app.snapshot.capture.active = false;
                        app.snapshot.capture.message = "capture unavailable".into();
                    }
                    hash = draw_hash(hash, &mut app, width, height);
                }
            }
        }
    }
    assert_eq!(hash, 818637298919642789);
}
