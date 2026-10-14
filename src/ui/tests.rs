use super::render::status_line;
use super::*;
use crate::config::Language;
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
