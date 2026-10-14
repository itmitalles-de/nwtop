//! Characterization of the public UI facade before splitting its renderer.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use nwtop::{
    config::{GraphStyle, Language, Settings},
    ui::{App, demo_snapshot, draw},
};
use ratatui::{Terminal, backend::TestBackend};

fn press(app: &mut App, code: KeyCode) {
    app.handle_key(KeyEvent::new(code, KeyModifiers::NONE));
}

fn render(language: Language, width: u16, height: u16, scene: usize) -> u64 {
    let settings = Settings {
        language,
        ..Settings::default()
    };
    let mut app = App::with_settings(Some("enp112s0".into()), settings, true);
    for tick in 0..61 {
        app.update(demo_snapshot(tick, tick as f64));
    }
    match scene {
        0 => {}
        1 => press(&mut app, KeyCode::Char('c')),
        2 => press(&mut app, KeyCode::F(1)),
        3 => press(&mut app, KeyCode::F(5)),
        4 => press(&mut app, KeyCode::F(6)),
        5..=8 => {
            press(&mut app, KeyCode::F(2));
            for _ in 5..scene {
                press(&mut app, KeyCode::Down);
            }
            press(&mut app, KeyCode::Right);
        }
        9 => {
            app.settings.graph_style = GraphStyle::Braille;
            press(&mut app, KeyCode::Char('b'));
        }
        10 => {
            app.settings.show_graph = false;
            press(&mut app, KeyCode::Char('/'));
            press(&mut app, KeyCode::Char('c'));
        }
        11 => {
            app.settings.color = false;
            app.snapshot.capture.active = false;
            app.snapshot.capture.message = "capture unavailable".into();
        }
        _ => unreachable!(),
    }
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal.draw(|frame| draw(frame, &mut app)).unwrap();
    // Include every symbol, foreground/background color and modifier. FNV-1a
    // makes this independent of Rust's unspecified DefaultHasher algorithm.
    let cells = format!("{:?}", terminal.backend().buffer().content);
    cells.bytes().fold(0xcbf29ce484222325_u64, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x100000001b3)
    })
}

#[test]
fn public_ui_renders_the_same_cells_and_styles() {
    // Recorded on the unmodified renderer at f598a26.
    let cases = [
        (
            Language::En,
            40,
            24,
            [
                6666447872004305382,
                13557186733344913005,
                4439742924713312113,
                12294504479128642574,
                10850878108040962124,
                17095440411833439905,
                14825924530304825347,
                6121098257832830492,
                6684677764781846057,
                17371265395193754908,
                18371651177984041106,
                10752943807598810896,
            ],
        ),
        (
            Language::En,
            120,
            36,
            [
                15173916862482427459,
                6233232342426749974,
                12016239834806793349,
                2575247965435905868,
                8426368235546527324,
                7715753209524915045,
                18400090740027143101,
                4485980506442510954,
                5825661158259767001,
                10950869795723301371,
                6468560911116975222,
                4565702649253075451,
            ],
        ),
        (
            Language::De,
            40,
            24,
            [
                14521601337255828755,
                6468237511331702585,
                9740326293711731410,
                11031629423890356063,
                5133664494787634381,
                1655298961308710027,
                7276523702893640539,
                17122378009506493669,
                1564295619361361448,
                469937463109740543,
                14185090503033834986,
                10388809820085660621,
            ],
        ),
        (
            Language::De,
            120,
            36,
            [
                14013310312038819533,
                15988834434888958082,
                6959110590271552175,
                3746825508187885961,
                16439978834786297732,
                7792442368346039043,
                8909890817968679231,
                10359808767629437165,
                17552771783657294861,
                13097079777244967233,
                5769657773082097495,
                6569045946639472587,
            ],
        ),
    ];
    for (language, width, height, expected) in cases {
        for (scene, expected) in expected.into_iter().enumerate() {
            assert_eq!(
                render(language, width, height, scene),
                expected,
                "{language:?} {width}x{height}, scene {scene}"
            );
        }
    }
}
