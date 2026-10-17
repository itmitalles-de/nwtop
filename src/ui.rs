//! A compact nvtop-style terminal interface. No data is invented by the renderer.

use std::{
    cmp::Ordering,
    collections::{BTreeSet, VecDeque},
};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::widgets::TableState;

pub use crate::config::SortKey as Sort;
use crate::{
    config::{Field, Settings},
    i18n::Lang,
    model::{ConnectionRow, ProcessRow, Snapshot},
};

mod demo;
mod format;
mod render;

use format::pid;

pub use demo::demo_snapshot;
pub use format::{format_bytes, format_rate};
pub use render::draw;

const SORTS: [Sort; 6] = [
    Sort::Traffic,
    Sort::Receive,
    Sort::Send,
    Sort::Total,
    Sort::Pid,
    Sort::Name,
];
const CATEGORY_COUNT: usize = 4;

fn categories(lang: Lang) -> [&'static str; CATEGORY_COUNT] {
    match lang {
        Lang::En => ["General", "Interface", "Chart", "Processes"],
        Lang::De => ["Allgemein", "Schnittstelle", "Diagramm", "Prozesse"],
    }
}

impl Sort {
    pub fn next(self) -> Self {
        match self {
            Self::Traffic => Self::Receive,
            Self::Receive => Self::Send,
            Self::Send => Self::Total,
            Self::Total => Self::Pid,
            Self::Pid => Self::Name,
            Self::Name => Self::Traffic,
        }
    }

    pub fn label(self, lang: Lang) -> &'static str {
        match self {
            Self::Traffic => lang.pick("traffic", "Verkehr"),
            Self::Receive => "RX",
            Self::Send => "TX",
            Self::Total => lang.pick("total", "gesamt"),
            Self::Pid => "PID",
            Self::Name => lang.pick("command", "Befehl"),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Overlay {
    #[default]
    None,
    Help,
    Interfaces,
    Setup,
    Sort,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    None,
    Quit,
    InterfaceChanged,
    SettingsChanged,
    SaveSettings,
}

#[derive(Clone, Debug)]
pub struct Sample {
    pub at: f64,
    pub rx: f64,
    pub tx: f64,
}

pub struct App {
    pub snapshot: Snapshot,
    pub interface: Option<String>,
    pub history: VecDeque<Sample>,
    /// Effective runtime settings, including CLI and environment overrides.
    pub settings: Settings,
    /// Settings as stored in the preferences file.
    saved_settings: Settings,
    /// Preferences the user changed in this session; only these are saved.
    touched: BTreeSet<Field>,
    /// Language used when the language preference is Auto.
    pub system_lang: Lang,
    pub auto_interface: Option<String>,
    pub notice: Option<String>,
    pub notice_error: bool,
    pub paused: bool,
    pub filter: String,
    pub searching: bool,
    pub overlay: Overlay,
    pub table: TableState,
    picker: usize,
    help_scroll: u16,
    visible_rows: usize,
    pub demo: bool,
    setup_category: usize,
    setup_option: usize,
    setup_focus: bool,
}

impl App {
    pub fn new(interface: Option<String>, history_seconds: u16, bits: bool, demo: bool) -> Self {
        let settings = Settings {
            interface: Some(interface.clone().unwrap_or_else(|| "all".into())),
            history_seconds,
            bits,
            ..Settings::default()
        };
        Self::with_settings(interface, settings, demo)
    }

    pub fn with_settings(interface: Option<String>, settings: Settings, demo: bool) -> Self {
        Self::with_saved(interface, settings.clone(), settings, demo)
    }

    /// `settings` may contain temporary overrides; `saved` is the file content.
    /// Saving writes `saved` plus the preferences the user changed at runtime.
    pub fn with_saved(
        interface: Option<String>,
        settings: Settings,
        saved: Settings,
        demo: bool,
    ) -> Self {
        Self {
            snapshot: Snapshot::default(),
            auto_interface: interface.clone(),
            interface,
            history: VecDeque::new(),
            saved_settings: saved,
            touched: BTreeSet::new(),
            system_lang: Lang::En,
            settings,
            notice: None,
            notice_error: false,
            paused: false,
            filter: String::new(),
            searching: false,
            overlay: Overlay::None,
            table: TableState::default().with_selected(0),
            picker: 0,
            help_scroll: 0,
            visible_rows: 10,
            demo,
            setup_category: 0,
            setup_option: 0,
            setup_focus: false,
        }
    }

    pub fn history_seconds(&self) -> f64 {
        f64::from(self.settings.history_seconds)
    }

    pub fn lang(&self) -> Lang {
        Lang::resolve(self.settings.language, self.system_lang)
    }

    /// Saved settings plus only the preferences changed in Setup or by keys.
    /// CLI options, NO_COLOR and automatic fallbacks stay temporary.
    pub fn settings_to_save(&self) -> Settings {
        let mut settings = self.saved_settings.clone();
        for field in &self.touched {
            settings.copy_field(&self.settings, *field);
        }
        settings
    }

    pub fn settings_dirty(&self) -> bool {
        self.settings_to_save() != self.saved_settings
    }

    /// Record a successful save of `settings_to_save()`.
    pub fn settings_saved(&mut self, message: String) {
        self.saved_settings = self.settings_to_save();
        self.touched.clear();
        self.notice = Some(message);
        self.notice_error = false;
    }

    pub fn show_error(&mut self, message: String) {
        self.notice = Some(message);
        self.notice_error = true;
    }

    pub fn update(&mut self, snapshot: Snapshot) {
        if self.paused {
            return;
        }
        let (rx, tx, _, _) = totals(&snapshot, self.interface.as_deref());
        let at = snapshot.elapsed;
        self.history.push_back(Sample { at, rx, tx });
        while self
            .history
            .front()
            .is_some_and(|sample| at - sample.at > self.history_seconds())
        {
            self.history.pop_front();
        }
        // Also cap storage if the collector's clock does not advance.
        while self.history.len() > 6001 {
            self.history.pop_front();
        }
        self.snapshot = snapshot;
        let count = self.row_count();
        self.table
            .select((count > 0).then(|| self.table.selected().unwrap_or(0).min(count - 1)));
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> Action {
        let before = self.settings.clone();
        let action = self.handle_key_inner(key);
        self.touched.extend(self.settings.differing(&before));
        action
    }

    fn handle_key_inner(&mut self, key: KeyEvent) -> Action {
        // Quit and save work everywhere and keep the current notice visible.
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            return Action::Quit;
        }
        if key.code == KeyCode::F(12) {
            return Action::SaveSettings;
        }
        self.notice = None;
        // Setup closes on F10 instead of quitting.
        if self.overlay == Overlay::Setup {
            return self.setup_key(key);
        }
        if key.code == KeyCode::F(10) {
            return Action::Quit;
        }
        if self.overlay != Overlay::None {
            return self.overlay_key(key);
        }
        if self.searching {
            self.search_key(key);
            return Action::None;
        }
        self.monitor_key(key)
    }

    /// Edits the search filter; every key restarts the selection at the top.
    fn search_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                self.searching = false;
                self.filter.clear();
            }
            KeyCode::Enter => self.searching = false,
            KeyCode::Backspace => {
                self.filter.pop();
            }
            KeyCode::Char(c)
                if !key.modifiers.contains(KeyModifiers::CONTROL) && self.filter.len() < 256 =>
            {
                // Bound input even when pasted by a terminal.
                self.filter.push(c);
            }
            _ => {}
        }
        self.table.select(Some(0));
    }

    /// Keys of the main monitor view without an open overlay or search.
    fn monitor_key(&mut self, key: KeyEvent) -> Action {
        match key.code {
            KeyCode::Char('q') => return Action::Quit,
            KeyCode::F(1) | KeyCode::Char('?') => {
                self.overlay = Overlay::Help;
                self.help_scroll = 0;
            }
            KeyCode::F(2) => {
                self.overlay = Overlay::Setup;
                self.setup_focus = false;
            }
            KeyCode::F(5) | KeyCode::Char('i') => self.open_interface_picker(),
            KeyCode::Tab | KeyCode::BackTab => {
                return self.cycle_interface(key.code == KeyCode::BackTab);
            }
            KeyCode::F(3) | KeyCode::Char('/') => self.searching = true,
            KeyCode::F(6) => {
                self.overlay = Overlay::Sort;
                self.picker = self.sort_index();
            }
            KeyCode::Char('s') => {
                self.settings.sort = self.settings.sort.next();
                self.table.select(Some(0));
            }
            KeyCode::F(4) | KeyCode::Char('c') => {
                self.settings.connections = !self.settings.connections;
                self.table.select(Some(0));
            }
            KeyCode::Char('b') => self.settings.bits = !self.settings.bits,
            KeyCode::F(9) | KeyCode::Char(' ') => self.paused = !self.paused,
            KeyCode::Esc => self.filter.clear(),
            KeyCode::Down | KeyCode::Char('j') => self.move_selection(1),
            KeyCode::Up | KeyCode::Char('k') => self.move_selection(-1),
            KeyCode::PageDown => self.move_selection(self.visible_rows as isize),
            KeyCode::PageUp => self.move_selection(-(self.visible_rows as isize)),
            KeyCode::Home => self.table.select((self.row_count() > 0).then_some(0)),
            KeyCode::End => self.table.select(self.row_count().checked_sub(1)),
            _ => {}
        }
        Action::None
    }

    /// Opens the interface overlay on the current device; row 0 is "all".
    fn open_interface_picker(&mut self) {
        self.overlay = Overlay::Interfaces;
        self.picker = self
            .snapshot
            .interfaces
            .iter()
            .position(|iface| Some(iface.name.as_str()) == self.interface.as_deref())
            .map_or(0, |index| index + 1);
    }

    /// Switches to the next or previous interface that is up, or loopback.
    fn cycle_interface(&mut self, backward: bool) -> Action {
        let names: Vec<_> = self
            .snapshot
            .interfaces
            .iter()
            .filter(|iface| iface.state == "up" || iface.name == "lo")
            .map(|iface| iface.name.clone())
            .collect();
        if names.is_empty() {
            return Action::None;
        }
        let current = names
            .iter()
            .position(|name| Some(name) == self.interface.as_ref());
        let next = match (current, backward) {
            (Some(index), true) => (index + names.len() - 1) % names.len(),
            (Some(index), false) => (index + 1) % names.len(),
            (None, true) => names.len() - 1,
            (None, false) => 0,
        };
        self.set_interface(Some(names[next].clone()));
        Action::InterfaceChanged
    }

    /// Position of the current sort order in `SORTS`.
    fn sort_index(&self) -> usize {
        SORTS
            .iter()
            .position(|sort| *sort == self.settings.sort)
            .unwrap_or(0)
    }

    fn overlay_key(&mut self, key: KeyEvent) -> Action {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::F(1) | KeyCode::Char('?') => {
                self.overlay = Overlay::None
            }
            KeyCode::Up | KeyCode::Char('k') if self.overlay == Overlay::Help => {
                self.help_scroll = self.help_scroll.saturating_sub(1)
            }
            KeyCode::Down | KeyCode::Char('j') if self.overlay == Overlay::Help => {
                self.help_scroll = self.help_scroll.saturating_add(1).min(60)
            }
            KeyCode::PageUp if self.overlay == Overlay::Help => {
                self.help_scroll = self.help_scroll.saturating_sub(8)
            }
            KeyCode::PageDown if self.overlay == Overlay::Help => {
                self.help_scroll = self.help_scroll.saturating_add(8).min(60)
            }
            KeyCode::Up | KeyCode::Char('k') if self.overlay == Overlay::Interfaces => {
                self.picker = self.picker.saturating_sub(1)
            }
            KeyCode::Down | KeyCode::Char('j') if self.overlay == Overlay::Interfaces => {
                self.picker = (self.picker + 1).min(self.snapshot.interfaces.len())
            }
            KeyCode::Home if self.overlay == Overlay::Interfaces => self.picker = 0,
            KeyCode::End if self.overlay == Overlay::Interfaces => {
                self.picker = self.snapshot.interfaces.len()
            }
            KeyCode::Enter if self.overlay == Overlay::Interfaces => {
                let interface = self
                    .picker
                    .checked_sub(1)
                    .and_then(|index| self.snapshot.interfaces.get(index))
                    .map(|iface| iface.name.clone());
                self.set_interface(interface);
                self.overlay = Overlay::None;
                return Action::InterfaceChanged;
            }
            KeyCode::Up | KeyCode::Char('k') if self.overlay == Overlay::Sort => {
                self.picker = self.picker.saturating_sub(1);
            }
            KeyCode::Down | KeyCode::Char('j') if self.overlay == Overlay::Sort => {
                self.picker = (self.picker + 1).min(SORTS.len() - 1);
            }
            KeyCode::Enter if self.overlay == Overlay::Sort => {
                self.settings.sort = SORTS[self.picker.min(SORTS.len() - 1)];
                self.table.select(Some(0));
                self.overlay = Overlay::None;
            }
            _ => {}
        }
        Action::None
    }

    fn set_interface(&mut self, interface: Option<String>) {
        // An explicit choice is saved even if it equals a temporary override.
        self.touched.insert(Field::Interface);
        self.settings.interface = Some(interface.clone().unwrap_or_else(|| "all".into()));
        if self.interface != interface {
            self.interface = interface;
            self.history.clear();
            self.table.select(Some(0));
            // Switching device explicitly resumes live collection.
            self.paused = false;
        }
    }

    fn setup_len(&self) -> usize {
        match self.setup_category {
            0 => 4,
            1 => self.snapshot.interfaces.len() + 2,
            2 => 5,
            _ => 3,
        }
    }

    fn setup_key(&mut self, key: KeyEvent) -> Action {
        self.setup_option = self.setup_option.min(self.setup_len().saturating_sub(1));
        match key.code {
            KeyCode::Esc | KeyCode::F(2) | KeyCode::F(10) | KeyCode::Char('q') => {
                self.overlay = Overlay::None;
            }
            KeyCode::Tab | KeyCode::BackTab => self.setup_focus = !self.setup_focus,
            KeyCode::Right | KeyCode::Enter | KeyCode::Char(' ') if !self.setup_focus => {
                self.setup_focus = true;
            }
            KeyCode::Left | KeyCode::Backspace if self.setup_focus => self.setup_focus = false,
            KeyCode::Up | KeyCode::Char('k') => {
                if self.setup_focus {
                    self.setup_option = self.setup_option.saturating_sub(1);
                } else {
                    self.setup_category = self.setup_category.saturating_sub(1);
                    self.setup_option = 0;
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.setup_focus {
                    self.setup_option = (self.setup_option + 1).min(self.setup_len() - 1);
                } else {
                    self.setup_category = (self.setup_category + 1).min(CATEGORY_COUNT - 1);
                    self.setup_option = 0;
                }
            }
            KeyCode::Home if self.setup_focus => self.setup_option = 0,
            KeyCode::End if self.setup_focus => self.setup_option = self.setup_len() - 1,
            KeyCode::PageDown if self.setup_focus => {
                self.setup_option = (self.setup_option + 8).min(self.setup_len() - 1)
            }
            KeyCode::PageUp if self.setup_focus => {
                self.setup_option = self.setup_option.saturating_sub(8)
            }
            KeyCode::Right
            | KeyCode::Enter
            | KeyCode::Char(' ')
            | KeyCode::Char('+')
            | KeyCode::Char('=')
            | KeyCode::Char('-')
                if self.setup_focus =>
            {
                let direction = if key.code == KeyCode::Char('-') {
                    -1
                } else {
                    1
                };
                return self.change_setup(direction);
            }
            _ => {}
        }
        Action::None
    }

    fn change_setup(&mut self, direction: i32) -> Action {
        match (self.setup_category, self.setup_option) {
            (0, 0) => self.settings.color = !self.settings.color,
            (0, 1) => {
                self.settings.interval_ms = (self.settings.interval_ms as i64
                    + i64::from(direction) * 100)
                    .clamp(100, 60_000) as u64
            }
            (0, 2) => self.settings.bits = !self.settings.bits,
            (0, 3) => self.settings.language = self.settings.language.next(direction),
            (1, row) => {
                let interface = if row == 0 {
                    self.auto_interface.clone()
                } else if row == 1 {
                    None
                } else {
                    self.snapshot
                        .interfaces
                        .get(row - 2)
                        .map(|iface| iface.name.clone())
                };
                self.set_interface(interface);
                if row == 0 {
                    self.settings.interface = None;
                }
                return Action::InterfaceChanged;
            }
            (2, 0) => self.settings.show_graph = !self.settings.show_graph,
            (2, 1) => {
                self.settings.history_seconds = (i32::from(self.settings.history_seconds)
                    + direction * 10)
                    .clamp(10, 600) as u16
            }
            (2, 2) => self.settings.graph_style = self.settings.graph_style.next(direction),
            (2, 3) => self.settings.rx_color = self.settings.rx_color.next(direction),
            (2, 4) => self.settings.tx_color = self.settings.tx_color.next(direction),
            (3, 0) => self.settings.connections = !self.settings.connections,
            (3, 1) => {
                let current = self.sort_index() as i32;
                self.settings.sort =
                    SORTS[(current + direction).rem_euclid(SORTS.len() as i32) as usize];
            }
            (3, 2) => self.settings.show_idle = !self.settings.show_idle,
            _ => {}
        }
        self.table.select(Some(0));
        Action::SettingsChanged
    }

    fn move_selection(&mut self, delta: isize) {
        let count = self.row_count();
        if count == 0 {
            self.table.select(None);
            return;
        }
        let current = self.table.selected().unwrap_or(0) as isize;
        self.table
            .select(Some((current + delta).clamp(0, count as isize - 1) as usize));
    }

    fn row_count(&self) -> usize {
        if self.settings.connections {
            self.connection_rows().len()
        } else {
            self.process_rows().len()
        }
    }

    pub fn process_rows(&self) -> Vec<&ProcessRow> {
        let filter = self.filter.to_lowercase();
        let mut rows: Vec<_> = self
            .snapshot
            .processes
            .iter()
            .filter(|row| {
                self.settings.show_idle
                    || !(self.snapshot.capture.active || self.demo)
                    || row.rx_rate > 0.0
                    || row.tx_rate > 0.0
            })
            .filter(|row| {
                filter.is_empty()
                    || format!("{} {} {}", pid(row.pid), row.user, row.name)
                        .to_lowercase()
                        .contains(&filter)
            })
            .collect();
        rows.sort_by(|a, b| {
            self.compare(
                a.rx_rate,
                a.tx_rate,
                a.rx_bytes.saturating_add(a.tx_bytes),
                a.pid,
                &a.name,
                b.rx_rate,
                b.tx_rate,
                b.rx_bytes.saturating_add(b.tx_bytes),
                b.pid,
                &b.name,
            )
        });
        rows
    }

    fn connection_rows(&self) -> Vec<&ConnectionRow> {
        let filter = self.filter.to_lowercase();
        let mut rows: Vec<_> = self
            .snapshot
            .connections
            .iter()
            .filter(|row| {
                self.settings.show_idle
                    || !(self.snapshot.capture.active || self.demo)
                    || row.rx_rate > 0.0
                    || row.tx_rate > 0.0
            })
            .filter(|row| {
                filter.is_empty()
                    || format!(
                        "{} {} {} {} {} {}",
                        pid(row.pid),
                        row.user,
                        row.process,
                        row.protocol,
                        row.local,
                        row.remote
                    )
                    .to_lowercase()
                    .contains(&filter)
            })
            .collect();
        rows.sort_by(|a, b| {
            self.compare(
                a.rx_rate,
                a.tx_rate,
                a.rx_bytes.saturating_add(a.tx_bytes),
                a.pid,
                &a.process,
                b.rx_rate,
                b.tx_rate,
                b.rx_bytes.saturating_add(b.tx_bytes),
                b.pid,
                &b.process,
            )
            .then_with(|| a.local.cmp(&b.local))
            .then_with(|| a.remote.cmp(&b.remote))
        });
        rows
    }

    #[allow(clippy::too_many_arguments)]
    fn compare(
        &self,
        arx: f64,
        atx: f64,
        total_a: u64,
        pid_a: Option<u32>,
        name_a: &str,
        brx: f64,
        btx: f64,
        total_b: u64,
        pid_b: Option<u32>,
        name_b: &str,
    ) -> Ordering {
        let order = match self.settings.sort {
            Sort::Traffic => (brx + btx).total_cmp(&(arx + atx)),
            Sort::Receive => brx.total_cmp(&arx),
            Sort::Send => btx.total_cmp(&atx),
            Sort::Total => total_b.cmp(&total_a),
            Sort::Pid => pid_a.unwrap_or(u32::MAX).cmp(&pid_b.unwrap_or(u32::MAX)),
            Sort::Name => name_a.cmp(name_b),
        };
        order.then_with(|| pid_a.unwrap_or(u32::MAX).cmp(&pid_b.unwrap_or(u32::MAX)))
    }
}

pub fn totals(snapshot: &Snapshot, interface: Option<&str>) -> (f64, f64, u64, u64) {
    snapshot
        .interfaces
        .iter()
        .filter(|iface| interface.is_none_or(|name| iface.name == name))
        .fold((0.0, 0.0, 0u64, 0u64), |(rx, tx, rb, tb), iface| {
            (
                rx + iface.rx_rate,
                tx + iface.tx_rate,
                rb.saturating_add(iface.rx_bytes),
                tb.saturating_add(iface.tx_bytes),
            )
        })
}

#[cfg(test)]
mod tests;
