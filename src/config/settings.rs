//! Versioned preference schema and validation, independent of filesystem I/O.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

// Additive optional fields keep version 1: older releases ignore them and newer
// releases fill missing fields with defaults.
const VERSION: u32 = 1;
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphStyle {
    #[default]
    Steps,
    Braille,
}

impl GraphStyle {
    pub fn next(self, direction: i32) -> Self {
        if direction.rem_euclid(2) == 0 {
            self
        } else {
            match self {
                Self::Steps => Self::Braille,
                Self::Braille => Self::Steps,
            }
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Steps => "Steps",
            Self::Braille => "Braille",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlotColor {
    #[default]
    Green,
    Yellow,
    Cyan,
    Red,
    Blue,
    Magenta,
    White,
}

impl PlotColor {
    pub fn next(self, direction: i32) -> Self {
        let colors = [
            Self::Green,
            Self::Yellow,
            Self::Cyan,
            Self::Red,
            Self::Blue,
            Self::Magenta,
            Self::White,
        ];
        let index = colors.iter().position(|color| *color == self).unwrap_or(0);
        colors[(index as i64 + i64::from(direction)).rem_euclid(colors.len() as i64) as usize]
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Green => "Green",
            Self::Yellow => "Yellow",
            Self::Cyan => "Cyan",
            Self::Red => "Red",
            Self::Blue => "Blue",
            Self::Magenta => "Magenta",
            Self::White => "White",
        }
    }
}

/// UI language. `Auto` follows LC_ALL, LC_MESSAGES or LANG at startup.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Language {
    #[default]
    Auto,
    En,
    De,
}

impl Language {
    pub fn next(self, direction: i32) -> Self {
        let choices = [Self::Auto, Self::En, Self::De];
        let index = choices
            .iter()
            .position(|choice| *choice == self)
            .unwrap_or(0);
        choices[(index as i64 + i64::from(direction)).rem_euclid(choices.len() as i64) as usize]
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SortKey {
    #[default]
    Traffic,
    Receive,
    Send,
    Total,
    Pid,
    Name,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub version: u32,
    pub interface: Option<String>,
    pub interval_ms: u64,
    pub history_seconds: u16,
    pub bits: bool,
    pub color: bool,
    pub show_graph: bool,
    pub graph_style: GraphStyle,
    pub rx_color: PlotColor,
    pub tx_color: PlotColor,
    pub connections: bool,
    pub sort: SortKey,
    pub show_idle: bool,
    pub language: Language,
}

/// One user preference, used to persist only what the user changed at runtime.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Field {
    Interface,
    IntervalMs,
    HistorySeconds,
    Bits,
    Color,
    ShowGraph,
    GraphStyle,
    RxColor,
    TxColor,
    Connections,
    Sort,
    ShowIdle,
    Language,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            version: VERSION,
            interface: None,
            interval_ms: 1000,
            history_seconds: 60,
            bits: false,
            color: true,
            show_graph: true,
            graph_style: GraphStyle::Steps,
            rx_color: PlotColor::Green,
            tx_color: PlotColor::Yellow,
            connections: false,
            sort: SortKey::Traffic,
            show_idle: true,
            language: Language::Auto,
        }
    }
}

impl Settings {
    /// Preferences whose values differ between both settings.
    pub fn differing(&self, other: &Self) -> Vec<Field> {
        // Exhaustive destructuring makes a new preference a compile error here
        // until it is also handled by `copy_field`.
        let Self {
            version: _,
            interface,
            interval_ms,
            history_seconds,
            bits,
            color,
            show_graph,
            graph_style,
            rx_color,
            tx_color,
            connections,
            sort,
            show_idle,
            language,
        } = self;
        [
            (Field::Interface, *interface != other.interface),
            (Field::IntervalMs, *interval_ms != other.interval_ms),
            (
                Field::HistorySeconds,
                *history_seconds != other.history_seconds,
            ),
            (Field::Bits, *bits != other.bits),
            (Field::Color, *color != other.color),
            (Field::ShowGraph, *show_graph != other.show_graph),
            (Field::GraphStyle, *graph_style != other.graph_style),
            (Field::RxColor, *rx_color != other.rx_color),
            (Field::TxColor, *tx_color != other.tx_color),
            (Field::Connections, *connections != other.connections),
            (Field::Sort, *sort != other.sort),
            (Field::ShowIdle, *show_idle != other.show_idle),
            (Field::Language, *language != other.language),
        ]
        .into_iter()
        .filter_map(|(field, differs)| differs.then_some(field))
        .collect()
    }

    pub fn copy_field(&mut self, from: &Self, field: Field) {
        match field {
            Field::Interface => self.interface.clone_from(&from.interface),
            Field::IntervalMs => self.interval_ms = from.interval_ms,
            Field::HistorySeconds => self.history_seconds = from.history_seconds,
            Field::Bits => self.bits = from.bits,
            Field::Color => self.color = from.color,
            Field::ShowGraph => self.show_graph = from.show_graph,
            Field::GraphStyle => self.graph_style = from.graph_style,
            Field::RxColor => self.rx_color = from.rx_color,
            Field::TxColor => self.tx_color = from.tx_color,
            Field::Connections => self.connections = from.connections,
            Field::Sort => self.sort = from.sort,
            Field::ShowIdle => self.show_idle = from.show_idle,
            Field::Language => self.language = from.language,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != VERSION {
            bail!(
                "unsupported settings version {}; this nwtop supports version {VERSION}",
                self.version
            );
        }
        if !(100..=60_000).contains(&self.interval_ms) {
            bail!("interval_ms must be between 100 and 60000");
        }
        if !(10..=600).contains(&self.history_seconds) {
            bail!("history_seconds must be between 10 and 600");
        }
        if let Some(name) = &self.interface
            && (name.is_empty()
                || name.len() >= libc::IFNAMSIZ
                || name == "."
                || name == ".."
                || name
                    .chars()
                    .any(|c| c.is_control() || c.is_whitespace() || c == '/' || c == ':'))
        {
            bail!("interface must be 'all' or a valid Linux interface name");
        }
        Ok(())
    }
}
