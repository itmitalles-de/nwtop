//! Braille and step history plots share the same samples and scale.

use super::{DIM, history_peak, plot_color, short_rate};
use crate::{config::GraphStyle, ui::App};
use ratatui::{
    Frame,
    layout::{Alignment, Rect},
    style::Style,
    symbols,
    text::Line,
    widgets::{Axis, Block, Borders, Chart, Dataset, GraphType, Paragraph},
};

pub(super) fn draw_graph(frame: &mut Frame<'_>, app: &App, area: Rect) {
    if area.height == 0 {
        return;
    }
    if app.settings.graph_style == GraphStyle::Steps {
        draw_step_graph(frame, app, area);
        return;
    }
    let now = app.history.back().map_or(0.0, |sample| sample.at);
    let rx: Vec<_> = app
        .history
        .iter()
        .map(|sample| (sample.at - now, sample.rx))
        .collect();
    let tx: Vec<_> = app
        .history
        .iter()
        .map(|sample| (sample.at - now, sample.tx))
        .collect();
    let peak = plot_ceiling(app);
    let labels =
        [0.0, peak / 2.0, peak].map(|value| Line::from(short_rate(value, app.settings.bits)));
    let datasets = vec![
        Dataset::default()
            .name("RX")
            .marker(symbols::Marker::Braille)
            .graph_type(GraphType::Line)
            .style(Style::default().fg(plot_color(app.settings.rx_color)))
            .data(&rx),
        Dataset::default()
            .name("TX")
            .marker(symbols::Marker::Braille)
            .graph_type(GraphType::Line)
            .style(Style::default().fg(plot_color(app.settings.tx_color)))
            .data(&tx),
    ];
    let chart = Chart::new(datasets)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default()),
        )
        .x_axis(
            Axis::default()
                .style(Style::default().fg(DIM))
                .bounds([-app.history_seconds(), 0.0])
                .labels([
                    Line::from(seconds_ago(app.history_seconds())),
                    Line::from(seconds_ago(app.history_seconds() / 2.0)),
                    Line::from("0s"),
                ]),
        )
        .y_axis(
            Axis::default()
                .style(Style::default().fg(DIM))
                .bounds([0.0, peak])
                .labels(labels),
        );
    frame.render_widget(chart, area);
}

/// Top of the rate axis: the history peak plus 10% headroom.
fn plot_ceiling(app: &App) -> f64 {
    history_peak(app) * 1.1
}

/// Time axis label such as "-60s".
fn seconds_ago(seconds: f64) -> String {
    format!("-{seconds:.0}s")
}

fn draw_step_graph(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let block = Block::default().borders(Borders::ALL);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.width < 14 || inner.height < 3 {
        return;
    }
    let peak = plot_ceiling(app);
    let labels = [peak, peak / 2.0, 0.0].map(|value| short_rate(value, app.settings.bits));
    let label_width = labels.iter().map(String::len).max().unwrap_or(6).min(11) as u16;
    // The bottom row of the frame interior holds the time axis labels.
    let plot = Rect {
        x: inner.x + label_width + 1,
        y: inner.y,
        width: inner.width.saturating_sub(label_width + 1),
        height: inner.height - 1,
    };
    draw_rate_labels(frame, &labels, inner.x, label_width, plot);
    // Draw TX first, so RX stays visible at intersections. Each series uses
    // terminal line characters, as in nvtop, rather than colored dot cells.
    for (receive, color) in [
        (false, app.settings.tx_color),
        (true, app.settings.rx_color),
    ] {
        let columns = step_columns(app, plot, peak, receive);
        let paths = step_paths(columns, plot.width, plot.height);
        draw_step_paths(frame, plot, &paths, Style::default().fg(plot_color(color)));
    }
    draw_step_legend(frame, app, plot);
    draw_step_time_labels(frame, app, plot, inner.bottom() - 1);
}

/// Right-aligned top, middle and zero rate labels left of the plot.
fn draw_rate_labels(frame: &mut Frame<'_>, labels: &[String], x: u16, width: u16, plot: Rect) {
    for (index, label) in labels.iter().enumerate() {
        let y = plot.y + (plot.height - 1) * index as u16 / 2;
        frame.render_widget(
            Paragraph::new(label.as_str()).alignment(Alignment::Right),
            Rect::new(x, y, width, 1),
        );
    }
}

/// Plot row of the newest sample in each column; samples outside the history
/// window are skipped.
fn step_columns(app: &App, plot: Rect, peak: f64, receive: bool) -> Vec<Option<u16>> {
    let now = app.history.back().map_or(0.0, |sample| sample.at);
    let mut columns = vec![None; usize::from(plot.width)];
    for sample in &app.history {
        let progress = (sample.at - now + app.history_seconds()) / app.history_seconds();
        if !(0.0..=1.0).contains(&progress) {
            continue;
        }
        let x = (progress * f64::from(plot.width - 1)).round() as usize;
        let value = if receive { sample.rx } else { sample.tx };
        let y =
            ((1.0 - (value / peak).clamp(0.0, 1.0)) * f64::from(plot.height - 1)).round() as u16;
        columns[x] = Some(y);
    }
    columns
}

// Directions a line leaves a cell in, combined into one mask per cell.
const UP: u8 = 1;
const RIGHT: u8 = 2;
const DOWN: u8 = 4;
const LEFT: u8 = 8;

/// Joins consecutive column points with horizontal-then-vertical steps and
/// returns one direction mask per plot cell, row by row.
fn step_paths(columns: Vec<Option<u16>>, width: u16, height: u16) -> Vec<u8> {
    let mut paths = vec![0u8; usize::from(width) * usize::from(height)];
    let index = |x: u16, y: u16| usize::from(y) * usize::from(width) + usize::from(x);
    let mut previous = None;
    for (x, y) in columns
        .into_iter()
        .enumerate()
        .filter_map(|(x, y)| y.map(|y| (x as u16, y)))
    {
        if let Some((px, py)) = previous {
            for column in px..x {
                paths[index(column, py)] |= RIGHT;
                paths[index(column + 1, py)] |= LEFT;
            }
            for row in py.min(y)..py.max(y) {
                paths[index(x, row)] |= DOWN;
                paths[index(x, row + 1)] |= UP;
            }
        } else {
            paths[index(x, y)] = LEFT | RIGHT;
        }
        previous = Some((x, y));
    }
    paths
}

/// Box-drawing character for a direction mask; `None` leaves the cell empty.
fn path_symbol(mask: u8) -> Option<&'static str> {
    Some(match mask {
        0 => return None,
        1 | 4 | 5 => "│",
        2 | 8 | 10 => "─",
        3 => "└",
        6 => "┌",
        9 => "┘",
        12 => "┐",
        7 => "├",
        11 => "┴",
        13 => "┤",
        14 => "┬",
        _ => "┼",
    })
}

fn draw_step_paths(frame: &mut Frame<'_>, plot: Rect, paths: &[u8], style: Style) {
    for y in 0..plot.height {
        for x in 0..plot.width {
            let mask = paths[usize::from(y) * usize::from(plot.width) + usize::from(x)];
            if let Some(symbol) = path_symbol(mask) {
                frame.buffer_mut()[(plot.x + x, plot.y + y)]
                    .set_symbol(symbol)
                    .set_style(style);
            }
        }
    }
}

fn draw_step_legend(frame: &mut Frame<'_>, app: &App, plot: Rect) {
    for (row, label, color) in [
        (0, "RX", app.settings.rx_color),
        (1, "TX", app.settings.tx_color),
    ] {
        frame.render_widget(
            Paragraph::new(label).style(Style::default().fg(plot_color(color))),
            Rect::new(plot.x + 1, plot.y + row, 2, 1),
        );
    }
}

/// Oldest, middle (when there is room) and current time below the plot.
fn draw_step_time_labels(frame: &mut Frame<'_>, app: &App, plot: Rect, y: u16) {
    frame.buffer_mut().set_stringn(
        plot.x,
        y,
        seconds_ago(app.history_seconds()),
        usize::from(plot.width),
        Style::default(),
    );
    if plot.width >= 28 {
        let label = seconds_ago(app.history_seconds() / 2.0);
        frame.buffer_mut().set_stringn(
            plot.x + (plot.width - label.len() as u16) / 2,
            y,
            &label,
            label.len(),
            Style::default(),
        );
    }
    frame
        .buffer_mut()
        .set_stringn(plot.right() - 2, y, "0s", 2, Style::default());
}
