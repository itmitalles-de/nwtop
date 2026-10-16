//! Braille and step history plots share the same samples and scale.

use super::{DIM, plot_color};
use crate::{
    config::GraphStyle,
    ui::{App, format_rate},
};
use ratatui::{
    Frame,
    layout::Rect,
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
    let peak = app
        .history
        .iter()
        .flat_map(|sample| [sample.rx, sample.tx])
        .fold(1024.0f64, f64::max)
        * 1.1;
    let labels = [0.0, peak / 2.0, peak].map(|value| {
        Line::from(
            format_rate(value, app.settings.bits)
                .trim_end_matches("/s")
                .to_string(),
        )
    });
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
                    Line::from(format!("-{:.0}s", app.history_seconds())),
                    Line::from(format!("-{:.0}s", app.history_seconds() / 2.0)),
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

fn draw_step_graph(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let block = Block::default().borders(Borders::ALL);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.width < 14 || inner.height < 3 {
        return;
    }
    let peak = app
        .history
        .iter()
        .flat_map(|sample| [sample.rx, sample.tx])
        .fold(1024.0f64, f64::max)
        * 1.1;
    let labels = [peak, peak / 2.0, 0.0].map(|value| {
        format_rate(value, app.settings.bits)
            .trim_end_matches("/s")
            .to_owned()
    });
    let label_width = labels.iter().map(String::len).max().unwrap_or(6).min(11) as u16;
    let plot = Rect {
        x: inner.x + label_width + 1,
        y: inner.y,
        width: inner.width.saturating_sub(label_width + 1),
        height: inner.height - 1,
    };
    for (index, label) in labels.iter().enumerate() {
        let y = plot.y + (plot.height - 1) * index as u16 / 2;
        frame.render_widget(
            Paragraph::new(label.as_str()).alignment(ratatui::layout::Alignment::Right),
            Rect::new(inner.x, y, label_width, 1),
        );
    }
    let now = app.history.back().map_or(0.0, |sample| sample.at);
    // Draw TX first, so RX stays visible at intersections. Each series uses
    // terminal line characters, as in nvtop, rather than colored dot cells.
    for (receive, color) in [
        (false, app.settings.tx_color),
        (true, app.settings.rx_color),
    ] {
        let mut columns = vec![None; usize::from(plot.width)];
        for sample in &app.history {
            let progress = (sample.at - now + app.history_seconds()) / app.history_seconds();
            if !(0.0..=1.0).contains(&progress) {
                continue;
            }
            let x = (progress * f64::from(plot.width - 1)).round() as usize;
            let value = if receive { sample.rx } else { sample.tx };
            let y = ((1.0 - (value / peak).clamp(0.0, 1.0)) * f64::from(plot.height - 1)).round()
                as u16;
            columns[x] = Some(y);
        }
        let mut paths = vec![0u8; usize::from(plot.width) * usize::from(plot.height)];
        let index = |x: u16, y: u16| usize::from(y) * usize::from(plot.width) + usize::from(x);
        let mut previous = None;
        for (x, y) in columns
            .into_iter()
            .enumerate()
            .filter_map(|(x, y)| y.map(|y| (x as u16, y)))
        {
            if let Some((px, py)) = previous {
                for column in px..x {
                    paths[index(column, py)] |= 2;
                    paths[index(column + 1, py)] |= 8;
                }
                for row in py.min(y)..py.max(y) {
                    paths[index(x, row)] |= 4;
                    paths[index(x, row + 1)] |= 1;
                }
            } else {
                paths[index(x, y)] = 10;
            }
            previous = Some((x, y));
        }
        for y in 0..plot.height {
            for x in 0..plot.width {
                let symbol = match paths[index(x, y)] {
                    0 => continue,
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
                };
                frame.buffer_mut()[(plot.x + x, plot.y + y)]
                    .set_symbol(symbol)
                    .set_style(Style::default().fg(plot_color(color)));
            }
        }
    }
    for (row, label, color) in [
        (0, "RX", app.settings.rx_color),
        (1, "TX", app.settings.tx_color),
    ] {
        frame.render_widget(
            Paragraph::new(label).style(Style::default().fg(plot_color(color))),
            Rect::new(plot.x + 1, plot.y + row, 2, 1),
        );
    }
    let label_y = inner.bottom() - 1;
    frame.buffer_mut().set_stringn(
        plot.x,
        label_y,
        format!("-{:.0}s", app.history_seconds()),
        usize::from(plot.width),
        Style::default(),
    );
    if plot.width >= 28 {
        let label = format!("-{:.0}s", app.history_seconds() / 2.0);
        frame.buffer_mut().set_stringn(
            plot.x + (plot.width - label.len() as u16) / 2,
            label_y,
            &label,
            label.len(),
            Style::default(),
        );
    }
    frame
        .buffer_mut()
        .set_stringn(plot.right() - 2, label_y, "0s", 2, Style::default());
}
