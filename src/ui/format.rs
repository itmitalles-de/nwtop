//! Display units shared by the TUI and non-interactive output.

pub fn format_rate(bytes: f64, bits: bool) -> String {
    if bits {
        let (value, unit, decimals) = scaled(
            bytes.max(0.0) * 8.0,
            1000.0,
            &["bit", "kbit", "Mbit", "Gbit", "Tbit"],
            |_| 1,
        );
        format!("{value:.decimals$} {unit}/s")
    } else {
        format!("{}/s", format_bytes(bytes))
    }
}

pub fn format_bytes(bytes: f64) -> String {
    let (value, unit, decimals) = scaled(
        bytes.max(0.0),
        1024.0,
        &["B", "KiB", "MiB", "GiB", "TiB"],
        |index| if index == 0 { 0 } else { 1 },
    );
    format!("{value:.decimals$} {unit}")
}

/// Scale to the largest unit below `base` after rounding to the displayed
/// precision, so 1023.96 KiB becomes "1.0 MiB" rather than "1024.0 KiB".
/// Below the last unit, the result is at most "999.9 kbit" or "1023.9 KiB".
fn scaled(
    value: f64,
    base: f64,
    units: &'static [&'static str],
    decimals: impl Fn(usize) -> usize,
) -> (f64, &'static str, usize) {
    let mut value = if value.is_finite() { value } else { 0.0 };
    let mut index = 0;
    loop {
        let factor = 10f64.powi(decimals(index) as i32);
        let rounded = (value * factor).round() / factor;
        if rounded < base || index + 1 == units.len() {
            return (rounded, units[index], decimals(index));
        }
        value /= base;
        index += 1;
    }
}

pub(super) fn pid(value: Option<u32>) -> String {
    value.map_or_else(|| "-".into(), |value| value.to_string())
}
