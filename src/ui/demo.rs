//! Explicit preview data, isolated from live collection and rendering.

use crate::model::{ConnectionRow, Interface, ProcessRow, Snapshot};

/// Explicit preview data; only called when the user passes --demo or by tests.
pub fn demo_snapshot(tick: u64, elapsed: f64) -> Snapshot {
    let wave = |offset: f64, max: f64| {
        let t = tick as f64 * 0.23 + offset;
        (0.15 + (t.sin() * 0.5 + 0.5) * 0.68 + (t * 2.8).sin().abs() * 0.17) * max
    };
    let rx = wave(0.0, 14_500_000.0);
    let tx = wave(1.7, 4_500_000.0);
    let processes = [
        (4823, "brave", rx * 0.68, tx * 0.06, 24),
        (9645, "docker", rx * 0.12, tx * 0.72, 8),
        (1005126, "curl", rx * 0.18, tx * 0.02, 1),
        (12826, "syncthing", rx * 0.02, tx * 0.18, 12),
        (27180, "ssh", 640.0, 2100.0, 2),
        (31140, "systemd-resolved", 320.0, 240.0, 3),
    ]
    .into_iter()
    .map(|(id, name, down, up, connections)| ProcessRow {
        pid: Some(id),
        user: "tim".into(),
        name: name.into(),
        rx_rate: down,
        tx_rate: up,
        rx_bytes: (down * elapsed) as u64,
        tx_bytes: (up * elapsed) as u64,
        connections,
    })
    .collect::<Vec<_>>();
    let connections = processes
        .iter()
        .enumerate()
        .map(|(index, process)| ConnectionRow {
            pid: process.pid,
            user: process.user.clone(),
            process: process.name.clone(),
            protocol: if index == 5 {
                "UDP".into()
            } else {
                "TCP".into()
            },
            local: format!("192.0.2.10:{}", 42000 + index),
            remote: format!("198.51.100.{}:443", index + 10),
            state: "ESTABLISHED".into(),
            rx_rate: process.rx_rate,
            tx_rate: process.tx_rate,
            rx_bytes: process.rx_bytes,
            tx_bytes: process.tx_bytes,
        })
        .collect();
    Snapshot {
        elapsed,
        interfaces: vec![
            Interface {
                name: "enp112s0".into(),
                state: "up".into(),
                address: Some("192.0.2.10".into()),
                speed_mbps: Some(2500),
                mtu: Some(1500),
                rx_rate: rx,
                tx_rate: tx,
                rx_bytes: 14_820_000_000 + (elapsed * rx) as u64,
                tx_bytes: 4_320_000_000 + (elapsed * tx) as u64,
                ..Default::default()
            },
            Interface {
                name: "tailscale0".into(),
                state: "up".into(),
                is_virtual: true,
                rx_rate: 8200.0,
                tx_rate: 4100.0,
                mtu: Some(1280),
                ..Default::default()
            },
            Interface {
                name: "lo".into(),
                state: "up".into(),
                is_virtual: true,
                ..Default::default()
            },
        ],
        processes,
        connections,
        capture: crate::model::CaptureStatus {
            active: true,
            message: "DEMO data".into(),
            dropped: 0,
            notes: Vec::new(),
        },
    }
}
