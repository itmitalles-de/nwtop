//! Per-snapshot capture status notes.
use super::{Attribution, IntervalStatus, extended};
use crate::model::{CaptureNote, CaptureStatus};

impl Attribution {
    /// Status notes for one snapshot. `problems` covers only this interval,
    /// so a past burst never taints later snapshots.
    pub(super) fn capture_status(
        &self,
        problems: &IntervalStatus,
        interface: Option<&str>,
        capture_note: Option<&CaptureNote>,
        counter_limit: bool,
    ) -> CaptureStatus {
        let mut status = CaptureStatus {
            active: self.capture.is_some(),
            notes: capture_note.into_iter().cloned().collect(),
            ..CaptureStatus::default()
        };
        if let Some(capture) = &self.capture {
            pcap_status(
                &mut status,
                problems,
                interface.is_some(),
                capture.interface_indexes,
                self.worker_error.as_deref(),
                self.capture_error.as_deref(),
            );
        }
        if let Some(extended) = &self.extended {
            extended_status(&mut status, extended, problems, interface.is_none());
        }
        if self.inventory.restricted {
            status.notes.push(CaptureNote::OwnersInaccessible);
        }
        if self.inventory.limited || counter_limit {
            status.notes.push(CaptureNote::CounterLimit);
        }
        status
    }
}

/// Notes of a running pcap session.
pub(super) fn pcap_status(
    status: &mut CaptureStatus,
    problems: &IntervalStatus,
    selected: bool,
    interface_indexes: bool,
    worker_error: Option<&str>,
    capture_error: Option<&str>,
) {
    status.dropped = problems.dropped.saturating_add(problems.overflow);
    status.notes = vec![if selected && !interface_indexes {
        status.active = false;
        CaptureNote::NoInterfaceIndexes
    } else if !selected {
        CaptureNote::AllInterfaces
    } else {
        CaptureNote::Sampled
    }];
    if problems.dropped > 0 {
        status.notes.push(CaptureNote::PcapMissed {
            packets: problems.dropped,
        });
    }
    if problems.overflow > 0 {
        status.notes.push(CaptureNote::CaptureQueueLimit {
            packets: problems.overflow,
        });
    }
    if problems.attribution_overflow > 0 {
        status.notes.push(CaptureNote::AttributionQueueLimit {
            packets: problems.attribution_overflow,
        });
    }
    if problems.unsupported > 0 || problems.truncated > 0 {
        status.notes.push(CaptureNote::Unreadable {
            unsupported: problems.unsupported,
            truncated: problems.truncated,
        });
    }
    if let Some(error) = worker_error {
        status.notes.push(CaptureNote::AttributionAtRefresh {
            error: error.to_string(),
        });
    }
    if let Some(error) = capture_error {
        status.active = false;
        status.notes = vec![CaptureNote::Stopped {
            error: error.to_string(),
        }];
    }
}

/// Notes of optional socket events and NAT metadata. Reading them clears
/// the per-interval unconfirmed-flow flag.
pub(super) fn extended_status(
    status: &mut CaptureStatus,
    extended: &extended::Extended,
    problems: &IntervalStatus,
    all_interfaces: bool,
) {
    let socket_packets = all_interfaces && extended.packet_capture_active();
    if socket_packets {
        for note in &mut status.notes {
            if *note == CaptureNote::AllInterfaces {
                *note = CaptureNote::AllSocketPackets;
            }
        }
    }
    if all_interfaces && extended.packet_capture_failed() {
        status.active = false;
    }
    if extended.available() {
        status.notes.retain(|note| *note != CaptureNote::Sampled);
        status.notes.push(CaptureNote::Extended);
    }
    if extended.available() && !socket_packets && problems.timestamp_invalid > 0 {
        status.notes.push(CaptureNote::ExtendedIssue {
            detail: format!(
                "{} packet timestamps unavailable; uncertain event owners withheld",
                problems.timestamp_invalid
            ),
        });
    }
    for detail in &extended.issues {
        status.notes.push(CaptureNote::ExtendedIssue {
            detail: detail.clone(),
        });
    }
    if extended.unconfirmed.replace(false) && !socket_packets {
        status.notes.push(CaptureNote::ExtendedIssue {
            detail: "no confirmed conntrack entry for some flows; only positive socket events can attribute them".into(),
        });
    }
}
