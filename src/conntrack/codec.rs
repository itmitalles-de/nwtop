//! Validation of netlink messages into conntrack metadata; no I/O or cache writes.

use super::{
    CT_DELETE, CT_NEW, Entry, Event, Identity, MAX_ATTRIBUTES, MAX_CACHE_AGE, Message, Protocol,
    Tuple,
};
use anyhow::{Context, Result, bail};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::{Duration, Instant},
};

pub(super) fn attributes(mut bytes: &[u8]) -> Result<Vec<(u16, &[u8])>> {
    let mut result = Vec::new();
    while !bytes.is_empty() {
        if bytes.len() < 4 || result.len() >= MAX_ATTRIBUTES {
            bail!("invalid conntrack attribute header");
        }
        let length = u16::from_ne_bytes([bytes[0], bytes[1]]) as usize;
        let kind = u16::from_ne_bytes([bytes[2], bytes[3]]) & 0x3fff;
        if length < 4 || length > bytes.len() {
            bail!("invalid conntrack attribute length");
        }
        result.push((kind, &bytes[4..length]));
        let aligned = (length + 3) & !3;
        if aligned > bytes.len() {
            bail!("truncated conntrack attribute padding");
        }
        bytes = &bytes[aligned..];
    }
    Ok(result)
}

fn attr<'a>(attributes: &[(u16, &'a [u8])], kind: u16) -> Result<Option<&'a [u8]>> {
    let mut found = attributes
        .iter()
        .filter(|(candidate, _)| *candidate == kind);
    let value = found.next().map(|(_, value)| *value);
    if found.next().is_some() {
        bail!("duplicate conntrack attribute");
    }
    Ok(value)
}

fn required<'a>(attributes: &[(u16, &'a [u8])], kind: u16) -> Result<&'a [u8]> {
    attr(attributes, kind)?.context("missing conntrack attribute")
}

fn be16(bytes: &[u8]) -> Result<u16> {
    Ok(u16::from_be_bytes(
        bytes.try_into().context("invalid conntrack u16")?,
    ))
}
fn be32(bytes: &[u8]) -> Result<u32> {
    Ok(u32::from_be_bytes(
        bytes.try_into().context("invalid conntrack u32")?,
    ))
}

fn parse_tuple(bytes: &[u8], family: u8, default_zone: u16) -> Result<Option<(Tuple, u16)>> {
    let fields = attributes(bytes)?;
    let proto = attributes(required(&fields, 2)?)?;
    let number = required(&proto, 1)?;
    let protocol = match number {
        [6] => Protocol::Tcp,
        [17] => Protocol::Udp,
        [_] => return Ok(None),
        _ => bail!("invalid conntrack protocol"),
    };
    let ip = attributes(required(&fields, 1)?)?;
    let (source, destination) = if family == libc::AF_INET as u8 {
        (
            IpAddr::V4(Ipv4Addr::from(
                <[u8; 4]>::try_from(required(&ip, 1)?).context("invalid conntrack IPv4")?,
            )),
            IpAddr::V4(Ipv4Addr::from(
                <[u8; 4]>::try_from(required(&ip, 2)?).context("invalid conntrack IPv4")?,
            )),
        )
    } else if family == libc::AF_INET6 as u8 {
        (
            IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(required(&ip, 3)?).context("invalid conntrack IPv6")?,
            )),
            IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(required(&ip, 4)?).context("invalid conntrack IPv6")?,
            )),
        )
    } else {
        return Ok(None);
    };
    let zone = attr(&fields, 3)?
        .map(be16)
        .transpose()?
        .unwrap_or(default_zone);
    Ok(Some((
        Tuple {
            protocol,
            source: SocketAddr::new(source, be16(required(&proto, 2)?)?),
            destination: SocketAddr::new(destination, be16(required(&proto, 3)?)?),
        },
        zone,
    )))
}

pub(super) fn parse_entry(bytes: &[u8], delete: bool, now: Instant) -> Result<Option<Event>> {
    if bytes.len() < 4 || bytes[1] != 0 {
        bail!("invalid conntrack nfgenmsg");
    }
    let family = bytes[0];
    if family != libc::AF_INET as u8 && family != libc::AF_INET6 as u8 {
        return Ok(None);
    }
    let fields = attributes(&bytes[4..])?;
    let zone = attr(&fields, 18)?.map(be16).transpose()?.unwrap_or(0);
    let Some((original, original_zone)) = parse_tuple(required(&fields, 1)?, family, zone)? else {
        return Ok(None);
    };
    let Some((reply, reply_zone)) = parse_tuple(required(&fields, 2)?, family, zone)? else {
        bail!("conntrack reply protocol differs");
    };
    if original.protocol != reply.protocol {
        bail!("conntrack tuple protocols differ");
    }
    let identity = Identity {
        id: be32(required(&fields, 12)?)?,
        original,
        zones: (original_zone, reply_zone),
    };
    if delete {
        return Ok(Some(Event::Delete(Entry {
            identity,
            reply,
            expires: now,
        })));
    }
    let timeout = be32(required(&fields, 7)?)?;
    let expires = now + Duration::from_secs(timeout as u64).min(MAX_CACHE_AGE);
    Ok(Some(Event::Upsert(Entry {
        identity,
        reply,
        expires,
    })))
}

pub(super) fn parse_datagram(mut bytes: &[u8], now: Instant) -> Result<Vec<Message>> {
    let mut messages = Vec::new();
    while !bytes.is_empty() {
        if bytes.len() < 16 {
            bail!("truncated conntrack netlink header");
        }
        let length = u32::from_ne_bytes(bytes[..4].try_into().unwrap()) as usize;
        let kind = u16::from_ne_bytes(bytes[4..6].try_into().unwrap());
        let flags = u16::from_ne_bytes(bytes[6..8].try_into().unwrap());
        let sequence = u32::from_ne_bytes(bytes[8..12].try_into().unwrap());
        if length < 16 || length > bytes.len() {
            bail!("invalid conntrack message length");
        }
        if flags & 0x10 != 0 {
            bail!("conntrack dump interrupted");
        }
        let body = &bytes[16..length];
        match kind {
            1 => {} // NLMSG_NOOP
            2 => {
                if body.len() < 4 {
                    bail!("truncated conntrack error");
                }
                let error = i32::from_ne_bytes(body[..4].try_into().unwrap());
                if error != 0 {
                    bail!(
                        "conntrack netlink error {}",
                        std::io::Error::from_raw_os_error(error.saturating_neg())
                    );
                }
            }
            3 => {
                if !body.is_empty()
                    && (body.len() < 4 || i32::from_ne_bytes(body[..4].try_into().unwrap()) != 0)
                {
                    bail!("conntrack dump failed");
                }
                messages.push(Message::Done(sequence));
            }
            4 => bail!("conntrack event buffer overrun"),
            CT_NEW | CT_DELETE => {
                if let Some(event) = parse_entry(body, kind == CT_DELETE, now)? {
                    messages.push(Message::Event { sequence, event });
                }
            }
            _ => {}
        }
        let aligned = (length + 3) & !3;
        if aligned > bytes.len() {
            bail!("truncated conntrack message padding");
        }
        bytes = &bytes[aligned..];
    }
    Ok(messages)
}
