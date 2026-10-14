//! Linux interface counters, addresses, topology and default-route selection.

use super::{KernelInterface, LinkTopology};
use crate::model::Interface;
use anyhow::{Context, Result, bail};
use std::{
    collections::{HashMap, HashSet},
    ffi::{CStr, CString},
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::{Duration, Instant},
};

/// Bridge, bond and VLAN membership is reread at most this often by the
/// background worker, and whenever the set of links changes.
const TOPOLOGY_REFRESH: Duration = Duration::from_secs(2);

pub(super) fn read_interfaces() -> Result<Vec<KernelInterface>> {
    let contents = fs::read_to_string("/proc/net/dev")
        .context("reading Linux network counters (/proc/net/dev)")?;
    let mut addresses = interface_addresses();
    let mut interfaces = Vec::new();
    for line in contents.lines().skip(2) {
        let Some((name, values)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        let values: Vec<_> = values
            .split_ascii_whitespace()
            .filter_map(|value| value.parse::<u64>().ok())
            .collect();
        if values.len() != 16 {
            continue;
        }
        // An interface that vanished since /proc/net/dev was read has no
        // index; skip it rather than merging it with others under index 0.
        let Some(index) = interface_index(name) else {
            continue;
        };
        let path = format!("/sys/class/net/{name}");
        let read = |file: &str| {
            fs::read_to_string(format!("{path}/{file}"))
                .ok()
                .map(|value| value.trim().to_string())
        };
        let link = addresses.remove(&index).unwrap_or_default();
        let interface_ips = link.addresses;
        let address = interface_ips
            .iter()
            .find(|ip| ip.is_ipv4())
            .or(interface_ips.first())
            .map(ToString::to_string);
        let loopback = link.loopback || read("type").is_some_and(|value| value == "772");
        interfaces.push(KernelInterface {
            info: Interface {
                name: name.to_string(),
                state: read("operstate").unwrap_or_else(|| "unknown".to_string()),
                address,
                speed_mbps: read("speed")
                    .and_then(|value| value.parse::<i64>().ok())
                    .filter(|speed| *speed > 0)
                    .map(|speed| speed as u64),
                mtu: read("mtu").and_then(|value| value.parse().ok()),
                is_virtual: fs::canonicalize(&path)
                    .is_ok_and(|path| path.to_string_lossy().contains("/virtual/")),
                rx_bytes: values[0],
                rx_packets: values[1],
                tx_bytes: values[8],
                tx_packets: values[9],
                errors: values[2].saturating_add(values[10]),
                dropped: values[3].saturating_add(values[11]),
                ..Interface::default()
            },
            index,
            addresses: interface_ips,
            loopback,
            topology: LinkTopology::default(),
        });
    }
    if interfaces.is_empty() {
        bail!("/proc/net/dev contains no network interfaces");
    }
    let mut topology = read_topology(
        interfaces
            .iter()
            .map(|interface| (interface.index, interface.info.name.as_str())),
    );
    for interface in &mut interfaces {
        interface.topology = topology.remove(&interface.index).unwrap_or_default();
    }
    interfaces.sort_by(|a, b| a.info.name.cmp(&b.info.name));
    Ok(interfaces)
}

fn interface_index(name: &str) -> Option<u32> {
    let name = CString::new(name).ok()?;
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    (index != 0).then_some(index)
}

/// IPv4 alias addresses carry their label ("eth0:1") as the name; Linux
/// interface names never contain ':' so the base name identifies the device.
fn base_interface_name(label: &str) -> &str {
    label.split_once(':').map_or(label, |(name, _)| name)
}

#[derive(Debug, Default)]
struct LinkAddresses {
    name: String,
    addresses: Vec<IpAddr>,
    loopback: bool,
}

/// Addresses and loopback flags keyed by interface index, so alias labels and
/// renamed devices still map to the link that owns them.
fn interface_addresses() -> HashMap<u32, LinkAddresses> {
    let mut result: HashMap<u32, LinkAddresses> = HashMap::new();
    let mut head = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return result;
    }
    let mut entries = Vec::new();
    // AF_PACKET entries carry each link's kernel index, avoiding one
    // if_nametoindex socket per device on every background tick.
    let mut indexes: HashMap<String, Option<u32>> = HashMap::new();
    let mut current = head;
    while !current.is_null() {
        let interface = unsafe { &*current };
        if !interface.ifa_name.is_null() {
            let label = unsafe { CStr::from_ptr(interface.ifa_name) }.to_string_lossy();
            let name = base_interface_name(&label).to_string();
            let address = interface.ifa_addr;
            if !address.is_null() && unsafe { (*address).sa_family as i32 } == libc::AF_PACKET {
                let link = unsafe { &*(address as *const libc::sockaddr_ll) };
                if link.sll_ifindex > 0 {
                    indexes.insert(name.clone(), Some(link.sll_ifindex as u32));
                }
            }
            let loopback = interface.ifa_flags & libc::IFF_LOOPBACK as u32 != 0;
            entries.push((name, loopback, socket_ip(address)));
        }
        current = interface.ifa_next;
    }
    unsafe { libc::freeifaddrs(head) };
    for (name, loopback, ip) in entries {
        let index = *indexes
            .entry(name.clone())
            .or_insert_with_key(|name| interface_index(name));
        let Some(index) = index else {
            continue;
        };
        let link = result.entry(index).or_default();
        if link.name.is_empty() {
            link.name = name;
        }
        link.loopback |= loopback;
        if let Some(ip) = ip
            && !link.addresses.contains(&ip)
        {
            link.addresses.push(ip);
        }
    }
    result
}

fn socket_ip(address: *const libc::sockaddr) -> Option<IpAddr> {
    if address.is_null() {
        return None;
    }
    match unsafe { (*address).sa_family as i32 } {
        libc::AF_INET => {
            let address = unsafe { &*(address as *const libc::sockaddr_in) };
            Some(IpAddr::V4(Ipv4Addr::from(
                address.sin_addr.s_addr.to_ne_bytes(),
            )))
        }
        libc::AF_INET6 => {
            let address = unsafe { &*(address as *const libc::sockaddr_in6) };
            Some(IpAddr::V6(Ipv6Addr::from(address.sin6_addr.s6_addr)))
        }
        _ => None,
    }
}

/// Masters and uppers of each link from sysfs: `master` and `upper_*`
/// entries (bridge/bond membership, VLAN, macvlan and other stacked devices).
fn read_topology<'a>(
    links: impl Iterator<Item = (u32, &'a str)> + Clone,
) -> HashMap<u32, LinkTopology> {
    let indexes: HashMap<&str, u32> = links.clone().map(|(index, name)| (name, index)).collect();
    links
        .filter_map(|(index, name)| {
            let path = format!("/sys/class/net/{name}");
            let master = fs::symlink_metadata(format!("{path}/master")).is_ok();
            let uppers: Vec<u32> = fs::read_dir(&path)
                .into_iter()
                .flatten()
                .filter_map(Result::ok)
                .filter_map(|entry| {
                    let entry = entry.file_name();
                    let upper = entry.to_str()?.strip_prefix("upper_")?;
                    indexes.get(upper).copied()
                })
                .collect();
            (master || !uppers.is_empty()).then_some((index, LinkTopology { master, uppers }))
        })
        .collect()
}

/// The worker rereads sysfs topology only periodically or when links change.
#[derive(Default)]
pub(super) struct TopologyCache {
    links: Vec<(u32, String)>,
    topology: HashMap<u32, LinkTopology>,
    read: Option<Instant>,
}

impl TopologyCache {
    fn get(&mut self, mut links: Vec<(u32, String)>) -> &HashMap<u32, LinkTopology> {
        links.sort();
        let now = Instant::now();
        if links != self.links
            || self
                .read
                .is_none_or(|read| now.saturating_duration_since(read) >= TOPOLOGY_REFRESH)
        {
            self.topology =
                read_topology(links.iter().map(|(index, name)| (*index, name.as_str())));
            self.links = links;
            self.read = Some(now);
        }
        &self.topology
    }
}

/// The address view the background worker needs for attribution, without
/// the per-device counter reads of a full snapshot.
pub(super) fn local_interfaces(cache: &mut TopologyCache) -> Vec<KernelInterface> {
    let links = interface_addresses();
    let topology = cache.get(
        links
            .iter()
            .map(|(index, link)| (*index, link.name.clone()))
            .collect(),
    );
    links
        .into_iter()
        .map(|(index, link)| KernelInterface {
            info: Interface {
                name: link.name,
                ..Interface::default()
            },
            index,
            addresses: link.addresses,
            loopback: link.loopback,
            topology: topology.get(&index).cloned().unwrap_or_default(),
        })
        .collect()
}

/// Prefer the lowest-metric default route, then a physical link, then loopback.
pub fn default_interface() -> Option<String> {
    let mut routes = Vec::new();
    if let Ok(contents) = fs::read_to_string("/proc/net/route") {
        for line in contents.lines().skip(1) {
            let fields: Vec<_> = line.split_ascii_whitespace().collect();
            if fields.len() >= 8
                && fields[1] == "00000000"
                && u32::from_str_radix(fields[3], 16).is_ok_and(|flags| flags & 1 == 1)
                && let Ok(metric) = fields[6].parse::<u32>()
            {
                routes.push((metric, fields[0].to_string()));
            }
        }
    }
    if let Ok(contents) = fs::read_to_string("/proc/net/ipv6_route") {
        for line in contents.lines() {
            let fields: Vec<_> = line.split_ascii_whitespace().collect();
            if fields.len() >= 10
                && fields[0] == "00000000000000000000000000000000"
                && fields[1] == "00"
                && u32::from_str_radix(fields[8], 16).is_ok_and(|flags| flags & 1 == 1)
                && let Ok(metric) = u32::from_str_radix(fields[5], 16)
            {
                routes.push((metric, fields[9].to_string()));
            }
        }
    }
    routes.sort();
    let interfaces = read_interfaces().ok()?;
    let available: HashSet<_> = interfaces
        .iter()
        .map(|interface| interface.info.name.as_str())
        .collect();
    if let Some((_, name)) = routes
        .into_iter()
        .find(|(_, name)| available.contains(name.as_str()))
    {
        return Some(name);
    }
    interfaces
        .iter()
        .find(|interface| !interface.info.is_virtual && interface.info.state == "up")
        .or_else(|| {
            interfaces
                .iter()
                .find(|interface| interface.info.state == "up")
        })
        .or_else(|| interfaces.iter().find(|interface| interface.loopback))
        .map(|interface| interface.info.name.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alias_labels_map_to_their_device() {
        assert_eq!(base_interface_name("eth0:1"), "eth0");
        assert_eq!(base_interface_name("eth0"), "eth0");
        let loopback = interface_index("lo").unwrap();
        let addresses = interface_addresses();
        let link = &addresses[&loopback];
        assert!(link.loopback);
        assert!(link.addresses.contains(&IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(interface_index("nwtop-test-interface-does-not-exist").is_none());
        assert!(
            local_interfaces(&mut TopologyCache::default())
                .iter()
                .any(|interface| interface.index == loopback && interface.loopback)
        );
    }
}
