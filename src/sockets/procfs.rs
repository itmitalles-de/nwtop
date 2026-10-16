//! Bounded procfs reads, namespace addresses, socket tables and inode owners.

use super::{
    MAX_FD_LINKS, MAX_NAMESPACES, MAX_PROC_FILE, MAX_PROCESSES, Namespace, Owner, ProcessIdentity,
    Protocol, Socket, SocketKey, canonical_ip,
};
use std::{
    collections::{HashMap, HashSet},
    fs,
    io::Read,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    os::unix::fs::MetadataExt,
    path::Path,
    time::Instant,
};

pub(super) fn namespace_id(pid: u32) -> std::io::Result<u64> {
    fs::metadata(format!("/proc/{pid}/ns/net")).map(|metadata| metadata.ino())
}

pub(super) fn discover_namespaces(host: u64) -> (HashMap<u64, Namespace>, bool, bool) {
    let mut namespaces = HashMap::from([(
        host,
        Namespace {
            id: host,
            representative_pid: std::process::id(),
            addresses: HashSet::new(),
        },
    )]);
    let mut restricted = host == 0;
    let mut limited = false;
    let Ok(entries) = fs::read_dir("/proc") else {
        return (namespaces, true, false);
    };
    let mut pids = Vec::new();
    for entry in entries {
        let Ok(entry) = entry else {
            restricted = true;
            continue;
        };
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        if pids.len() == MAX_PROCESSES {
            limited = true;
            break;
        }
        pids.push(pid);
    }
    // Prefer older representatives, usually the container's init process.
    pids.sort_unstable();
    for pid in pids {
        match namespace_id(pid) {
            Ok(id) if namespaces.contains_key(&id) => {}
            Ok(id) => {
                if namespaces.len() == MAX_NAMESPACES {
                    limited = true;
                    break;
                }
                namespaces.insert(
                    id,
                    Namespace {
                        id,
                        representative_pid: pid,
                        addresses: HashSet::new(),
                    },
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => restricted = true,
        }
    }
    (namespaces, restricted, limited)
}

/// Kernel tables can grow with unrelated system activity. Bound both each
/// allocation and aggregate bytes per refresh, rejecting incomplete files.
pub(super) fn read_proc_bounded(
    path: &Path,
    budget: &mut usize,
    restricted: &mut bool,
    limited: &mut bool,
) -> Option<String> {
    if *budget == 0 {
        *limited = true;
        return None;
    }
    let file = match fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
        Err(_) => {
            *restricted = true;
            return None;
        }
    };
    let bound = MAX_PROC_FILE.min(*budget);
    let mut contents = Vec::new();
    if file
        .take((bound + 1) as u64)
        .read_to_end(&mut contents)
        .is_err()
    {
        *budget = budget.saturating_sub(contents.len());
        *restricted = true;
        return None;
    }
    *budget = budget.saturating_sub(contents.len());
    if contents.len() > bound {
        *limited = true;
        return None;
    }
    match String::from_utf8(contents) {
        Ok(contents) => Some(contents),
        Err(_) => {
            *restricted = true;
            None
        }
    }
}

pub(super) fn read_namespace_addresses(
    root: &Path,
    budget: &mut usize,
    restricted: &mut bool,
    limited: &mut bool,
) -> HashSet<IpAddr> {
    let ipv4 = read_proc_bounded(&root.join("fib_trie"), budget, restricted, limited);
    let ipv6 = read_proc_bounded(&root.join("if_inet6"), budget, restricted, limited);
    namespace_addresses(ipv4.as_deref().unwrap_or(""), ipv6.as_deref().unwrap_or(""))
}

pub(super) fn namespace_addresses(ipv4: &str, ipv6: &str) -> HashSet<IpAddr> {
    let mut addresses = HashSet::new();
    let mut leaf = None;
    for line in ipv4.lines() {
        let line = line.trim();
        if let Some(address) = line.strip_prefix("|-- ") {
            leaf = address.parse::<Ipv4Addr>().ok();
        } else if line.split_ascii_whitespace().eq(["/32", "host", "LOCAL"]) {
            if let Some(ip) = leaf.take() {
                addresses.insert(IpAddr::V4(ip));
            }
        } else {
            leaf = None;
        }
    }
    for line in ipv6.lines() {
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        if fields.len() != 6 || fields[0].len() != 32 {
            continue;
        }
        let (Ok(address), Ok(flags)) = (
            u128::from_str_radix(fields[0], 16),
            u32::from_str_radix(fields[4], 16),
        ) else {
            continue;
        };
        // DAD failure or a tentative address is not ready to receive traffic.
        if flags & (0x08 | 0x40) == 0 {
            addresses.insert(canonical_ip(IpAddr::V6(Ipv6Addr::from(address))));
        }
    }
    addresses.retain(|address| !address.is_unspecified() && !address.is_multicast());
    addresses
}

pub(super) fn parse_address(value: &str, ipv6: bool) -> Option<SocketAddr> {
    let (hex_ip, hex_port) = value.rsplit_once(':')?;
    let port = u16::from_str_radix(hex_port, 16).ok()?;
    let ip = if ipv6 {
        if hex_ip.len() != 32 {
            return None;
        }
        let mut bytes = [0; 16];
        for (index, chunk) in hex_ip.as_bytes().as_chunks::<8>().0.iter().enumerate() {
            let word = u32::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
            bytes[index * 4..index * 4 + 4].copy_from_slice(&word.to_ne_bytes());
        }
        canonical_ip(IpAddr::V6(Ipv6Addr::from(bytes)))
    } else {
        let word = u32::from_str_radix(hex_ip, 16).ok()?;
        IpAddr::V4(Ipv4Addr::from(word.to_ne_bytes()))
    };
    Some(SocketAddr::new(ip, port))
}

pub(super) fn parse_socket(
    line: &str,
    protocol: Protocol,
    ipv6: bool,
    now: Instant,
    namespace: u64,
) -> Option<Socket> {
    let fields: Vec<_> = line.split_ascii_whitespace().collect();
    let state = u8::from_str_radix(fields.get(3)?, 16).ok()?;
    Some(Socket {
        key: SocketKey {
            namespace,
            inode: fields.get(9)?.parse().ok()?,
            protocol,
            local: parse_address(fields.get(1)?, ipv6)?,
            remote: parse_address(fields.get(2)?, ipv6)?,
        },
        uid: fields.get(7)?.parse().ok()?,
        state: state_label(state, protocol).to_string(),
        owners: Vec::new(),
        observed: now,
        current: true,
        ipv6_only: None,
    })
}

pub(super) fn state_label(state: u8, protocol: Protocol) -> &'static str {
    if protocol == Protocol::Udp {
        return if state == 1 { "CONNECTED" } else { "BOUND" };
    }
    match state {
        1 => "ESTABLISHED",
        2 => "SYN-SENT",
        3 => "SYN-RECV",
        4 => "FIN-WAIT-1",
        5 => "FIN-WAIT-2",
        6 => "TIME-WAIT",
        7 => "CLOSE",
        8 => "CLOSE-WAIT",
        9 => "LAST-ACK",
        10 => "LISTEN",
        11 => "CLOSING",
        12 => "NEW-SYN-RECV",
        _ => "UNKNOWN",
    }
}

pub(super) fn start_time(stat: &str) -> Option<u64> {
    // comm is parenthesized and may contain spaces or parentheses.
    let (_, fields) = stat.rsplit_once(')')?;
    fields.split_ascii_whitespace().nth(19)?.parse().ok()
}

pub(super) fn sanitize_label(label: &str) -> String {
    label
        .chars()
        .take(128)
        .map(|character| {
            if character.is_control() {
                '?'
            } else {
                character
            }
        })
        .collect()
}

pub(super) fn scan_owners(
    inodes: &HashSet<u64>,
    users: &HashMap<u32, String>,
) -> (HashMap<u64, Vec<Owner>>, bool, bool) {
    let mut owners: HashMap<u64, Vec<Owner>> = HashMap::new();
    let mut restricted = false;
    let mut limited = false;
    let mut fd_links = 0;
    let Ok(processes) = fs::read_dir("/proc") else {
        return (owners, true, false);
    };
    for (process_count, entry) in processes
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().parse::<u32>().is_ok())
        .enumerate()
    {
        if process_count >= MAX_PROCESSES || fd_links >= MAX_FD_LINKS {
            limited = true;
            break;
        }
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let path = entry.path();
        let Ok(before_stat) = fs::read_to_string(path.join("stat")) else {
            continue;
        };
        let Some(before_start) = start_time(&before_stat) else {
            continue;
        };
        let descriptors = match fs::read_dir(path.join("fd")) {
            Ok(descriptors) => descriptors,
            Err(error) => {
                restricted |= error.kind() == std::io::ErrorKind::PermissionDenied;
                continue;
            }
        };
        let mut matched = HashSet::new();
        for descriptor in descriptors.filter_map(Result::ok) {
            fd_links += 1;
            if fd_links >= MAX_FD_LINKS {
                limited = true;
                break;
            }
            let target = match fs::read_link(descriptor.path()) {
                Ok(target) => target,
                Err(error) => {
                    // Directory listing and ptrace-gated symlink access are
                    // separate permissions, notably for nondumpable processes.
                    restricted |= error.kind() == std::io::ErrorKind::PermissionDenied;
                    continue;
                }
            };
            let text = target.to_string_lossy();
            let Some(inode) = text
                .strip_prefix("socket:[")
                .and_then(|s| s.strip_suffix(']'))
                .and_then(|s| s.parse::<u64>().ok())
            else {
                continue;
            };
            if inodes.contains(&inode) {
                matched.insert(inode);
            }
        }
        if matched.is_empty() {
            continue;
        }
        let Ok(after_stat) = fs::read_to_string(path.join("stat")) else {
            continue;
        };
        if start_time(&after_stat) != Some(before_start) {
            continue;
        }
        let uid = fs::metadata(&path)
            .map(|metadata| metadata.uid())
            .unwrap_or(u32::MAX);
        let raw_name =
            fs::read_to_string(path.join("comm")).unwrap_or_else(|_| "unknown".to_string());
        let name = sanitize_label(raw_name.strip_suffix('\n').unwrap_or(&raw_name));
        let owner = Owner {
            identity: ProcessIdentity {
                pid,
                start_time: before_start,
            },
            user: users.get(&uid).cloned().unwrap_or_else(|| uid.to_string()),
            name,
        };
        for inode in matched {
            let entries = owners.entry(inode).or_default();
            // Forked/shared descriptors deliberately preserve all owners.
            if entries.len() < 32 {
                entries.push(owner.clone());
            } else {
                limited = true;
            }
        }
    }
    (owners, restricted, limited)
}
