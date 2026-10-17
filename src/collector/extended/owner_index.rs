//! Current descriptor holders by socket inode, used to veto or corroborate
//! socket event evidence.
use crate::collector::sockets::{Inventory, ProcessIdentity, Socket};
use std::collections::HashMap;

pub(super) const MAX_OWNER_INODES: usize = 32_768;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum InodeOwner {
    Single(ProcessIdentity),
    Ambiguous,
}

#[derive(Default)]
pub(super) struct OwnerIndex {
    pub(super) entries: HashMap<(u64, u64), InodeOwner>,
    positions: HashMap<(u64, u64), usize>,
    pub(super) limited: bool,
}

impl OwnerIndex {
    pub(super) fn refresh(&mut self, inventory: &Inventory) {
        self.entries.clear();
        self.positions.clear();
        self.limited = false;
        for (position, socket) in inventory
            .sockets
            .iter()
            .enumerate()
            .filter(|(_, socket)| socket.current)
        {
            let evidence = match socket.owners.as_slice() {
                [] => continue,
                [owner] => InodeOwner::Single(owner.identity),
                _ => InodeOwner::Ambiguous,
            };
            let key = (socket.key.namespace, socket.key.inode);
            if self.entries.len() >= MAX_OWNER_INODES && !self.entries.contains_key(&key) {
                // Never drop a contradictory holder just to keep the table
                // bounded. Suppress event-only certainty for this refresh.
                self.entries.clear();
                self.positions.clear();
                self.limited = true;
                break;
            }
            self.entries
                .entry(key)
                .and_modify(|known| {
                    if *known != evidence {
                        *known = InodeOwner::Ambiguous;
                    }
                })
                .or_insert(evidence);
            self.positions.insert(key, position);
        }
    }

    pub(super) fn vetoes(&self, socket: &Socket) -> bool {
        self.limited
            || self
                .entries
                .get(&(socket.key.namespace, socket.key.inode))
                .is_some_and(|evidence| match evidence {
                    InodeOwner::Ambiguous => true,
                    InodeOwner::Single(identity) => {
                        Some(*identity) != socket.owner().map(|owner| owner.identity)
                    }
                })
    }

    /// The sampled socket of the same inode as `observed`, if one was indexed.
    pub(super) fn current<'a>(
        &self,
        inventory: &'a Inventory,
        observed: &Socket,
    ) -> Option<&'a Socket> {
        self.positions
            .get(&(observed.key.namespace, observed.key.inode))
            .and_then(|position| inventory.sockets.get(*position))
    }

    /// Current descriptor evidence can corroborate an event-observed socket
    /// only for that exact still-open inode and full PID identity, never a
    /// reused inode, a different process or a vetoed owner.
    pub(super) fn corroborates(&self, current: &Socket, observed: &Socket) -> bool {
        current.current
            && current.key.namespace == observed.key.namespace
            && current.key.inode != 0
            && current.key.inode == observed.key.inode
            && current.owner().map(|owner| owner.identity)
                == observed.owner().map(|owner| owner.identity)
            && !self.vetoes(observed)
    }
}
