//! Prolly tree diff for efficient sync

use cid::Cid;

/// A delta in a diff operation
#[derive(Debug, Clone)]
pub enum Delta {
    Add { key: Vec<u8>, cid: Cid },
    Remove { key: Vec<u8>, cid: Cid },
    Modify { key: Vec<u8>, old_cid: Cid, new_cid: Cid },
}

impl Delta {
    pub fn key(&self) -> &[u8] {
        match self {
            Delta::Add { key, .. } => key,
            Delta::Remove { key, .. } => key,
            Delta::Modify { key, .. } => key,
        }
    }
}
