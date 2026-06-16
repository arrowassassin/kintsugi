//! Decision-memory helpers.
//!
//! The mutable store itself lives on [`crate::EventLog`] (same SQLite file);
//! this module holds the small pure pieces: how a command is hashed into a
//! stable key for the per-repo always-allow / always-deny memory.

use sha2::{Digest, Sha256};

/// Stable hash of a raw command line, used as the memory key within a repo.
///
/// The exact command text is hashed (not the argv), so "always allow this exact
/// command in this repo" means exactly that — a different command, even by a
/// space, is a different key.
pub fn command_hash(raw: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(raw.trim().as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::command_hash;

    #[test]
    fn stable_and_trim_insensitive() {
        assert_eq!(command_hash("rm -rf x"), command_hash("  rm -rf x  "));
    }

    #[test]
    fn distinguishes_different_commands() {
        assert_ne!(command_hash("rm -rf x"), command_hash("rm -rf y"));
        assert_eq!(command_hash("ls").len(), 64);
    }
}
