//! Aegis ratatui terminal UI (Phase 4).
//!
//! Intentionally empty in Phase 0/1. The fully interactive timeline — live data
//! from the event log, keyboard navigation, hold-card approval, undo — is built
//! in Phase 4 per the requirements in `CLAUDE.md`.

#![forbid(unsafe_code)]

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    #[test]
    fn version_is_set() {
        assert!(!super::VERSION.is_empty());
    }
}
