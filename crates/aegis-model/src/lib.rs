//! Aegis Tier-2 model wrapper.
//!
//! In Phase 0/1 Aegis is deliberately rules-only: there is no model in the loop,
//! so the ambiguous band defaults to the safe side (Hold). The real CPU GGUF
//! model (summary + severity for the ambiguous band) arrives in Phase 2.
//!
//! Security spine: even once present, the model may only ADD caution. It can
//! never downgrade or unlock a rule-based block.

#![forbid(unsafe_code)]

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Whether a Tier-2 model is available in this build. Always `false` until Phase 2.
pub fn model_available() -> bool {
    false
}

#[cfg(test)]
mod tests {
    #[test]
    fn no_model_in_phase_0_1() {
        assert!(!super::model_available());
        assert!(!super::VERSION.is_empty());
    }
}
