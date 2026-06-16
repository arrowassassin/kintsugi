//! Kintsugi interception adapters.
//!
//! Three sources, one normalized event. Each adapter turns an agent's proposed
//! command into a [`kintsugi_core::ProposedCommand`], sends it to the daemon, and
//! enforces the returned [`kintsugi_core::Verdict`].

#![forbid(unsafe_code)]

pub mod dialect;
pub mod holdcard;
pub mod hook;
pub mod mcp;
pub mod shim;

/// One trait, three impls (shim, hook, MCP). Each normalizes a source and runs.
pub trait Adapter {
    /// Stable name of the adapter, e.g. `"shim"`, `"claude-code"`, `"mcp"`.
    fn name(&self) -> &'static str;
    /// Run the adapter. Long-running for hook/MCP servers; one-shot for the shim.
    fn run(&self) -> anyhow::Result<()>;
}

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
