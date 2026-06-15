//! `aegis-mcp`: the `aegis-exec` MCP server (JSON-RPC over stdio).
//!
//! Point a tool-calling agent (Qwen, Codex, custom) at this binary as an MCP
//! server. It exposes one tool, `aegis-exec`, which runs a shell command guarded
//! and recorded by Aegis. See `aegis init` for per-agent wiring.

fn main() -> anyhow::Result<()> {
    aegis_intercept::mcp::run()
}
