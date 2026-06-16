//! `kintsugi-mcp`: the `kintsugi-exec` MCP server (JSON-RPC over stdio).
//!
//! Point a tool-calling agent (Qwen, Codex, custom) at this binary as an MCP
//! server. It exposes one tool, `kintsugi-exec`, which runs a shell command guarded
//! and recorded by Kintsugi. See `kintsugi init` for per-agent wiring.

fn main() -> anyhow::Result<()> {
    kintsugi_intercept::mcp::run()
}
