# Kintsugi Control Room (desktop app)

A local-first **dashboard** for Kintsugi (Tauri + Dioxus, all-Rust, no npm). It is
not a gate — the daemon already decides; this app reads what the daemon and the
append-only event log know and shows it: the command timeline, session taint, the
deterministic provenance trail, and the approval queue.

## Layout

Canonical Tauri layout — the Dioxus frontend is the project root, the Tauri host
nested under `src-tauri/`:

```
desktop/
  Cargo.toml        # Dioxus (WASM) frontend crate — its own [workspace]
  index.html        # Trunk entry
  app.css
  src/              # main.rs (components) + invoke.rs (Tauri invoke binding)
  dist/             # Trunk build output (Tauri serves this for `build`)
  src-tauri/        # Tauri host — #[tauri::command]s over the engine
    Cargo.toml
    tauri.conf.json
    src/main.rs
```

```
 frontend (Dioxus/WASM) ──invoke()──▶ Tauri host ──calls──▶ kintsugi-app (engine, native)
 renders kintsugi-app-types          #[tauri::command]s      reads EventLog + daemon over IPC
        ▲ JSON (shared types) ────────────────┘                      │ IPC / read
                                                                     ▼
                                                          kintsugi daemon + event log (SQLite)
```

The view-models live in **`kintsugi-app-types`**, a wasm-safe crate both sides
depend on — so every `invoke` payload is one compiler-checked Rust contract, no
hand-kept TypeScript. The engine (`kintsugi-app`) and the types crate are part of
the main workspace and are unit-tested; this `desktop/` tree is **detached** from
that workspace (its own `[workspace]` tables) because it pulls in the platform
webview and the wasm target, which CI and headless builds don't carry.

## Build (on a workstation with the platform webview)

```bash
cargo install trunk            # wasm frontend bundler (once)
cargo install tauri-cli        # `cargo tauri` (once)
rustup target add wasm32-unknown-unknown

# Run from the desktop/ root (NOT desktop/src-tauri) — Tauri runs `trunk serve`
# from here, where index.html lives.
cd desktop
cargo tauri dev                # Trunk serves the frontend; Tauri opens the window
cargo tauri build              # production bundle
```

macOS uses WKWebView (built in) — no extra packages. Linux needs the webkit2gtk
dev packages (e.g. `libwebkit2gtk-4.1-dev`); Windows uses WebView2.

## Design

Carries the codebase's TUI design rules into the GUI (`kintsugi-app-design-brief.md`):
calm until it must shout — one gold seam accent, the single danger accent reserved
for a lethal-trifecta block; every state pairs a glyph/word with color (never color
alone); mono for every command, path, and source id; designed empty states. The
provenance-trail panel is the hero — the gold seam threads the steps from the
untrusted read down to the rule that fired.
