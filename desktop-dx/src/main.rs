//! Kintsugi Control Room — Dioxus DESKTOP app.
//!
//! Replaces the Tauri+WASM shell: the UI runs in the same process as the engine,
//! so screens call `kintsugi-app` directly (see `bindings`) — no IPC, no invoke,
//! no WASM. The design's inline-style + CSS-variable system carries over 1:1.

#![cfg_attr(all(not(debug_assertions), target_os = "windows"), windows_subsystem = "windows")]

use dioxus::prelude::*;

mod theme;
mod state;
mod data;
mod bindings;
mod components;

use state::{Store, Screen};
use components::{login::Login, shell::{TitleBar, Sidebar, TopBar}, screens};

pub const LOGO: Asset = asset!("/assets/logo-mark.svg");
pub const STYLES: Asset = asset!("/assets/styles.css");
/// The brand SVG inlined at compile time — bulletproof against asset-protocol
/// quirks in the embedded webview (the `asset!()`-served file was showing a
/// broken-image placeholder on some macOS builds).
pub const LOGO_SVG: &str = include_str!("../assets/logo-mark.svg");
/// The full stylesheet embedded as a string — the `asset!()` route silently
/// fails to serve styles.css on production macOS builds, so we inline it via a
/// `<style>` tag instead. Bulletproof and avoids a CSP/asset-protocol round-trip.
pub const STYLES_CSS: &str = include_str!("../assets/styles.css");

/// The 256-px window icon, rasterized from the brand SVG at build time.
const ICON_PNG: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/logo-256.png"));
/// All sizes baked into the binary, so the self-install registers full icon sets.
const ICON_PNG_16: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/logo-16.png"));
const ICON_PNG_32: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/logo-32.png"));
const ICON_PNG_64: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/logo-64.png"));
const ICON_PNG_128: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/logo-128.png"));
const ICON_PNG_512: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/logo-512.png"));

mod install;
mod tray;

fn main() {
    // Self-install flags so `cargo install kintsugi-control-room && kintsugi-control-room --install`
    // registers the OS-level desktop entry (mac .app, Linux .desktop). Same code
    // path as install.sh, but with the icons embedded in the binary.
    let mut args = std::env::args().skip(1);
    if let Some(arg) = args.next() {
        match arg.as_str() {
            "--install" => {
                if let Err(e) = install::install_app() {
                    eprintln!("install failed: {e}");
                    std::process::exit(1);
                }
                return;
            }
            "--uninstall" => {
                if let Err(e) = install::uninstall_app() {
                    eprintln!("uninstall failed: {e}");
                    std::process::exit(1);
                }
                return;
            }
            "--help" | "-h" => {
                println!(
                    "Kintsugi Control Room\n\n\
                     Usage:\n  \
                     kintsugi-control-room          launch the app\n  \
                     kintsugi-control-room --install     register as a desktop app (mac .app / Linux .desktop)\n  \
                     kintsugi-control-room --uninstall   reverse --install\n"
                );
                return;
            }
            _ => { /* fall through */ }
        }
    }

    use dioxus::desktop::{tao::window::Icon, Config, LogicalSize, WindowBuilder};

    // Decode the embedded PNG into RGBA for the OS-level window icon. If
    // anything goes wrong (e.g. on a build that somehow shipped without the
    // PNG), fall back to launching without an icon rather than crashing.
    let icon = (|| -> Option<Icon> {
        let decoder = png::Decoder::new(ICON_PNG);
        let mut reader = decoder.read_info().ok()?;
        let mut buf = vec![0; reader.output_buffer_size()];
        let info = reader.next_frame(&mut buf).ok()?;
        Icon::from_rgba(buf[..info.buffer_size()].to_vec(), info.width, info.height).ok()
    })();

    let mut window = WindowBuilder::new()
        .with_title("Kintsugi")
        .with_inner_size(LogicalSize::new(1280.0, 820.0))
        .with_min_inner_size(LogicalSize::new(960.0, 640.0));
    if let Some(ico) = icon {
        window = window.with_window_icon(Some(ico));
    }

    // Set the OS window background to our dark bg so the brief "blank" frame on
    // launch + the area outside our root <div> (e.g. between webview redraws)
    // doesn't flash white. Matches `--bg` in styles.css.
    let cfg = Config::default()
        .with_window(window)
        .with_background_color((11, 13, 18, 255));

    // The system tray is installed AFTER dioxus starts (see `App::use_effect`).
    // On macOS, NSStatusItem requires NSApplication to exist — touching the
    // Cocoa AppKit before `dioxus::launch` initializes it segfaults.
    dioxus::LaunchBuilder::desktop()
        .with_cfg(cfg)
        .launch(App);
}

#[component]
fn App() -> Element {
    // Provide the shared store to the whole tree (context = `this`).
    use_context_provider(Store::new);
    let mut store = use_context::<Store>();

    // Install the system tray AFTER dioxus has set up the AppKit/GTK event loop.
    // macOS needs NSApplication to exist before NSStatusItem is created (doing
    // it earlier segfaults). We leak the handle on purpose so the icon lives
    // for the whole session without us needing to thread a static through.
    use_effect(|| {
        if let Some(tray) = tray::install_tray() {
            Box::leak(Box::new(tray));
        }
    });

    // Bridge the system tray to the window: when a left-click on the tray (or
    // "Show Kintsugi" from the menu) flips the flag, set the window visible +
    // focused so the user finds the app where they expect it.
    let window = dioxus::desktop::use_window();
    use_future(move || {
        let window = window.clone();
        async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                if tray::SHOW_REQUESTED.swap(false, std::sync::atomic::Ordering::SeqCst) {
                    window.set_visible(true);
                    window.set_focus();
                }
            }
        }
    });

    // First-run setup wizard — show once on first launch (no marker file yet),
    // and only when the user is unlocked so the password card etc. are usable.
    use_effect(move || {
        if *store.unlocked.read() && store.wizard_step.peek().is_none() {
            if !crate::bindings::setup_done() {
                store.wizard_step.set(Some(crate::state::WizardStep::Welcome));
            }
        }
    });

    // Live-refresh heartbeats. Every screen's data reads one of these ticks, so
    // bumping them re-runs the reads. Fast (250ms) for light row lists + status;
    // slow (2s) for heavy aggregates — see Store::tick docs.
    let mut tick = store.tick;
    use_future(move || async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            let v = *tick.peek();
            tick.set(v.wrapping_add(1));
        }
    });
    let mut slow_tick = store.slow_tick;
    use_future(move || async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(2000)).await;
            let v = *slow_tick.peek();
            slow_tick.set(v.wrapping_add(1));
        }
    });

    // Persist the look whenever it changes — reads both signals so a theme swap
    // OR a menu-bar toggle re-runs it, writing the prefs file the next launch
    // restores from. Best-effort; the write never blocks the UI.
    use_effect(move || {
        let theme = *store.theme.read();
        let nav_open = *store.nav_open.read();
        crate::bindings::save_ui_prefs(theme, nav_open);
    });

    let theme_vars = store.theme.read().root_vars();
    let unlocked = *store.unlocked.read();
    let panic = *store.panic.read();

    rsx! {
        // Inline stylesheet — asset!()-served CSS silently doesn't load in the
        // production macOS build, so the `body { overflow:hidden }` and the
        // keyframes (kpulse, kfade, kspin) never applied → the phantom right
        // scrollbar. Embedding it as a <style> tag fixes both.
        style { dangerous_inner_html: "{STYLES_CSS}" }

        div {
            style: "height:100vh;width:100%;display:flex;flex-direction:column;color:var(--ink);background:var(--bg);overflow:hidden;font-family:'IBM Plex Sans',ui-sans-serif,system-ui,sans-serif;{theme_vars}",

            if !unlocked {
                Login {}
            } else {
                TitleBar {}

                if panic { PanicBanner {} }

                div { style: "flex:1;display:flex;min-height:0",
                    Sidebar {}
                    main { style: "flex:1;min-width:0;display:flex;flex-direction:column;background:var(--bg)",
                        TopBar {}
                        div { style: "flex:1;overflow-y:auto;min-height:0",
                            ScreenRouter {}
                        }
                    }
                }
                // Per-activity detail drawer — overlays everything when a row is clicked.
                screens::DetailDrawer {}
                // Always-available "everything Kintsugi can do" reference panel.
                screens::HelpDrawer {}
                // First-run setup wizard — shown once until the marker file is written.
                screens::SetupWizard {}
                // Transient toast notifications stack (bottom-right).
                screens::Toasts {}
            }
        }
    }
}

#[component]
fn ScreenRouter() -> Element {
    let store = use_context::<Store>();
    // Copy the screen out so the signal borrow is released before the rsx! arms
    // (which build temporaries) — otherwise the Ref lives to end-of-block.
    let screen = *store.screen.read();
    match screen {
        Screen::Dashboard => rsx! { screens::Dashboard {} },
        Screen::Feed => rsx! { screens::Feed {} },
        Screen::Held => rsx! { screens::Held {} },
        Screen::Audit => rsx! { screens::Audit {} },
        Screen::Provenance => rsx! { screens::Provenance {} },
        Screen::Recorder => rsx! { screens::Recorder {} },
        Screen::Snapshots => rsx! { screens::Snapshots {} },
        Screen::Policy => rsx! { screens::Policy {} },
        Screen::Settings => rsx! { screens::Settings {} },
        // The V2 plans remain patterned for now.
        _ => rsx! { screens::Placeholder {} },
    }
}

#[component]
fn PanicBanner() -> Element {
    let mut store = use_context::<Store>();
    rsx! {
        div { style: "flex:none;display:flex;align-items:center;gap:14px;padding:11px 20px;background:linear-gradient(90deg,rgba(255,93,93,.18),rgba(255,93,93,.05));border-bottom:1px solid rgba(255,93,93,.4)",
            span { style: "display:inline-flex;width:9px;height:9px;border-radius:50%;background:var(--red);animation:kpulse 1.1s infinite" }
            span { style: "font-size:13.5px;font-weight:600;color:var(--red)", "Panic engaged — all agent actions halted and queued." }
            span { style: "font-size:13px;color:var(--dim)", "Nothing runs until you resume." }
            button { class: "kn-btn-ghost", style: "margin-left:auto;font-family:inherit;font-size:12.5px;font-weight:600;color:var(--ink);background:var(--panel);border:1px solid var(--line);border-radius:7px;padding:7px 14px;cursor:pointer",
                onclick: move |_| { let _ = bindings::set_panic(false); store.panic.set(false); },
                "Resume guarding"
            }
        }
    }
}
