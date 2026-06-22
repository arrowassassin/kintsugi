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

fn main() {
    dioxus::launch(App);
}

#[component]
fn App() -> Element {
    // Provide the shared store to the whole tree (context = `this`).
    use_context_provider(Store::new);
    let store = use_context::<Store>();

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

    let theme_vars = store.theme.read().root_vars();
    let unlocked = *store.unlocked.read();
    let panic = *store.panic.read();

    rsx! {
        document::Link { rel: "stylesheet", href: STYLES }

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
