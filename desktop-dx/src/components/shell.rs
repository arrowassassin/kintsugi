//! App shell: OS-neutral title bar, collapsible icon sidebar, topbar.

use dioxus::prelude::*;
use crate::state::{use_store, Screen};

/// (screen, label, badge, svg-path-d)
type Nav = (Screen, &'static str, Option<String>, &'static str);

fn groups(held_count: usize) -> Vec<(&'static str, Vec<Nav>)> {
    let held_badge = if held_count > 0 { Some(held_count.to_string()) } else { None };
    vec![
        ("EVERYDAY", vec![
            (Screen::Dashboard, "Home", None, "M3 3h7v7H3z M14 3h7v7h-7z M14 14h7v7h-7z M3 14h7v7H3z"),
            (Screen::Held, "Needs review", held_badge, "M12 3l7 3v5c0 4-3 7-7 9-4-2-7-5-7-9V6z M12 8.5v4 M12 15.4v.5"),
            (Screen::Feed, "Activity", None, "M3 12h3.4l2-6 3.2 12 2.3-7 2 1h3.1"),
            (Screen::Provenance, "Where it came from", None, "M6 13a2.2 2.2 0 1 0 0-4.4 2.2 2.2 0 0 0 0 4.4z M18 7.2a2.2 2.2 0 1 0 0-4.4 2.2 2.2 0 0 0 0 4.4z M18 21.2a2.2 2.2 0 1 0 0-4.4 2.2 2.2 0 0 0 0 4.4z M8 10l8-4 M8 13l8 4.4"),
            (Screen::Recorder, "Recorder", None, "M4 5h16v14H4z M7.5 9.5l2.5 2.5-2.5 2.5 M13 15h3.5"),
        ]),
        ("RECORDS", vec![
            (Screen::Audit, "History", None, "M6 3h9l4 4v14H6z M9 13l2 2 4-4"),
            (Screen::Policy, "Rules", None, "M4 7h16 M4 17h16 M9 5v4 M15 15v4"),
            (Screen::Snapshots, "Undo", None, "M4 12a8 8 0 1 1 2.4 5.7 M4 18v-4h4 M12 8.5v4l3 1.8"),
        ]),
        ("SETUP", vec![
            (Screen::Settings, "Settings", None, "M12 8.5a3.5 3.5 0 1 0 0 7 3.5 3.5 0 0 0 0-7z M12 2.5v2 M12 19.5v2 M3.5 12h2 M18.5 12h2 M5.6 5.6l1.5 1.5 M16.9 16.9l1.5 1.5 M18.4 5.6l-1.5 1.5 M7.1 16.9l-1.5 1.5"),
        ]),
    ]
}

fn v2_navs() -> Vec<Nav> {
    vec![
        (Screen::Verified, "Verified gate", None, "M9 12l2 2 4-4 M12 3l7 3v5c0 4-3 7-7 9-4-2-7-5-7-9V6z"),
        (Screen::Capability, "Capability scopes", None, "M15 7a4 4 0 1 0-3.9 5l5.9 5.9 2-2-1-1 1-1-1-1 1.5-1.5"),
        (Screen::Fleet, "Team fleet", None, "M9 11a3 3 0 1 0 0-6 3 3 0 0 0 0 6z M2 20a7 7 0 0 1 14 0 M17 7a3 3 0 0 1 0 6 M16 20a7 7 0 0 0-2-4.5"),
    ]
}

#[component]
fn NavItem(item: Nav, v2: bool) -> Element {
    let mut store = use_store();
    let (screen, label, badge, d) = item;
    let active = *store.screen.read() == screen;
    let open = *store.nav_open.read();

    let base = if active {
        "background:var(--panel);color:var(--gold);box-shadow:inset 2px 0 0 var(--gold);"
    } else {
        "background:transparent;color:var(--dim);box-shadow:inset 2px 0 0 transparent;"
    };
    let justify = if open { "" } else { "justify-content:center;padding-left:0;padding-right:0;" };
    let label_hide = if open { "" } else { "display:none;" };

    rsx! {
        button {
            class: "kn-navitem",
            title: "{label}",
            style: "display:flex;align-items:center;gap:11px;width:100%;text-align:left;font-family:inherit;font-size:13.5px;font-weight:500;border:none;border-radius:8px;padding:9px 11px;cursor:pointer;{base}{justify}",
            onclick: move |_| store.screen.set(screen),
            svg { view_box: "0 0 24 24", width: "17", height: "17", fill: "none", stroke: "currentColor",
                stroke_width: "1.6", stroke_linecap: "round", stroke_linejoin: "round", style: "flex:none",
                path { d: "{d}" }
            }
            span { style: "flex:1;{label_hide}", "{label}" }
            if let Some(b) = badge {
                span { style: "font-size:10.5px;font-weight:700;color:#1a1206;background:var(--amber);border-radius:20px;min-width:18px;height:18px;display:inline-flex;align-items:center;justify-content:center;padding:0 5px;{label_hide}", "{b}" }
            }
            if v2 {
                span { style: "font-size:9px;font-weight:700;letter-spacing:.5px;border:1px solid var(--gold-line);color:var(--gold);border-radius:5px;padding:2px 5px;{label_hide}", "V2" }
            }
        }
    }
}

#[component]
pub fn Sidebar() -> Element {
    let store = use_store();
    let open = *store.nav_open.read();

    // The "Needs review" badge count, from the REAL pending queue (the old
    // `held_resolved` signal was never written, so the badge was always on).
    let held_res = use_resource(move || async move {
        let _ = store.tick.read();
        tokio::task::spawn_blocking(crate::bindings::queue).await.unwrap_or_default()
    });
    let held_count = held_res().map(|q| q.len()).unwrap_or(0);

    // Live engine status, on the same 250ms tick as the topbar so the two never
    // disagree. Reads run off the UI thread. Was hardcoded "Protected" before —
    // that's the desync the user saw.
    let status = use_resource(move || async move {
        let _ = store.tick.read();
        let up = tokio::task::spawn_blocking(crate::bindings::engine_running).await.unwrap_or(false);
        let paused = tokio::task::spawn_blocking(crate::bindings::panic_engaged).await.unwrap_or(false);
        (up, paused)
    });
    let (up, paused) = (*status.read()).unwrap_or((false, false));
    let (dot, glow, st_title, st_sub) = if paused {
        ("var(--amber)", "rgba(245,179,90,.16)", "Paused", "Agents halted — engine on")
    } else if up {
        ("var(--green)", "rgba(90,247,142,.14)", "Protected", "Running in the background")
    } else {
        ("var(--dim)", "rgba(130,130,130,.10)", "Stopped", "Protection is off")
    };
    let width = if open { "width:248px;min-width:248px;max-width:248px" } else { "width:64px;min-width:64px;max-width:64px" };
    let label_hide = if open { "" } else { "display:none;" };
    let center = if open { "" } else { "justify-content:center;" };

    rsx! {
        aside { style: "flex:none;display:flex;flex-direction:column;background:var(--bg2);border-right:1px solid var(--line);padding:14px 12px;overflow:hidden;transition:width .18s ease;{width}",
            nav { class: "kn-nav", style: "flex:1;overflow-y:auto;overflow-x:hidden;display:flex;flex-direction:column;gap:3px",
                for (name, items) in groups(held_count) {
                    div { style: "font-size:10px;font-weight:600;letter-spacing:1.4px;color:var(--dim);opacity:.7;padding:14px 10px 5px;{label_hide}", "{name}" }
                    for it in items { NavItem { item: it, v2: false } }
                }
                div { style: "font-size:10px;font-weight:600;letter-spacing:1.4px;color:var(--dim);opacity:.7;padding:16px 10px 5px;{label_hide}", "PLANNED · V2" }
                for it in v2_navs() { NavItem { item: it, v2: true } }
            }
            div { style: "margin-top:12px;padding-top:12px;border-top:1px solid var(--line);display:flex;align-items:center;gap:9px;{center}",
                span { style: "display:inline-flex;width:9px;height:9px;border-radius:50%;background:{dot};box-shadow:0 0 0 3px {glow};animation:kpulse 2.4s infinite;flex:none" }
                div { style: "line-height:1.3;{label_hide}",
                    div { style: "font-size:12.5px;font-weight:600", "{st_title}" }
                    div { style: "font-size:11px;color:var(--dim)", "{st_sub}" }
                }
            }
        }
    }
}

#[component]
pub fn TitleBar() -> Element {
    let mut store = use_store();
    let (title, _) = store.screen.read().meta();
    rsx! {
        div { style: "height:40px;flex:none;display:flex;align-items:center;gap:10px;padding:0 14px;background:var(--bg2);border-bottom:1px solid var(--line);user-select:none",
            button { class: "kn-iconbtn", title: "Toggle menu",
                style: "display:inline-flex;align-items:center;justify-content:center;width:26px;height:26px;margin-left:-4px;border:none;border-radius:7px;background:transparent;color:var(--dim);cursor:pointer;flex:none",
                onclick: move |_| { let v = *store.nav_open.read(); store.nav_open.set(!v); },
                svg { view_box: "0 0 24 24", width: "16", height: "16", fill: "none", stroke: "currentColor", stroke_width: "2", stroke_linecap: "round",
                    path { d: "M4 6h16M4 12h16M4 18h16" }
                }
            }
            img { src: crate::LOGO, width: "18", height: "18", alt: "Kintsugi", style: "display:block" }
            span { style: "font-size:12.5px;font-weight:600;letter-spacing:.2px", "Kintsugi" }
            span { style: "font-size:12.5px;color:var(--dim)", "— {title}" }
        }
    }
}

#[component]
pub fn TopBar() -> Element {
    let mut store = use_store();
    let (title, sub) = store.screen.read().meta();
    let panic = *store.panic.read();
    let panic_label = if panic { "Resume" } else { "Panic" };

    // Live engine status, polled in-process (direct call — no IPC). The same loop
    // syncs panic from the kill-switch flag so the banner reflects reality.
    let mut engine_up = use_signal(crate::bindings::engine_running);
    let mut engine_err = use_signal(|| None::<String>);
    use_future(move || async move {
        loop {
            engine_up.set(crate::bindings::engine_running());
            let real_panic = crate::bindings::panic_engaged();
            if *store.panic.peek() != real_panic {
                store.panic.set(real_panic);
            }
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }
    });
    let up = *engine_up.read();
    let (dot, chip_label) = if up { ("var(--green)", "Protected") } else { ("var(--dim)", "Stopped") };
    let toggle_label = if up { "Stop" } else { "Start" };
    let toggle_color = if up { "var(--red)" } else { "var(--green)" };

    rsx! {
        header { style: "flex:none;height:64px;display:flex;align-items:center;gap:16px;padding:0 26px;border-bottom:1px solid var(--line);background:var(--bg)",
            div { style: "min-width:0",
                h1 { style: "margin:0;font-size:17px;font-weight:700;letter-spacing:-.1px;white-space:nowrap", "{title}" }
                div { style: "font-size:12px;color:var(--dim);white-space:nowrap;overflow:hidden;text-overflow:ellipsis", "{sub}" }
            }
            div { style: "margin-left:auto;display:flex;align-items:center;gap:10px",
                div { style: "display:flex;align-items:center;gap:7px;height:34px;border:1px solid var(--line);border-radius:8px;padding:0 12px;background:var(--panel);white-space:nowrap;flex:none",
                    span { style: "display:inline-flex;width:7px;height:7px;border-radius:50%;background:{dot}" }
                    span { style: "font-size:12px;font-weight:600", "{chip_label}" }
                }
                // On / Off — start or stop the resident daemon (the single power toggle).
                button { class: "kn-btn-ghost",
                    title: if up { "Stop — turn Kintsugi off. The daemon exits and nothing is guarded until you Start again." } else { "Start — bring Kintsugi's protection online." },
                    style: "font-family:inherit;font-size:12.5px;font-weight:600;color:{toggle_color};background:transparent;border:1px solid var(--line);border-radius:8px;height:34px;padding:0 14px;cursor:pointer",
                    onclick: move |_| {
                        let res = if *engine_up.peek() {
                            // Authenticate the shutdown with the password proven at
                            // login — no second prompt. Falls back to the no-vault
                            // path if nothing was held (e.g. unprovisioned).
                            match store.session_pw.peek().clone() {
                                Some(pw) => crate::bindings::stop_engine_with_password(&pw),
                                None => crate::bindings::stop_engine(),
                            }
                        } else {
                            crate::bindings::start_engine()
                        };
                        match res {
                            Ok(()) => engine_err.set(None),
                            Err(e) => engine_err.set(Some(e.to_string())),
                        }
                        engine_up.set(crate::bindings::engine_running());
                    },
                    "{toggle_label}"
                }
                if let Some(err) = engine_err.read().clone() {
                    span {
                        title: "{err}",
                        style: "font-size:11.5px;color:var(--red);max-width:240px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;flex:none",
                        "{err}"
                    }
                }
                button { class: "kn-iconbtn", title: "Lock",
                    style: "display:inline-flex;align-items:center;justify-content:center;width:34px;height:34px;border:1px solid var(--line);border-radius:8px;background:var(--panel);color:var(--dim);cursor:pointer;flex:none",
                    onclick: move |_| store.lock(),
                    svg { view_box: "0 0 24 24", width: "15", height: "15", fill: "none", stroke: "currentColor", stroke_width: "1.7", stroke_linecap: "round", stroke_linejoin: "round",
                        rect { x: "4", y: "11", width: "16", height: "9", rx: "2" }
                        path { d: "M8 11V8a4 4 0 0 1 8 0v3" }
                    }
                }
                button {
                    title: if panic { "Resume — let agents run again. (The engine stayed on the whole time; actions were just paused.)" } else { "Panic — instantly halt ALL agent actions and queue them. The engine STAYS ON; nothing runs until you Resume. Different from Stop, which powers Kintsugi off." },
                    style: "font-family:inherit;font-size:12.5px;font-weight:600;color:var(--red);background:transparent;border:1px solid rgba(255,93,93,.35);border-radius:8px;height:34px;padding:0 14px;cursor:pointer",
                    onclick: move |_| { let v = *store.panic.peek(); let _ = crate::bindings::set_panic(!v); store.panic.set(!v); },
                    "{panic_label}"
                }
            }
        }
    }
}
