//! Screens — wired to the REAL backend via `crate::bindings` (reads off the UI
//! thread via spawn_blocking; fs-watch kept out of the main feed).
use crate::data;
use crate::state::{use_store, Screen, FEED_PAGE_SIZE};
use crate::theme::{decision, Theme};
use dioxus::prelude::*;

const FADE: &str = "animation:kfade .3s ease;";

/// Parse an rfc3339 (UTC) timestamp into (local date, local time) in the user's
/// timezone. Falls back to a raw string split if it doesn't parse.
fn local_datetime(ts: &str) -> (String, String) {
    use chrono::{DateTime, Local};
    if let Ok(dt) = DateTime::parse_from_rfc3339(ts) {
        let l = dt.with_timezone(&Local);
        return (
            l.format("%Y-%m-%d").to_string(),
            l.format("%H:%M:%S").to_string(),
        );
    }
    match ts.split_once('T') {
        Some((date, rest)) => (date.to_string(), rest.get(..8).unwrap_or(rest).to_string()),
        None => (ts.to_string(), String::new()),
    }
}

/// Local date + time on one line — a bare clock is ambiguous across days.
fn short_time(ts: &str) -> String {
    let (date, time) = local_datetime(ts);
    if time.is_empty() {
        date
    } else {
        format!("{date} {time}")
    }
}
fn clock(ts: &str) -> String {
    short_time(ts)
}
/// Map a TimelineRow outcome to the key decision() understands.
fn outcome_key(o: &str) -> &'static str {
    match o {
        "allowed" => "allowed",
        "held" => "held",
        "denied" => "blocked",
        _ => "blocked",
    }
}
fn outcome_decision(o: &str) -> &'static str {
    outcome_key(o)
}

/// A timestamp table cell: time on top (prominent), date dimmed below. Keeps the
/// full date+time readable in a narrow column without the ugly mid-string wrap.
#[component]
fn TimeCell(ts: String) -> Element {
    let (date, time) = local_datetime(&ts);
    rsx! {
        span { style: "display:inline-flex;flex-direction:column;line-height:1.25;font-family:'IBM Plex Mono',monospace;white-space:nowrap",
            span { style: "font-size:11.5px;color:var(--ink)", "{time}" }
            span { style: "font-size:9.5px;color:var(--dim)", "{date}" }
        }
    }
}

/// The brand mark — renders the SVG inline via `dangerous_inner_html` so it
/// never depends on the asset protocol. The source SVG hardcodes
/// `width="64" height="64"`, so we strip those once on first call and serve a
/// version that scales with the wrapper. `size` controls the square box.
fn logo_svg_scalable() -> &'static str {
    use std::sync::OnceLock;
    static CLEANED: OnceLock<String> = OnceLock::new();
    CLEANED.get_or_init(|| {
        let mut s = crate::LOGO_SVG.to_string();
        for attr in [r#" width="64""#, r#" height="64""#] {
            s = s.replace(attr, "");
        }
        // Force the root svg to fill the wrapper and never carry intrinsic size.
        s.replacen(
            "<svg ",
            "<svg style=\"width:100%;height:100%;display:block\" ",
            1,
        )
    })
}

#[component]
pub fn LogoMark(size: u32) -> Element {
    let svg = logo_svg_scalable();
    rsx! {
        div { style: "display:inline-flex;width:{size}px;height:{size}px;flex:none;line-height:0",
            dangerous_inner_html: "{svg}",
        }
    }
}

/// First-run setup wizard — four steps that introduce Kintsugi, propose
/// setting a master password, propose picking a local model, then finish.
/// All steps are optional (Skip moves on); the user can always set things up
/// later from Settings. Mounted at the app shell as a full-screen overlay.
#[component]
pub fn SetupWizard() -> Element {
    let mut store = use_store();
    let step = store.wizard_step.read().clone();
    let Some(step) = step else { return rsx! {} };

    let mut pw_new = use_signal(String::new);
    let mut pw_confirm = use_signal(String::new);
    let mut pw_err = use_signal(String::new);
    let mut recovery_key = use_signal(|| None::<String>);

    // Real local-model state for step 3 — same source as Settings.
    let local_models = use_resource(move || async move {
        let _ = store.tick.read();
        tokio::task::spawn_blocking(crate::bindings::available_models)
            .await
            .unwrap_or_default()
    });
    let hf_suggested = use_resource(move || async move {
        tokio::task::spawn_blocking(crate::bindings::hf_suggested)
            .await
            .unwrap_or_default()
    });
    let mut downloading = use_signal(|| None::<String>);

    // Detected agent CLIs for the final step — same source as the Settings hook
    // panel. `hooks_tick` re-runs the read after we enable them.
    let mut hooks_tick = use_signal(|| 0u32);
    let agent_hooks = use_resource(move || async move {
        let _ = hooks_tick();
        tokio::task::spawn_blocking(crate::bindings::agent_hooks)
            .await
            .unwrap_or_default()
    });

    let mut dismiss = move |finalize: bool| {
        if finalize {
            let _ = crate::bindings::mark_setup_done();
        }
        store.wizard_step.set(None);
    };

    let step_index = match step {
        crate::state::WizardStep::Welcome => 0usize,
        crate::state::WizardStep::Password => 1,
        crate::state::WizardStep::Model => 2,
        crate::state::WizardStep::Done => 3,
    };
    let step_label = ["Welcome", "Password", "Model", "Done"];

    rsx! {
        div { style: "position:fixed;inset:0;z-index:90;background:rgba(8,10,14,.92);display:flex;align-items:center;justify-content:center;animation:kfade .2s ease;backdrop-filter:blur(6px);overflow-y:auto;padding:24px",
            div { style: "width:620px;max-width:94vw;max-height:calc(100vh - 48px);background:var(--bg2);border:1px solid var(--gold-line);border-radius:16px;box-shadow:0 40px 100px rgba(0,0,0,.6);display:flex;flex-direction:column;overflow:hidden",

                // Stepper header — gold pill per step, current is filled. Pinned.
                div { style: "flex:none;display:flex;align-items:center;gap:8px;padding:18px 24px 12px;border-bottom:1px solid var(--hair)",
                    span { style: "font-size:14px;font-weight:700;letter-spacing:-.1px", "Welcome to Kintsugi" }
                    div { style: "margin-left:auto;display:flex;align-items:center;gap:7px",
                        for (i, lbl) in step_label.iter().enumerate() {
                            {
                                let (bg, fg) = if i == step_index {
                                    ("var(--gold)", "#1a1206")
                                } else if i < step_index {
                                    ("rgba(212,175,55,.25)", "var(--gold)")
                                } else {
                                    ("var(--panel2)", "var(--dim)")
                                };
                                let lbl_color = if i == step_index { "var(--ink)" } else { "var(--dim)" };
                                let n = i + 1;
                                rsx! {
                                    div { style: "display:inline-flex;align-items:center;gap:6px",
                                        span { style: "display:inline-flex;align-items:center;justify-content:center;width:20px;height:20px;border-radius:50%;background:{bg};color:{fg};font-size:11px;font-weight:700", "{n}" }
                                        span { style: "font-size:11px;font-weight:600;color:{lbl_color}", "{lbl}" }
                                    }
                                }
                            }
                        }
                    }
                    button { style: "margin-left:6px;display:inline-flex;align-items:center;justify-content:center;width:26px;height:26px;border:1px solid var(--line);border-radius:7px;background:var(--panel);color:var(--dim);font-size:15px;cursor:pointer",
                        onclick: move |_| dismiss(true),
                        title: "Close — you can re-run setup from Settings.",
                        "×"
                    }
                }

                // Step body — the one scrollable region.
                div { style: "flex:1;overflow-y:auto;padding:24px 28px 12px;min-height:0",
                    match step {
                        crate::state::WizardStep::Welcome => rsx! {
                            div { style: "display:flex;flex-direction:column;align-items:center;text-align:center;margin-bottom:10px",
                                LogoMark { size: 56 }
                                div { style: "font-size:20px;font-weight:700;letter-spacing:-.2px;margin-top:14px", "Local-first guardrails for AI agents" }
                                div { style: "font-size:13.5px;color:var(--dim);line-height:1.6;margin-top:8px;max-width:480px",
                                    "Kintsugi watches every command your coding agent (Claude, Codex, Cursor, etc.) tries to run. It allows safe ones, holds the ambiguous, and blocks the catastrophic — locally, with a tamper-evident audit log."
                                }
                            }
                            ul { style: "list-style:none;padding:0;margin:18px auto 0;max-width:460px;display:flex;flex-direction:column;gap:8px;font-size:13px",
                                li { style: "display:flex;gap:10px;align-items:flex-start", span { style: "color:var(--green);font-weight:700;flex:none", "✓" } "Nothing leaves your machine — the local model summarizes commands." }
                                li { style: "display:flex;gap:10px;align-items:flex-start", span { style: "color:var(--green);font-weight:700;flex:none", "✓" } "Two minutes of setup: a password (so only you can stop it) and an optional model." }
                                li { style: "display:flex;gap:10px;align-items:flex-start", span { style: "color:var(--green);font-weight:700;flex:none", "✓" } "Every step here is optional — you can configure all of it later from Settings." }
                            }
                        },
                        crate::state::WizardStep::Password => rsx! {
                            div { style: "font-size:18px;font-weight:700", "Set a master password" }
                            div { style: "font-size:12.5px;color:var(--gold);margin-top:4px;font-weight:600", "Recommended" }
                            div { style: "font-size:13px;color:var(--dim);line-height:1.55;margin-top:10px;margin-bottom:18px",
                                "Without a password an agent that compromises your shell could "
                                b { style: "color:var(--ink)", "stop Kintsugi itself" }
                                ". The password gates shutdown and \"loosening\" operations. It is verified locally — never sent anywhere."
                            }
                            if let Some(key) = recovery_key.read().clone() {
                                div { style: "border:1px solid var(--gold-line);border-radius:10px;background:rgba(212,175,55,.07);padding:13px 15px;margin-bottom:14px",
                                    div { style: "font-size:12px;font-weight:700;color:var(--gold);display:flex;align-items:center;gap:7px",
                                        span { "⚠" }
                                        "Save this recovery key — shown once, never again."
                                    }
                                    div { style: "font-family:'IBM Plex Mono',monospace;font-size:13px;color:#e7ecf6;margin-top:9px;background:var(--term);border:1px solid var(--line);border-radius:8px;padding:11px 13px;overflow-x:auto;white-space:nowrap", "{key}" }
                                }
                            } else {
                                div { style: "display:flex;flex-direction:column;gap:9px",
                                    input { r#type: "password", class: "kn-input", value: "{pw_new}", placeholder: "Pick a password",
                                        style: "height:36px;box-sizing:border-box;border-radius:8px;border:1px solid var(--line);background:var(--panel2);color:var(--ink);padding:0 12px;font-family:inherit;font-size:13px;outline:none",
                                        oninput: move |e| { pw_new.set(e.value()); pw_err.set(String::new()); },
                                    }
                                    input { r#type: "password", class: "kn-input", value: "{pw_confirm}", placeholder: "Confirm",
                                        style: "height:36px;box-sizing:border-box;border-radius:8px;border:1px solid var(--line);background:var(--panel2);color:var(--ink);padding:0 12px;font-family:inherit;font-size:13px;outline:none",
                                        oninput: move |e| { pw_confirm.set(e.value()); pw_err.set(String::new()); },
                                    }
                                    if !pw_err.read().is_empty() {
                                        div { style: "font-size:12px;color:var(--red);display:inline-flex;align-items:center;gap:6px",
                                            span { "⛔" }
                                            "{pw_err}"
                                        }
                                    }
                                }
                            }
                        },
                        crate::state::WizardStep::Model => rsx! {
                            div { style: "font-size:18px;font-weight:700", "Pick a local model" }
                            div { style: "font-size:12.5px;color:var(--gold);margin-top:4px;font-weight:600", "Recommended" }
                            div { style: "font-size:13px;color:var(--dim);line-height:1.55;margin-top:10px;margin-bottom:16px",
                                "The local model writes the plain-English summary you see when a command is held — without it, you only get the rule name. Models run entirely on-device."
                            }
                            // Already-on-disk picks (instant)
                            if let Some(local) = local_models() {
                                if !local.is_empty() {
                                    div { style: "font-size:10.5px;font-weight:600;letter-spacing:.6px;text-transform:uppercase;color:var(--dim);margin-bottom:7px", "Already on disk" }
                                    div { style: "display:flex;flex-direction:column;gap:7px;margin-bottom:16px",
                                        for m in local.iter().take(3).cloned() {
                                            {
                                                let path = m.path.clone();
                                                let name = m.name.clone();
                                                rsx! {
                                                    div { style: "display:flex;align-items:center;gap:11px;border:1px solid var(--line);border-radius:9px;background:var(--panel2);padding:10px 13px",
                                                        div { style: "flex:1;min-width:0",
                                                            span { style: "display:block;font-family:'IBM Plex Mono',monospace;font-size:12.5px;font-weight:600;color:var(--ink);overflow:hidden;text-overflow:ellipsis;white-space:nowrap", "{name}" }
                                                            div { style: "font-size:11px;color:var(--dim);margin-top:2px", "{m.size} · on disk" }
                                                        }
                                                        button { style: "flex:none;font-family:inherit;font-size:12px;font-weight:600;color:var(--gold);background:var(--panel);border:1px solid var(--gold-line);border-radius:7px;padding:7px 12px;cursor:pointer",
                                                            onclick: move |_| {
                                                                let _ = crate::bindings::set_model(&path);
                                                                store.toast(crate::state::ToastKind::Success, "Model selected — finishing setup will restart the daemon.");
                                                                store.wizard_step.set(Some(crate::state::WizardStep::Done));
                                                            },
                                                            "Use this"
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            // Suggested from Hugging Face
                            div { style: "font-size:10.5px;font-weight:600;letter-spacing:.6px;text-transform:uppercase;color:var(--dim);margin-bottom:7px", "Suggested on Hugging Face" }
                            if hf_suggested().is_none() {
                                Loader { label: "Loading suggestions…".to_string() }
                            } else {
                                div { style: "display:flex;flex-direction:column;gap:7px",
                                    for m in hf_suggested().unwrap_or_default().iter().take(3).cloned() {
                                        {
                                            let id = m.id.clone();
                                            let is_dl = downloading.read().as_deref() == Some(m.id.as_str());
                                            rsx! {
                                                div { style: "display:flex;align-items:center;gap:11px;border:1px solid var(--line);border-radius:9px;background:var(--panel2);padding:10px 13px",
                                                    div { style: "flex:1;min-width:0",
                                                        span { style: "display:block;font-family:'IBM Plex Mono',monospace;font-size:12.5px;font-weight:600;color:var(--ink);overflow:hidden;text-overflow:ellipsis;white-space:nowrap", "{m.id}" }
                                                        div { style: "font-size:11px;color:var(--dim);margin-top:2px", "{m.downloads} downloads · ~2 GB" }
                                                    }
                                                    if is_dl {
                                                        span { style: "flex:none;font-size:12px;color:var(--gold);display:inline-flex;align-items:center;gap:7px",
                                                            span { style: "width:12px;height:12px;border-radius:50%;border:2px solid var(--line);border-top-color:var(--gold);animation:kspin .7s linear infinite" }
                                                            "Downloading…"
                                                        }
                                                    } else {
                                                        button { style: "flex:none;font-family:inherit;font-size:12px;font-weight:600;color:var(--gold);background:var(--panel);border:1px solid var(--gold-line);border-radius:7px;padding:7px 12px;cursor:pointer",
                                                            onclick: move |_| {
                                                                let id_s = id.clone();
                                                                let mut downloading = downloading;
                                                                downloading.set(Some(id_s.clone()));
                                                                store.toast(crate::state::ToastKind::Info, "Downloading — runs in the background; you can keep going.");
                                                                spawn(async move {
                                                                    let id2 = id_s.clone();
                                                                    let res = tokio::task::spawn_blocking(move || crate::bindings::download_model(&id2)).await;
                                                                    match res {
                                                                        Ok(Ok(_)) => { store.toast(crate::state::ToastKind::Success, format!("Downloaded {id_s} — select it from Settings.")); }
                                                                        Ok(Err(e)) => { store.toast(crate::state::ToastKind::Error, format!("Download failed: {e}")); }
                                                                        Err(_) => { store.toast(crate::state::ToastKind::Error, "Download task crashed.".to_string()); }
                                                                    }
                                                                    downloading.set(None);
                                                                });
                                                            },
                                                            "Download"
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        crate::state::WizardStep::Done => {
                            let hooks = agent_hooks().unwrap_or_default();
                            let off = hooks.iter().filter(|h| !h.installed).count();
                            rsx! {
                                div { style: "display:flex;flex-direction:column;align-items:center;text-align:center;padding:6px 10px 2px",
                                    span { style: "display:inline-flex;align-items:center;justify-content:center;width:54px;height:54px;border-radius:15px;background:rgba(90,247,142,.13);color:var(--green);font-size:27px;font-weight:700", "✓" }
                                    div { style: "font-size:20px;font-weight:700;margin-top:12px", "You're protected." }
                                    div { style: "font-size:13px;color:var(--dim);margin-top:7px;line-height:1.5;max-width:440px",
                                        "Open the "
                                        b { style: "color:var(--ink)", "?" }
                                        " button anytime for a tour, or jump to Activity to see your agents live."
                                    }
                                }

                                // Wire the agent CLIs (GUI-first users never run `kintsugi init`).
                                div { style: "margin-top:16px;border:1px solid var(--line);border-radius:12px;background:var(--panel);overflow:hidden",
                                    div { style: "display:flex;align-items:center;gap:10px;padding:12px 15px;border-bottom:1px solid var(--hair)",
                                        div { style: "flex:1",
                                            div { style: "font-size:13.5px;font-weight:700", "Agent CLIs" }
                                            div { style: "font-size:11.5px;color:var(--dim);margin-top:1px",
                                                if hooks.is_empty() { "None detected — install one (e.g. Claude Code), then enable it in Settings." }
                                                else if off == 0 { "All detected agent CLIs are guarded." }
                                                else { "Turn on Kintsugi's hook for every detected CLI." }
                                            }
                                        }
                                        if !hooks.is_empty() {
                                            button {
                                                class: "kn-btn-gold",
                                                style: "flex:none;font-family:inherit;font-size:12.5px;font-weight:700;color:#1a1206;background:var(--gold);border:none;border-radius:8px;padding:8px 14px;cursor:pointer",
                                                disabled: off == 0,
                                                onclick: move |_| {
                                                    let hs = agent_hooks().unwrap_or_default();
                                                    let (mut ok, mut err) = (0u32, 0u32);
                                                    for h in hs.iter().filter(|h| !h.installed) {
                                                        match crate::bindings::enable_agent_hook(&h.id) {
                                                            Ok(()) => ok += 1,
                                                            Err(_) => err += 1,
                                                        }
                                                    }
                                                    let t = *hooks_tick.read(); hooks_tick.set(t + 1);
                                                    if err == 0 {
                                                        store.toast(crate::state::ToastKind::Success, format!("Enabled Kintsugi on {ok} agent CLI(s)."));
                                                    } else {
                                                        store.toast(crate::state::ToastKind::Error, format!("Enabled {ok}, {err} failed — check Settings."));
                                                    }
                                                },
                                                if off == 0 { "All on ✓" } else { "Enable all" }
                                            }
                                        }
                                    }
                                    for h in hooks.iter() {
                                        div { style: "display:flex;align-items:center;gap:10px;padding:9px 15px;border-bottom:1px solid var(--hair)",
                                            span { style: "flex:1;font-size:12.5px;color:var(--ink)", "{h.name}" }
                                            if h.installed {
                                                span { style: "flex:none;font-size:11.5px;font-weight:600;color:var(--green)", "✓ on" }
                                            } else {
                                                span { style: "flex:none;font-size:11.5px;color:var(--dim)", "off" }
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    }
                }

                // Footer — Skip / Back / Next. Pinned.
                div { style: "flex:none;display:flex;align-items:center;gap:10px;padding:14px 24px 18px;border-top:1px solid var(--hair);background:var(--bg2)",
                    button { style: "font-family:inherit;font-size:12.5px;font-weight:600;color:var(--dim);background:transparent;border:none;cursor:pointer",
                        onclick: move |_| dismiss(true),
                        if step_index < 3 { "Skip setup" } else { "Close" }
                    }
                    div { style: "margin-left:auto;display:flex;align-items:center;gap:10px",
                        if step_index > 0 && step_index < 3 {
                            button { class: "kn-btn-ghost", style: "font-family:inherit;font-size:13px;font-weight:600;color:var(--ink);background:var(--panel);border:1px solid var(--line);border-radius:9px;padding:10px 16px;cursor:pointer",
                                onclick: move |_| {
                                    let next = match step {
                                        crate::state::WizardStep::Password => crate::state::WizardStep::Welcome,
                                        crate::state::WizardStep::Model => crate::state::WizardStep::Password,
                                        _ => return,
                                    };
                                    store.wizard_step.set(Some(next));
                                },
                                "Back"
                            }
                        }
                        button { class: "kn-btn-gold", style: "font-family:inherit;font-size:13px;font-weight:600;color:#1a1206;background:var(--gold);border:none;border-radius:9px;padding:10px 20px;cursor:pointer",
                            onclick: move |_| {
                                match step {
                                    crate::state::WizardStep::Welcome => store.wizard_step.set(Some(crate::state::WizardStep::Password)),
                                    crate::state::WizardStep::Password => {
                                        // Second click ("I've saved it — next"): the password is
                                        // already set and the recovery key has been shown — ADVANCE.
                                        // (Re-running set_master_password here would fail now that a
                                        // vault exists, leaving the wizard stuck.)
                                        if recovery_key.read().is_some() {
                                            store.wizard_step.set(Some(crate::state::WizardStep::Model));
                                            return;
                                        }
                                        // If they typed a password, set it; else skip.
                                        let new = pw_new.read().clone();
                                        if new.is_empty() {
                                            store.wizard_step.set(Some(crate::state::WizardStep::Model));
                                            return;
                                        }
                                        if new != *pw_confirm.read() {
                                            pw_err.set("The two passwords don't match.".to_string());
                                            return;
                                        }
                                        match crate::bindings::set_master_password(&new) {
                                            Ok(key) => {
                                                recovery_key.set(Some(key));
                                                store.session_pw.set(Some(zeroize::Zeroizing::new(new.clone())));
                                                store.toast(crate::state::ToastKind::Success, "Master password set.");
                                                // Stay on the password step so the recovery key shows; user clicks Next again to advance.
                                                store.wizard_step.set(Some(crate::state::WizardStep::Password));
                                            }
                                            Err(e) => pw_err.set(e.to_string()),
                                        }
                                    }
                                    crate::state::WizardStep::Model => store.wizard_step.set(Some(crate::state::WizardStep::Done)),
                                    crate::state::WizardStep::Done => dismiss(true),
                                }
                            },
                            match step {
                                crate::state::WizardStep::Welcome => "Get started →",
                                crate::state::WizardStep::Password => if recovery_key.read().is_some() { "I've saved it — next" } else if !pw_new.read().is_empty() { "Set password" } else { "Skip" },
                                crate::state::WizardStep::Model => "Continue",
                                crate::state::WizardStep::Done => "Open the app",
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Always-available cheatsheet of what Kintsugi can do. Opened via the "?"
/// button in the sidebar footer. Lives in its own slide-in panel so it never
/// blocks the screen behind it.
#[component]
pub fn HelpDrawer() -> Element {
    let mut store = use_store();
    if !*store.help_open.read() {
        return rsx! {};
    };

    struct Group {
        title: &'static str,
        items: &'static [(&'static str, &'static str)],
    }
    static GROUPS: &[Group] = &[
        Group { title: "Live protection",
            items: &[
                ("Activity", "every command your agents try — allowed, held, blocked, live."),
                ("Needs review", "ambiguous commands waiting on your decision (only the ones Kintsugi can't resolve via the agent's own prompt)."),
                ("Where it came from", "the provenance trail when untrusted content influences a command (the lethal trifecta)."),
                ("Panic", "halts ALL agent actions instantly while keeping the engine on. Different from Stop, which powers Kintsugi off."),
            ] },
        Group { title: "Records",
            items: &[
                ("History", "what Kintsugi held or blocked — tamper-evidence chain re-verifies on entry."),
                ("Rules", "the deterministic floor: which built-in protections are armed + your effective policy."),
                ("Undo", "every snapshot of a destructive op, one click from rollback."),
            ] },
        Group { title: "Setup",
            items: &[
                ("Master password", "argon2id-sealed — gates stopping and loosening. Verified locally, never sent."),
                ("Local model", "browse Hugging Face or pick from disk; deletes are two-step. Drives the plain-English summaries."),
                ("Agent CLI hooks", "per-CLI on/off + refresh — see every agent Kintsugi is wired into."),
                ("Recorder", "describes shell commands with the model summary and (gated) asks before risky ones."),
                ("Fail-closed / Auto-restart", "real toggles; the recorder writes a fenced block in your shell rc."),
                ("Uninstall", "password-gated, optional data purge, plan + type-to-confirm."),
            ] },
        Group { title: "Click any activity row",
            items: &[
                ("Details drawer", "raw command, decision, the model's summary, agent, session, working dir, rule, tier, event id, plus a jump to provenance for tainted commands."),
            ] },
    ];

    rsx! {
        div { style: "position:fixed;inset:0;z-index:70;background:rgba(0,0,0,.45);display:flex;justify-content:flex-end;animation:kfade .15s ease",
            onclick: move |_| store.help_open.set(false),
            div { style: "width:520px;max-width:94vw;height:100%;background:var(--bg2);border-left:1px solid var(--line);box-shadow:-24px 0 60px rgba(0,0,0,.45);overflow-y:auto",
                onclick: move |e| e.stop_propagation(),
                div { style: "position:sticky;top:0;background:var(--bg2);display:flex;align-items:center;gap:12px;padding:18px 22px;border-bottom:1px solid var(--line);z-index:1",
                    span { style: "font-size:15px;font-weight:700;letter-spacing:-.1px", "Everything Kintsugi can do" }
                    button { style: "margin-left:auto;display:inline-flex;align-items:center;justify-content:center;width:30px;height:30px;border:1px solid var(--line);border-radius:8px;background:var(--panel);color:var(--dim);font-size:17px;cursor:pointer",
                        onclick: move |_| store.help_open.set(false),
                        "×"
                    }
                }
                div { style: "padding:6px 22px 22px",
                    for g in GROUPS.iter() {
                        div { style: "margin-top:18px;font-size:10.5px;font-weight:700;letter-spacing:.7px;color:var(--gold);text-transform:uppercase", "{g.title}" }
                        for (title, body) in g.items.iter() {
                            div { style: "padding:11px 0;border-bottom:1px solid var(--hair)",
                                div { style: "font-size:13px;font-weight:600;color:var(--ink)", "{title}" }
                                div { style: "font-size:12px;color:var(--dim);margin-top:3px;line-height:1.5", "{body}" }
                            }
                        }
                    }
                    div { style: "margin-top:18px;font-size:11.5px;color:var(--dim);line-height:1.55",
                        "Need to re-run the setup wizard? Open Settings → Uninstall (or just reset by deleting "
                        span { style: "font-family:'IBM Plex Mono',monospace;color:var(--ink)", "~/Library/Application Support/kintsugi/desktop-setup-done" }
                        ")."
                    }
                }
            }
        }
    }
}

/// Bottom-right stack of transient notifications driven by `Store::toasts`.
/// Each toast auto-dismisses after 3.5s; click × to dismiss early.
#[component]
pub fn Toasts() -> Element {
    let mut store = use_store();
    let toasts = store.toasts.read().clone();

    // Pop the front toast every 3.5s — simple FIFO so each toast lingers a
    // comparable amount of time without needing per-id timestamps.
    let _auto = use_resource(move || async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(3500)).await;
            let mut w = store.toasts.write();
            if !w.is_empty() {
                w.remove(0);
            }
        }
    });

    rsx! {
        div { style: "position:fixed;right:18px;bottom:18px;z-index:80;display:flex;flex-direction:column;gap:9px;pointer-events:none",
            for t in toasts.iter().cloned() {
                {
                    let (color, glow, icon) = match t.kind {
                        crate::state::ToastKind::Success => ("var(--green)", "rgba(90,247,142,.15)", "✓"),
                        crate::state::ToastKind::Error => ("var(--red)", "rgba(255,93,93,.15)", "⛔"),
                        crate::state::ToastKind::Info => ("var(--gold)", "rgba(212,175,55,.15)", "ⓘ"),
                    };
                    let id = t.id;
                    rsx! {
                        div { style: "pointer-events:auto;display:flex;align-items:center;gap:11px;background:var(--bg2);border:1px solid var(--line);border-left:3px solid {color};border-radius:10px;padding:11px 14px;min-width:260px;max-width:420px;box-shadow:0 8px 26px rgba(0,0,0,.35);animation:kfade .15s ease",
                            span { style: "flex:none;display:inline-flex;align-items:center;justify-content:center;width:24px;height:24px;border-radius:7px;background:{glow};color:{color};font-size:13px;font-weight:700", "{icon}" }
                            span { style: "flex:1;font-size:12.5px;color:var(--ink);line-height:1.4", "{t.message}" }
                            button { style: "flex:none;display:inline-flex;align-items:center;justify-content:center;width:22px;height:22px;border:none;border-radius:6px;background:transparent;color:var(--dim);font-size:14px;cursor:pointer",
                                onclick: move |_| store.dismiss_toast(id),
                                "×"
                            }
                        }
                    }
                }
            }
        }
    }
}

/// A centered loading spinner shown while a screen's first read is in flight.
#[component]
fn Loader(label: String) -> Element {
    rsx! {
        div { style: "display:flex;flex-direction:column;align-items:center;justify-content:center;gap:13px;padding:54px 18px",
            span { style: "width:26px;height:26px;border-radius:50%;border:2.5px solid var(--line);border-top-color:var(--gold);animation:kspin .7s linear infinite" }
            span { style: "font-size:12.5px;color:var(--dim)", "{label}" }
        }
    }
}

/// One label/value line in the detail drawer.
#[component]
fn DetailRow(label: String, value: String) -> Element {
    rsx! {
        div { style: "display:flex;gap:14px;padding:9px 0;border-bottom:1px solid var(--hair)",
            span { style: "flex:none;width:104px;font-size:12px;color:var(--dim)", "{label}" }
            span { style: "flex:1;min-width:0;font-size:12.5px;color:var(--ink);font-family:'IBM Plex Mono',monospace;word-break:break-all", "{value}" }
        }
    }
}

/// The full detail for one activity — a right-side drawer opened by clicking any
/// row. Shows the verbatim command, the decision, the model's plain-English
/// summary (when it scored), and the provenance hop. Renders nothing when closed.
#[component]
pub fn DetailDrawer() -> Element {
    let mut store = use_store();
    let row = store.detail.read().clone();
    let Some(r) = row else { return rsx! {} };

    let dec_key = outcome_key(&r.outcome);
    let (glyph, color) = decision(dec_key);
    let (class_label, class_st) = crate::data::risk_style(&r.class);
    let decided_by = if r.tier >= 2 {
        "Local model · Tier 2"
    } else {
        "Deterministic rules · Tier 1"
    };
    let session = r.session.clone().unwrap_or_else(|| "—".to_string());

    rsx! {
        div {
            style: "position:fixed;inset:0;z-index:50;background:rgba(0,0,0,.45);display:flex;justify-content:flex-end;animation:kfade .15s ease",
            onclick: move |_| store.detail.set(None),
            div {
                style: "width:480px;max-width:94vw;height:100%;background:var(--bg2);border-left:1px solid var(--line);box-shadow:-24px 0 60px rgba(0,0,0,.45);overflow-y:auto",
                onclick: move |e| e.stop_propagation(),

                div { style: "position:sticky;top:0;background:var(--bg2);display:flex;align-items:center;gap:12px;padding:17px 22px;border-bottom:1px solid var(--line);z-index:1",
                    span { style: "font-size:15px;font-weight:700;letter-spacing:-.1px", "Activity detail" }
                    span { style: "display:inline-flex;align-items:center;gap:6px;font-size:12.5px;font-weight:600;color:{color}", "{glyph} {dec_key}" }
                    button {
                        style: "margin-left:auto;display:inline-flex;align-items:center;justify-content:center;width:30px;height:30px;border:1px solid var(--line);border-radius:8px;background:var(--panel);color:var(--dim);font-size:17px;cursor:pointer",
                        onclick: move |_| store.detail.set(None),
                        "×"
                    }
                }

                div { style: "padding:20px 22px",
                    // verbatim command
                    div { style: "font-family:'IBM Plex Mono',monospace;font-size:13px;color:var(--ink);background:var(--bg);border:1px solid var(--line);border-radius:10px;padding:13px 15px;line-height:1.5;word-break:break-all;margin-bottom:14px", "{r.command}" }

                    // badges
                    div { style: "display:flex;flex-wrap:wrap;gap:8px;margin-bottom:18px",
                        if !class_label.is_empty() {
                            span { style: "font-size:11px;font-weight:600;border:1px solid var(--line);border-radius:6px;padding:4px 10px;{class_st}", "{class_label}" }
                        }
                        if let Some(risk) = r.risk {
                            span { style: "font-size:11px;font-weight:600;color:var(--dim);border:1px solid var(--line);border-radius:6px;padding:4px 10px", "risk {risk}/100" }
                        }
                        if r.provenance_block {
                            span { style: "font-size:11px;font-weight:600;color:var(--red);border:1px solid rgba(255,93,93,.35);border-radius:6px;padding:4px 10px", "⚠ trifecta block" }
                        }
                    }

                    // model summary — the thing the user said was missing
                    if let Some(s) = r.summary.clone().filter(|s| !s.is_empty()) {
                        div { style: "border:1px solid var(--gold-line);border-radius:10px;background:linear-gradient(100deg,rgba(212,175,55,.07),transparent);padding:13px 15px;margin-bottom:18px",
                            div { style: "font-size:10.5px;font-weight:600;letter-spacing:.6px;text-transform:uppercase;color:var(--gold);margin-bottom:6px", "Model summary" }
                            div { style: "font-size:13px;color:var(--ink);line-height:1.5", "{s}" }
                        }
                    } else {
                        div { style: "font-size:12.5px;color:var(--dim);line-height:1.5;margin-bottom:18px;padding:11px 14px;border:1px dashed var(--line);border-radius:10px",
                            "Decided by deterministic rules — no model summary. The local model only scores the ambiguous band."
                        }
                    }

                    // fields
                    DetailRow { label: "When".to_string(), value: short_time(&r.ts) }
                    DetailRow { label: "Agent".to_string(), value: r.agent.clone() }
                    DetailRow { label: "Session".to_string(), value: session }
                    DetailRow { label: "Working dir".to_string(), value: r.cwd.clone() }
                    DetailRow { label: "Rule".to_string(), value: r.reason.clone() }
                    DetailRow { label: "Decided by".to_string(), value: decided_by.to_string() }
                    DetailRow { label: "Event id".to_string(), value: r.id.clone() }

                    // jump to the provenance trail for a tainted command
                    if r.provenance_block {
                        button {
                            style: "margin-top:18px;width:100%;font-family:inherit;font-size:12.5px;font-weight:600;color:var(--gold);background:var(--panel);border:1px solid var(--gold-line);border-radius:9px;padding:11px;cursor:pointer",
                            onclick: move |_| { store.detail.set(None); store.screen.set(Screen::Provenance); },
                            "See where it came from →"
                        }
                    }
                }
            }
        }
    }
}

/// The settings toggle switch (used by the protection toggles in Settings).
#[component]
fn Toggle(on: bool, on_click: EventHandler<()>) -> Element {
    let track = if on {
        "background:var(--gold)"
    } else {
        "background:var(--line)"
    };
    let knob = if on { "left:21px" } else { "left:3px" };
    rsx! {
        button { style: "flex:none;width:42px;height:24px;border-radius:13px;border:none;cursor:pointer;position:relative;transition:background .15s;{track}",
            onclick: move |_| on_click.call(()),
            span { style: "position:absolute;top:3px;width:18px;height:18px;border-radius:50%;background:#fff;transition:left .15s;{knob}" }
        }
    }
}

#[component]
pub fn Dashboard() -> Element {
    let mut store = use_store();

    // ---- live backend reads (off the UI thread via spawn_blocking) ----
    // Light reads refresh on the fast tick; the heavy metrics full-scan on the
    // slow tick so a 4 Hz refresh never re-runs a full-table scan (the lag fix).
    // commands(6) is the agent feed with fs-watch EXCLUDED (no watcher noise).
    let metrics_res = use_resource(move || async move {
        let _ = store.slow_tick.read();
        tokio::task::spawn_blocking(crate::bindings::metrics)
            .await
            .unwrap_or_default()
    });
    let queue_res = use_resource(move || async move {
        let _ = store.tick.read();
        tokio::task::spawn_blocking(crate::bindings::queue)
            .await
            .unwrap_or_default()
    });
    let activity_res = use_resource(move || async move {
        let _ = store.tick.read();
        tokio::task::spawn_blocking(|| crate::bindings::commands(6))
            .await
            .unwrap_or_default()
    });

    let metrics = metrics_res().unwrap_or_default();
    let queue = queue_res().unwrap_or_default();
    let activity = activity_res().unwrap_or_default();

    let needs = queue.len();
    let alert = needs > 0;

    // ---- hero state (red "needs review" vs green "you're protected") ----
    let (icon_path, title, sub, bg, line, icon_bg, icon_color) = if alert {
        let title = if needs == 1 {
            "1 thing needs your review".to_string()
        } else {
            format!("{needs} things need your review")
        };
        (
            "M12 3l7 3v5c0 4-3 7-7 9-4-2-7-5-7-9V6z M12 8.5v4 M12 15.4v.5",
            title,
            "Everything else is guarded. This one is waiting on you.".to_string(),
            "linear-gradient(100deg,rgba(255,93,93,.12),transparent)",
            "rgba(255,93,93,.4)",
            "rgba(255,93,93,.14)",
            "var(--red)",
        )
    } else {
        (
            "M12 3l7 3v5c0 4-3 7-7 9-4-2-7-5-7-9V6z M9 12l2 2 4-4",
            "You're protected".to_string(),
            "Nothing needs you right now — your agents are guarded.".to_string(),
            "linear-gradient(100deg,rgba(90,247,142,.08),transparent)",
            "rgba(90,247,142,.3)",
            "rgba(90,247,142,.13)",
            "var(--green)",
        )
    };

    // ---- today summary line (live counts) ----
    let summary = [
        (metrics.allowed, "allowed", "var(--green)"),
        (metrics.held, "held", "var(--amber)"),
        (metrics.denied, "blocked", "var(--red)"),
    ];

    rsx! {
        div { style: "padding:30px 26px;{FADE}",
            div { style: "border:1px solid {line};border-radius:16px;background:{bg};padding:22px 24px",
                div { style: "display:flex;align-items:center;gap:16px",
                    span { style: "display:inline-flex;align-items:center;justify-content:center;width:46px;height:46px;flex:none;border-radius:12px;background:{icon_bg}",
                        svg { view_box: "0 0 24 24", width: "24", height: "24", fill: "none", stroke: "{icon_color}", stroke_width: "1.7", stroke_linecap: "round", stroke_linejoin: "round",
                            path { d: "{icon_path}" }
                        }
                    }
                    div { style: "flex:1",
                        div { style: "font-size:19px;font-weight:700;letter-spacing:-.2px", "{title}" }
                        div { style: "font-size:13.5px;color:var(--dim);margin-top:3px", "{sub}" }
                    }
                    if alert {
                        button { class: "kn-btn-gold",
                            style: "flex:none;font-family:inherit;font-size:13.5px;font-weight:600;color:#1a1206;background:var(--gold);border:none;border-radius:9px;padding:11px 18px;cursor:pointer",
                            onclick: move |_| store.screen.set(Screen::Held),
                            "Review"
                        }
                    }
                }
                div { style: "display:flex;gap:26px;margin-top:20px;padding-top:18px;border-top:1px solid var(--hair)",
                    for (val, lbl, color) in summary {
                        div {
                            span { style: "font-size:21px;font-weight:700;font-family:'IBM Plex Mono',monospace;color:{color}", "{val}" }
                            span { style: "font-size:13px;color:var(--dim);margin-left:7px", "{lbl}" }
                        }
                    }
                    span { style: "margin-left:auto;align-self:center;font-size:12px;color:var(--dim)", "all time" }
                }
            }

            div { style: "margin-top:18px;border:1px solid var(--line);border-radius:14px;background:var(--panel);overflow:hidden",
                div { style: "display:flex;align-items:center;padding:15px 18px;border-bottom:1px solid var(--line)",
                    span { style: "font-size:14px;font-weight:700", "Recent activity" }
                    button { style: "margin-left:auto;font-family:inherit;font-size:12.5px;font-weight:600;color:var(--gold);background:none;border:none;cursor:pointer",
                        onclick: move |_| store.screen.set(Screen::Feed),
                        "See all →"
                    }
                }
                if activity.is_empty() {
                    div { style: "padding:30px 18px;text-align:center",
                        div { style: "font-size:13.5px;color:var(--ink)", "◌ Nothing yet" }
                        div { style: "font-size:12px;color:var(--dim);margin-top:4px", "When your agents run commands, they'll appear here as they happen." }
                    }
                } else {
                    for a in activity {
                        {
                            let (glyph, color) = decision(outcome_key(&a.outcome));
                            let detail_row = a.clone();
                            rsx! {
                                div { style: "display:flex;align-items:center;gap:14px;padding:14px 18px;border-bottom:1px solid var(--hair);cursor:pointer",
                                    onclick: move |_| store.detail.set(Some(detail_row.clone())),
                                    span { style: "display:inline-flex;align-items:center;justify-content:center;width:24px;height:24px;border-radius:7px;flex:none;font-size:12px;font-weight:700;color:{color}", "{glyph}" }
                                    div { style: "flex:1;min-width:0",
                                        div { style: "font-family:'IBM Plex Mono',monospace;font-size:13px;color:var(--ink);line-height:1.4;overflow:hidden;text-overflow:ellipsis;white-space:nowrap", "{a.command}" }
                                        div { style: "font-size:11.5px;color:var(--dim);margin-top:2px", "{a.agent}" }
                                    }
                                    span { style: "flex:none;text-align:right", TimeCell { ts: a.ts.clone() } }
                                }
                            }
                        }
                    }
                }
            }

            div { style: "margin-top:16px;display:flex;align-items:center;gap:10px;font-size:12.5px;color:var(--dim)",
                svg { view_box: "0 0 24 24", width: "15", height: "15", fill: "none", stroke: "var(--green)", stroke_width: "1.8", stroke_linecap: "round", stroke_linejoin: "round", style: "flex:none",
                    path { d: "M20 6L9 17l-5-5" }
                }
                span { "Everything is logged and reversible — nothing here is permanent." }
            }
        }
    }
}
#[component]
pub fn Feed() -> Element {
    let mut store = use_store();

    // "File changes" segment: off by default so the fs-watch backstop is AVAILABLE
    // but never in your face (this is what kills the noise complaint).
    let mut show_files = use_signal(|| false);

    let filter = *store.feed_filter.read();
    let search = store.feed_search.read().to_lowercase();
    let page = *store.feed_page.read();

    // Live backend data, OFF the UI thread (the #1 lag fix): the heavy read runs
    // inside spawn_blocking and we fetch once on mount + whenever the source toggle
    // flips — never on a fast render timer.
    let timeline = use_resource(move || async move {
        let _ = store.tick.read();
        let files = *show_files.read();
        let filt = *store.feed_filter.read();
        tokio::task::spawn_blocking(move || {
            if files {
                crate::bindings::file_changes(100) // fs-watch backstop, on demand
            } else if filt == "catastrophic" {
                // Class-targeted so old catastrophic events aren't windowed out by
                // a flood of ambiguous holds (a newest-200 feed would miss them).
                crate::bindings::catastrophic(200)
            } else {
                crate::bindings::commands(200) // agent feed, fs-watch EXCLUDED
            }
        })
        .await
        .unwrap_or_default()
    });
    let loading = timeline().is_none();
    let all_rows = timeline().unwrap_or_default();
    let viewing_files = *show_files.read();

    let rows: Vec<crate::bindings::TimelineRow> = all_rows
        .into_iter()
        .filter(|r| {
            let dec = outcome_decision(&r.outcome);
            match filter {
                "catastrophic" => r.class == "catastrophic",
                "held" => dec == "held",
                "blocked" => dec == "blocked",
                "tainted" => r.provenance_block,
                _ => true,
            }
        })
        .filter(|r| {
            search.is_empty()
                || r.command.to_lowercase().contains(&search)
                || r.agent.to_lowercase().contains(&search)
        })
        .collect();

    let total = rows.len();
    let pages = ((total + FEED_PAGE_SIZE - 1) / FEED_PAGE_SIZE).max(1);
    let page = page.min(pages).max(1);
    let start = (page - 1) * FEED_PAGE_SIZE;
    let end = (start + FEED_PAGE_SIZE).min(total);
    let slice: Vec<crate::bindings::TimelineRow> = rows[start..end].to_vec();
    let info = if total == 0 {
        "No matches".to_string()
    } else {
        format!("{}–{} of {}", start + 1, end, total)
    };

    let cols = "grid-template-columns:64px 1fr 130px 124px 150px 110px;gap:14px";
    let filters = [
        ("all", "All"),
        ("catastrophic", "Catastrophic"),
        ("held", "Held"),
        ("blocked", "Blocked"),
        ("tainted", "Tainted"),
    ];

    // Segment styles for the Agents / File-changes toggle (word + state, never color-alone).
    let agents_st = if !viewing_files {
        "background:var(--gold);color:#1a1206;border-color:var(--gold)"
    } else {
        "background:var(--panel);color:var(--dim)"
    };
    let files_st = if viewing_files {
        "background:var(--gold);color:#1a1206;border-color:var(--gold)"
    } else {
        "background:var(--panel);color:var(--dim)"
    };

    rsx! {
        div { style: "padding:26px;{FADE}",
            div { style: "display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap;align-items:center",
                div { style: "position:relative;flex:1;min-width:200px;max-width:300px",
                    svg { view_box: "0 0 24 24", width: "15", height: "15", fill: "none", stroke: "var(--dim)", stroke_width: "1.8", stroke_linecap: "round", stroke_linejoin: "round", style: "position:absolute;left:11px;top:50%;transform:translateY(-50%)",
                        circle { cx: "11", cy: "11", r: "7" }
                        path { d: "M21 21l-4-4" }
                    }
                    input { class: "kn-input", value: "{store.feed_search}", placeholder: "Search commands or agents…",
                        style: "width:100%;height:34px;border-radius:8px;border:1px solid var(--line);background:var(--panel);color:var(--ink);padding:0 12px 0 33px;font-family:inherit;font-size:12.5px",
                        oninput: move |e| { store.feed_search.set(e.value()); store.feed_page.set(1); },
                    }
                }
                for (id, label) in filters {
                    {
                        let active = filter == id;
                        let st = if active { "background:var(--gold);color:#1a1206;border-color:var(--gold)" } else { "background:var(--panel);color:var(--dim)" };
                        rsx! {
                            button { style: "font-family:inherit;font-size:12.5px;font-weight:600;border-radius:8px;padding:7px 14px;cursor:pointer;border:1px solid var(--line);{st}",
                                onclick: move |_| { store.feed_filter.set(id); store.feed_page.set(1); },
                                "{label}"
                            }
                        }
                    }
                }
                // ── source segment: Agents (default) ↔ File changes (fs-watch backstop) ──
                div { style: "display:inline-flex;border:1px solid var(--line);border-radius:8px;overflow:hidden;margin-left:6px",
                    button { style: "font-family:inherit;font-size:12.5px;font-weight:600;border:none;border-right:1px solid var(--line);padding:7px 13px;cursor:pointer;{agents_st}",
                        onclick: move |_| { show_files.set(false); store.feed_page.set(1); },
                        "Agents"
                    }
                    button { style: "font-family:inherit;font-size:12.5px;font-weight:600;border:none;padding:7px 13px;cursor:pointer;display:inline-flex;align-items:center;gap:6px;{files_st}",
                        onclick: move |_| { show_files.set(true); store.feed_page.set(1); },
                        svg { view_box: "0 0 24 24", width: "13", height: "13", fill: "none", stroke: "currentColor", stroke_width: "1.8", stroke_linecap: "round", stroke_linejoin: "round",
                            path { d: "M4 7a2 2 0 0 1 2-2h4l2 2h6a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2z" }
                        }
                        "File changes"
                    }
                }
                div { style: "margin-left:auto;display:flex;align-items:center;gap:8px;font-size:12px;color:var(--dim)",
                    span { style: "display:inline-flex;width:7px;height:7px;border-radius:50%;background:var(--green);animation:kpulse 1.6s infinite" }
                    if viewing_files { "filesystem backstop" } else { "agent activity" }
                }
            }

            // Quiet context line when the fs-watch lens is on, so its noise is opt-in and explained.
            if viewing_files {
                div { style: "display:flex;align-items:center;gap:9px;margin-bottom:14px;font-size:12px;color:var(--dim);border:1px solid var(--line);border-radius:9px;background:var(--panel);padding:9px 14px",
                    svg { view_box: "0 0 24 24", width: "14", height: "14", fill: "none", stroke: "var(--gold)", stroke_width: "1.7", stroke_linecap: "round", stroke_linejoin: "round", style: "flex:none",
                        circle { cx: "12", cy: "12", r: "9" } path { d: "M12 8v5M12 16v.4" }
                    }
                    span { "Filesystem-watcher backstop — every on-disk change, even commands the agent hook never saw. Kept out of the main feed by default." }
                }
            }

            div { style: "border:1px solid var(--line);border-radius:12px;background:var(--panel);overflow:hidden",
                div { style: "display:grid;{cols};padding:11px 18px;border-bottom:1px solid var(--line);font-size:10.5px;font-weight:600;letter-spacing:.6px;color:var(--dim);text-transform:uppercase",
                    span { "Time" } span { "Command" } span { "Agent" } span { "Risk" } span { "Taint" }
                    span { style: "text-align:right", "Decision" }
                }
                for r in slice {
                    {
                        let dec = outcome_decision(&r.outcome);
                        let (glyph, color) = decision(dec);
                        let (risk_label, risk_st) = crate::data::risk_style(&r.class);
                        let has_risk = !risk_label.is_empty();
                        let detail_row = r.clone();
                        rsx! {
                            div { style: "display:grid;{cols};padding:12px 18px;border-bottom:1px solid var(--hair);align-items:center;cursor:pointer",
                                onclick: move |_| store.detail.set(Some(detail_row.clone())),
                                TimeCell { ts: r.ts.clone() }
                                span { style: "font-family:'IBM Plex Mono',monospace;font-size:12.5px;color:var(--ink);min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap", "{r.command}" }
                                span { style: "font-size:12.5px;color:var(--dim)", "{r.agent}" }
                                span {
                                    if has_risk {
                                        span { style: "font-size:11.5px;font-weight:600;border-radius:6px;padding:3px 9px;{risk_st}", "{risk_label}" }
                                    }
                                }
                                span {
                                    if r.provenance_block {
                                        span { style: "font-size:11.5px;font-weight:600;color:var(--amber);display:inline-flex;align-items:center;gap:5px", "⚠ tainted" }
                                    }
                                }
                                span { style: "display:inline-flex;align-items:center;gap:6px;justify-content:flex-end;font-size:12.5px;font-weight:600;color:{color}", "{glyph} {dec}" }
                            }
                        }
                    }
                }
                if loading {
                    Loader { label: "Loading activity…".to_string() }
                } else if total == 0 {
                    div { style: "padding:40px 18px;text-align:center",
                        div { style: "font-size:22px;margin-bottom:8px;color:var(--green)", "✓" }
                        div { style: "font-size:14px;font-weight:600;color:var(--ink)",
                            if viewing_files { "No file changes recorded yet" } else { "Nothing to show yet" }
                        }
                        div { style: "font-size:12.5px;color:var(--dim);margin-top:5px;line-height:1.5;max-width:360px;margin-left:auto;margin-right:auto",
                            if !search.is_empty() || filter != "all" {
                                "No commands match this view. Try clearing the search or the filter."
                            } else if viewing_files {
                                "The filesystem watcher hasn't seen any on-disk changes yet. When something writes to a watched path, it lands here."
                            } else {
                                "As your agents run commands, every decision lands here — live, logged, and reversible."
                            }
                        }
                    }
                }
                div { style: "display:flex;align-items:center;gap:12px;padding:12px 18px;border-top:1px solid var(--line)",
                    span { style: "font-size:12px;color:var(--dim)", "{info}" }
                    div { style: "margin-left:auto;display:flex;align-items:center;gap:10px",
                        span { style: "font-size:12px;color:var(--dim)", "Page {page} of {pages}" }
                        button { class: "kn-btn-ghost", style: "font-family:inherit;font-size:12px;font-weight:600;color:var(--ink);background:var(--panel2);border:1px solid var(--line);border-radius:7px;padding:6px 12px;cursor:pointer",
                            onclick: move |_| { if page > 1 { store.feed_page.set(page - 1); } },
                            "‹ Prev"
                        }
                        button { class: "kn-btn-ghost", style: "font-family:inherit;font-size:12px;font-weight:600;color:var(--ink);background:var(--panel2);border:1px solid var(--line);border-radius:7px;padding:6px 12px;cursor:pointer",
                            onclick: move |_| { if page < pages { store.feed_page.set(page + 1); } },
                            "Next ›"
                        }
                    }
                }
            }
        }
    }
}
// (uses the shared `clock` helper at the top of the module)

/// Class → (label, css color) so the badge is a word + color, never color alone.
fn class_style(class: &str) -> (&'static str, &'static str) {
    match class {
        "catastrophic" => ("catastrophic", "var(--red)"),
        "ambiguous" => ("ambiguous", "var(--amber)"),
        "safe" => ("safe", "var(--green)"),
        _ => ("unclassified", "var(--dim)"),
    }
}

#[component]
pub fn Held() -> Element {
    let mut store = use_store();
    // Local tick re-runs the resource right after a resolve(); the global tick
    // keeps the list live. The queue read runs OFF the UI thread.
    let mut tick = use_signal(|| 0u32);
    // Which card (by id) is armed for "Approve & run" — a deliberate two-step so a
    // catastrophic command can't run on a single stray click. One signal for the
    // whole list (only one card arms at a time).
    let mut arming = use_signal(|| None::<String>);
    let rows = use_resource(move || async move {
        let _ = tick(); // refresh immediately after resolve()
        let _ = store.tick.read(); // live refresh on the heartbeat
        tokio::task::spawn_blocking(crate::bindings::queue)
            .await
            .unwrap_or_default()
    });
    let loading = rows().is_none();
    let rows = rows().unwrap_or_default();

    let total_pending = rows.len();
    rsx! {
        div { style: "padding:26px;{FADE}",

            // Bulk recovery: prune every stale "pending" entry left over by older
            // ambiguous holds an agent's native prompt approved. The spine fix in
            // the daemon prevents new ones; this is the cleanup for the backlog.
            if total_pending > 10 {
                div { style: "display:flex;align-items:center;gap:13px;margin-bottom:18px;border:1px solid rgba(212,175,55,.4);border-radius:10px;background:linear-gradient(90deg,rgba(212,175,55,.07),transparent);padding:11px 15px",
                    span { style: "flex:none;display:inline-flex;align-items:center;justify-content:center;width:26px;height:26px;border-radius:7px;background:rgba(212,175,55,.13);color:var(--gold);font-weight:700", "!" }
                    div { style: "flex:1;font-size:12.5px;line-height:1.45;color:var(--ink)",
                        "{total_pending} entries in the queue. Many are likely orphans (an agent's own prompt allowed them) — Kintsugi no longer enqueues those, but the backlog stayed."
                    }
                    button {
                        style: "flex:none;font-family:inherit;font-size:12px;font-weight:600;color:var(--gold);background:var(--panel);border:1px solid var(--gold-line);border-radius:8px;padding:8px 13px;cursor:pointer",
                        onclick: move |_| {
                            match crate::bindings::prune_pending() {
                                Ok(n) => {
                                    store.toast(crate::state::ToastKind::Success, format!("Cleared {n} stale entries."));
                                    let t = *tick.read(); tick.set(t + 1);
                                }
                                Err(e) => { store.toast(crate::state::ToastKind::Error, format!("Couldn't clear: {e}")); }
                            }
                        },
                        "Clear stale"
                    }
                }
            }

            if loading {
                Loader { label: "Loading the review queue…".to_string() }
            } else if rows.is_empty() {
                // Designed empty state — inviting, calm, paired with a glyph.
                div { style: "border:1px solid var(--line);border-radius:16px;background:var(--panel);padding:46px 30px;text-align:center",
                    span { style: "display:inline-flex;align-items:center;justify-content:center;width:54px;height:54px;border-radius:14px;background:rgba(90,247,142,.12);margin-bottom:18px",
                        svg { view_box: "0 0 24 24", width: "26", height: "26", fill: "none", stroke: "var(--green)", stroke_width: "1.7", stroke_linecap: "round", stroke_linejoin: "round",
                            path { d: "M12 3l7 3v5c0 4-3 7-7 9-4-2-7-5-7-9V6z" }
                            path { d: "M9 12l2 2 4-4" }
                        }
                    }
                    div { style: "font-size:18px;font-weight:700;letter-spacing:-.2px", "Nothing held" }
                    div { style: "font-size:13.5px;color:var(--dim);margin-top:6px;line-height:1.55;max-width:420px;margin-left:auto;margin-right:auto",
                        "Kintsugi only interrupts when it must. Every agent action so far cleared on its own — there's nothing waiting on you."
                    }
                }
            } else {
                // Count banner — gentle context above the queue.
                div { style: "display:flex;align-items:center;gap:10px;margin-bottom:16px;font-size:13px;color:var(--dim)",
                    span { style: "display:inline-flex;width:7px;height:7px;border-radius:50%;background:var(--amber);animation:kpulse 1.6s infinite" }
                    if rows.len() == 1 {
                        span { "1 command is paused, waiting for your decision." }
                    } else {
                        span { "{rows.len()} commands are paused, waiting for your decision." }
                    }
                }

                for q in rows {
                    {
                        let id = q.id.clone();
                        let allow_id = id.clone();
                        let deny_id = id.clone();
                        let run_id = id.clone();
                        let arm_id = id.clone();
                        let (class_label, class_color) = class_style(&q.class);
                        let agent = q.agent.clone();
                        // In-band agents (mcp/shim) have a caller parked, waiting to run the
                        // command the instant it's approved. Out-of-band ones (a one-shot
                        // agent hook like claude-code) already got the deny and left — nothing
                        // is waiting, so the human runs it here, from this trusted UI.
                        let in_band = matches!(q.agent.as_str(), "mcp" | "shim");
                        let armed = arming.read().as_deref() == Some(id.as_str());
                        let session = q.session.clone().unwrap_or_default();
                        let command = q.command.clone();
                        let reason = q.reason.clone();
                        let summary = q.summary.clone();
                        let ts = clock(&q.ts);
                        // The same "Activity detail" drawer the feed opens — built from the
                        // held command so a reviewer can inspect it (cwd, summary, rule, id)
                        // without leaving the queue. outcome is "held"; tier follows the
                        // summary (the model only scores the ambiguous/catastrophic bands).
                        let detail_row = crate::bindings::TimelineRow {
                            id: q.id.clone(),
                            ts: q.ts.clone(),
                            agent: q.agent.clone(),
                            session: q.session.clone(),
                            command: q.command.clone(),
                            class: q.class.clone(),
                            outcome: "held".to_string(),
                            reason: q.reason.clone(),
                            provenance_block: q.provenance_block,
                            risk: None,
                            summary: q.summary.clone(),
                            cwd: q.cwd.clone(),
                            tier: if q.summary.is_some() { 2 } else { 1 },
                        };
                        let trifecta = q.provenance_block;
                        let head_bg = if trifecta {
                            "background:linear-gradient(90deg,rgba(255,93,93,.1),transparent)"
                        } else {
                            "background:linear-gradient(90deg,rgba(255,216,102,.08),transparent)"
                        };
                        let border = if trifecta {
                            "border:1px solid rgba(255,93,93,.34)"
                        } else {
                            "border:1px solid var(--line)"
                        };
                        let head_color = if trifecta { "var(--red)" } else { "var(--amber)" };
                        rsx! {
                            div { style: "{border};border-radius:16px;overflow:hidden;background:var(--panel);margin-bottom:16px",
                                // card head
                                div { style: "display:flex;align-items:center;gap:12px;padding:15px 22px;{head_bg};border-bottom:1px solid var(--line)",
                                    span { style: "display:inline-flex;align-items:center;justify-content:center;width:34px;height:34px;border-radius:9px;background:rgba(255,216,102,.14);flex:none",
                                        svg { view_box: "0 0 24 24", width: "19", height: "19", fill: "none", stroke: "{head_color}", stroke_width: "1.8", stroke_linecap: "round", stroke_linejoin: "round",
                                            path { d: "M12 3l7 3v5c0 4-3 7-7 9-4-2-7-5-7-9V6z" }
                                            path { d: "M12 8.5v4M12 15.4v.5" }
                                        }
                                    }
                                    div {
                                        div { style: "font-size:14.5px;font-weight:700;color:{head_color}",
                                            if trifecta { "Held — causally influenced by untrusted content" } else { "Held — waiting for your decision" }
                                        }
                                        div { style: "font-size:12px;color:var(--dim);margin-top:1px", "This decision is deterministic. Rules paused it, not a guess." }
                                    }
                                    span { style: "margin-left:auto;font-family:'IBM Plex Mono',monospace;font-size:11.5px;color:var(--dim);white-space:nowrap", "held · {ts}" }
                                }

                                div { style: "padding:20px 22px",
                                    // badges row
                                    div { style: "display:flex;align-items:center;gap:9px;flex-wrap:wrap;margin-bottom:15px",
                                        span { style: "font-size:11.5px;font-weight:600;border-radius:6px;padding:3px 9px;color:{class_color};background:var(--panel2);border:1px solid var(--line)", "{class_label}" }
                                        if trifecta {
                                            span { style: "font-size:11.5px;font-weight:600;border-radius:6px;padding:3px 9px;color:var(--red);background:rgba(255,93,93,.1);border:1px solid rgba(255,93,93,.34);display:inline-flex;align-items:center;gap:5px",
                                                "⛔ lethal-trifecta"
                                            }
                                        }
                                        span { style: "margin-left:auto;font-size:12px;color:var(--dim)", "{agent}" }
                                        if !session.is_empty() {
                                            span { style: "font-family:'IBM Plex Mono',monospace;font-size:11.5px;color:var(--dim)", "{session}" }
                                        }
                                    }

                                    // reason — plain english
                                    div { style: "font-size:14px;line-height:1.55;margin-bottom:14px;color:var(--ink)", "{reason}" }

                                    // model summary — the Tier-2 plain-English read of the
                                    // command, when the local model scored it at hold time.
                                    if let Some(s) = summary.clone() {
                                        div { style: "display:flex;gap:10px;align-items:flex-start;margin-bottom:14px;padding:11px 13px;border:1px solid var(--gold-line);border-radius:9px;background:rgba(212,175,55,.06)",
                                            span { style: "flex:none;font-size:11px;font-weight:700;letter-spacing:.4px;text-transform:uppercase;color:var(--gold);padding-top:1px", "Model" }
                                            span { style: "font-size:13px;line-height:1.5;color:var(--ink)", "{s}" }
                                        }
                                    }

                                    // raw command verbatim, on the --term surface
                                    div { style: "display:flex;align-items:center;justify-content:space-between;margin-bottom:6px",
                                        span { style: "font-size:11px;color:var(--dim);text-transform:uppercase;letter-spacing:.5px", "Raw command — shown verbatim" }
                                        span { style: "font-size:11px;color:var(--gold);font-weight:600", "View detail →" }
                                    }
                                    div {
                                        style: "font-family:'IBM Plex Mono',monospace;font-size:13px;line-height:1.5;background:var(--term);border:1px solid var(--line);border-radius:9px;padding:13px 15px;color:#e7ecf6;overflow-x:auto;white-space:nowrap;cursor:pointer",
                                        title: "Open the Activity detail drawer",
                                        onclick: move |_| store.detail.set(Some(detail_row.clone())),
                                        "{command}"
                                    }

                                    // actions
                                    div { style: "display:flex;gap:11px;flex-wrap:wrap;margin-top:18px;padding-top:18px;border-top:1px solid var(--line)",
                                        button { style: "font-family:inherit;font-size:13.5px;font-weight:600;color:#fff;background:var(--red);border:none;border-radius:9px;padding:11px 20px;cursor:pointer;display:inline-flex;align-items:center;gap:9px",
                                            onclick: move |_| {
                                                crate::bindings::resolve(&deny_id, false);
                                                arming.set(None);
                                                let t = *tick.read();
                                                tick.set(t + 1);
                                            },
                                            kbd { style: "font-family:inherit;font-size:10.5px;background:rgba(0,0,0,.22);border-radius:4px;padding:1px 5px", "D" }
                                            "Deny"
                                        }

                                        if in_band {
                                            // A caller is parked waiting — approving lets IT run the command.
                                            button { style: "font-family:inherit;font-size:13.5px;font-weight:600;color:var(--ink);background:var(--panel2);border:1px solid var(--line);border-radius:9px;padding:11px 20px;cursor:pointer;display:inline-flex;align-items:center;gap:9px",
                                                onclick: move |_| {
                                                    crate::bindings::resolve(&allow_id, true);
                                                    let t = *tick.read();
                                                    tick.set(t + 1);
                                                },
                                                kbd { style: "font-family:inherit;font-size:10.5px;background:var(--bg);border-radius:4px;padding:1px 5px", "A" }
                                                "Allow once"
                                            }
                                            span { style: "margin-left:auto;align-self:center;font-size:12px;color:var(--dim);max-width:260px;text-align:right;line-height:1.4",
                                                "The {agent} call is waiting — approving lets it run."
                                            }
                                        } else if armed {
                                            // Step 2: confirm. The agent already got the deny and left;
                                            // running it here is the human taking over (snapshot + undo).
                                            button { style: "font-family:inherit;font-size:13.5px;font-weight:700;color:#fff;background:var(--gold);border:none;border-radius:9px;padding:11px 20px;cursor:pointer;display:inline-flex;align-items:center;gap:9px",
                                                onclick: move |_| {
                                                    let res = crate::bindings::approve_and_run(&run_id);
                                                    arming.set(None);
                                                    match res {
                                                        Ok(msg) => store.toast(crate::state::ToastKind::Success, msg),
                                                        Err(e) => store.toast(crate::state::ToastKind::Error, format!("Couldn't run it: {e}")),
                                                    };
                                                    let t = *tick.read();
                                                    tick.set(t + 1);
                                                },
                                                "⚠ Run it now"
                                            }
                                            button { style: "font-family:inherit;font-size:13.5px;font-weight:600;color:var(--dim);background:transparent;border:1px solid var(--line);border-radius:9px;padding:11px 18px;cursor:pointer",
                                                onclick: move |_| { arming.set(None); },
                                                "Cancel"
                                            }
                                            span { style: "margin-left:auto;align-self:center;font-size:12px;color:var(--gold);max-width:300px;text-align:right;line-height:1.4",
                                                "Runs it in its original directory. Snapshots first — `kintsugi undo` can roll it back (unbounded targets like rm -rf may not fully revert)."
                                            }
                                        } else {
                                            // Step 1: arm. The agent won't resume — you run it.
                                            button { style: "font-family:inherit;font-size:13.5px;font-weight:600;color:var(--ink);background:var(--panel2);border:1px solid var(--line);border-radius:9px;padding:11px 20px;cursor:pointer;display:inline-flex;align-items:center;gap:9px",
                                                onclick: move |_| { arming.set(Some(arm_id.clone())); },
                                                kbd { style: "font-family:inherit;font-size:10.5px;background:var(--bg);border-radius:4px;padding:1px 5px", "A" }
                                                "Approve & run"
                                            }
                                            span { style: "margin-left:auto;align-self:center;font-size:12px;color:var(--dim);max-width:280px;text-align:right;line-height:1.4",
                                                "The agent already got the deny and won't resume. If you want it, run it here — then tell your agent to continue."
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
/// `class` pill styling for the Audit table — a word + color, never color alone.
fn audit_class_style(class: &str) -> &'static str {
    match class {
        "safe" => "color:var(--green);border-color:rgba(90,247,142,.35)",
        "ambiguous" => "color:var(--amber);border-color:rgba(255,216,102,.4)",
        "catastrophic" => "color:var(--red);border-color:rgba(255,93,93,.4)",
        _ => "color:var(--dim);border-color:var(--line)",
    }
}

/// Map a TimelineRow.outcome to the decision() glyph key ("denied" -> "blocked").
fn audit_outcome_key(outcome: &str) -> &'static str {
    match outcome {
        "allowed" => "allowed",
        "held" => "held",
        "denied" => "blocked",
        _ => "held",
    }
}

#[component]
pub fn Audit() -> Element {
    let mut store = use_store();
    let mut search = use_signal(String::new);
    let q = search.read().trim().to_string();
    let has_query = !q.is_empty();

    // ── tamper-evidence chain: expensive — it hash-walks the ENTIRE log (can be
    //    100k+ events). Verify ONCE on mount, off the UI thread; re-entering the
    //    screen re-verifies. (Polling this every 2s on a huge log is what made the
    //    "Verifying the chain…" spinner appear stuck.)
    let chain = use_resource(move || async move {
        tokio::task::spawn_blocking(|| crate::bindings::verify())
            .await
            .unwrap_or(None)
    });
    let chain = chain();

    // ── rows: the destructive lens by default (history, fs-watch excluded);
    //    when a query is present, switch to the searchable audit. Both reads go
    //    through spawn_blocking so a typing user never blocks the render thread.
    let query = q.clone();
    let rows = use_resource(move || {
        let _ = store.tick.read();
        let query = query.clone();
        async move {
            tokio::task::spawn_blocking(move || {
                if query.is_empty() {
                    crate::bindings::history(300)
                } else {
                    crate::bindings::audit(&query, 300)
                }
            })
            .await
            .unwrap_or_default()
        }
    });
    let loading = rows().is_none();
    let all_rows = rows().unwrap_or_default();
    let total = all_rows.len();

    // Pagination (newest-first; same page size as the activity feed).
    let mut page = use_signal(|| 1usize);
    let pages = ((total + FEED_PAGE_SIZE - 1) / FEED_PAGE_SIZE).max(1);
    let page_n = (*page.read()).min(pages).max(1);
    let start = (page_n - 1) * FEED_PAGE_SIZE;
    let end = (start + FEED_PAGE_SIZE).min(total);
    let rows = all_rows[start..end].to_vec();
    let footer_ml = if pages > 1 { "20px" } else { "auto" };

    let cols = "grid-template-columns:64px 1fr 130px 124px 150px";

    rsx! {
        div { style: "padding:26px;{FADE}",

            // ── tamper-evidence badge ────────────────────────────────────
            {
                match chain {
                    Some(Some(v)) if v.intact => rsx! {
                        div { style: "display:flex;align-items:center;gap:14px;border:1px solid rgba(90,247,142,.3);border-radius:12px;background:linear-gradient(90deg,rgba(90,247,142,.07),transparent);padding:15px 18px;margin-bottom:18px",
                            span { style: "display:inline-flex;align-items:center;justify-content:center;width:34px;height:34px;border-radius:9px;background:rgba(90,247,142,.13);flex:none",
                                svg { view_box: "0 0 24 24", width: "18", height: "18", fill: "none", stroke: "var(--green)", stroke_width: "2", stroke_linecap: "round", stroke_linejoin: "round",
                                    path { d: "M20 6L9 17l-5-5" }
                                }
                            }
                            div { style: "flex:1",
                                div { style: "font-size:13.5px;font-weight:700;color:var(--green)", "✓ Hash chain intact — {v.length} events" }
                                div { style: "font-size:12px;color:var(--dim);margin-top:1px;font-family:'IBM Plex Mono',monospace", "append-only · every line hash-chained · nothing has been altered" }
                            }
                        }
                    },
                    Some(Some(v)) => {
                        let seq = v.broken_seq.map(|s| s.to_string()).unwrap_or_else(|| "?".to_string());
                        let detail = v.detail.clone().unwrap_or_else(|| "the chain does not verify".to_string());
                        rsx! {
                            div { style: "display:flex;align-items:center;gap:14px;border:1px solid rgba(255,93,93,.4);border-radius:12px;background:linear-gradient(90deg,rgba(255,93,93,.08),transparent);padding:15px 18px;margin-bottom:18px",
                                span { style: "display:inline-flex;align-items:center;justify-content:center;width:34px;height:34px;border-radius:9px;background:rgba(255,93,93,.14);flex:none;font-size:18px", "⛔" }
                                div { style: "flex:1",
                                    div { style: "font-size:13.5px;font-weight:700;color:var(--red)", "⛔ Broken at #{seq}: {detail}" }
                                    div { style: "font-size:12px;color:var(--dim);margin-top:1px", "The append-only log no longer verifies — investigate before trusting later rows." }
                                }
                            }
                        }
                    },
                    Some(None) => rsx! {
                        div { style: "display:flex;align-items:center;gap:14px;border:1px solid var(--line);border-radius:12px;background:var(--panel);padding:15px 18px;margin-bottom:18px",
                            span { style: "display:inline-flex;align-items:center;justify-content:center;width:34px;height:34px;border-radius:9px;background:var(--panel2);flex:none;font-size:16px;color:var(--dim)", "◌" }
                            div { style: "flex:1",
                                div { style: "font-size:13.5px;font-weight:700;color:var(--dim)", "Chain status unavailable" }
                                div { style: "font-size:12px;color:var(--dim);margin-top:1px", "Couldn't read the log to verify it right now — the engine may be offline." }
                            }
                        }
                    },
                    None => rsx! {
                        div { style: "display:flex;align-items:center;gap:14px;border:1px solid var(--line);border-radius:12px;background:var(--panel);padding:15px 18px;margin-bottom:18px",
                            span { style: "display:inline-flex;align-items:center;justify-content:center;width:34px;height:34px;border-radius:9px;background:var(--panel2);flex:none;font-size:16px;color:var(--dim)", "◌" }
                            div { style: "flex:1",
                                div { style: "font-size:13.5px;font-weight:700;color:var(--dim)", "Verifying the chain…" }
                                div { style: "font-size:12px;color:var(--dim);margin-top:1px", "Re-reading the append-only log to confirm nothing has been altered." }
                            }
                        }
                    },
                }
            }

            // ── intro line: what this lens shows ─────────────────────────
            div { style: "display:flex;align-items:center;gap:10px;margin-bottom:14px;font-size:12.5px;color:var(--dim)",
                svg { view_box: "0 0 24 24", width: "15", height: "15", fill: "none", stroke: "var(--gold)", stroke_width: "1.7", stroke_linecap: "round", stroke_linejoin: "round", style: "flex:none",
                    path { d: "M12 3l7 3v5c0 4-3 7-7 9-4-2-7-5-7-9V6z" }
                    path { d: "M9 11.5l2 2 4-4" }
                }
                if has_query {
                    span { "Searching the full record — every logged command and agent." }
                } else {
                    span { "History — only what Kintsugi held or blocked (Activity shows everything). Search to widen to the full record." }
                }
            }

            // ── search ───────────────────────────────────────────────────
            div { style: "position:relative;margin-bottom:16px;max-width:340px",
                svg { view_box: "0 0 24 24", width: "15", height: "15", fill: "none", stroke: "var(--dim)", stroke_width: "1.8", stroke_linecap: "round", stroke_linejoin: "round", style: "position:absolute;left:11px;top:50%;transform:translateY(-50%)",
                    circle { cx: "11", cy: "11", r: "7" }
                    path { d: "M21 21l-4-4" }
                }
                input { class: "kn-input", value: "{search}", placeholder: "Search history by command or agent…",
                    style: "width:100%;height:34px;box-sizing:border-box;border-radius:8px;border:1px solid var(--line);background:var(--panel);color:var(--ink);padding:0 12px 0 33px;font-family:inherit;font-size:12.5px;outline:none",
                    oninput: move |e| search.set(e.value()),
                }
            }

            // ── table ────────────────────────────────────────────────────
            div { style: "border:1px solid var(--line);border-radius:12px;background:var(--panel);overflow:hidden",
                div { style: "display:grid;{cols};gap:14px;padding:11px 18px;border-bottom:1px solid var(--line);font-size:10.5px;font-weight:600;letter-spacing:.6px;color:var(--dim);text-transform:uppercase",
                    span { "Time" } span { "Command" } span { "Agent" } span { "Class" }
                    span { style: "text-align:right", "Decision" }
                }
                for r in rows.iter() {
                    {
                        let key = audit_outcome_key(&r.outcome);
                        let (glyph, color) = decision(key);
                        let cls_st = audit_class_style(&r.class);
                        let detail_row = r.clone();
                        rsx! {
                            div { style: "display:grid;{cols};gap:14px;padding:12px 18px;border-bottom:1px solid var(--hair);align-items:center;cursor:pointer",
                                onclick: move |_| store.detail.set(Some(detail_row.clone())),
                                TimeCell { ts: r.ts.clone() }
                                span { style: "font-family:'IBM Plex Mono',monospace;font-size:12.5px;color:var(--ink);min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap", "{r.command}" }
                                span { style: "font-size:12.5px;color:var(--dim)", "{r.agent}" }
                                span {
                                    span { style: "font-size:11px;font-weight:600;border:1px solid var(--line);border-radius:6px;padding:3px 9px;{cls_st}", "{r.class}" }
                                }
                                span { style: "display:inline-flex;align-items:center;gap:6px;justify-content:flex-end;font-size:12.5px;font-weight:600;color:{color}", "{glyph} {key}" }
                            }
                        }
                    }
                }
                if loading {
                    Loader { label: "Loading history…".to_string() }
                } else if total == 0 {
                    div { style: "padding:40px 18px;text-align:center",
                        div { style: "font-size:24px;margin-bottom:8px;color:var(--dim)", "🗂" }
                        if has_query {
                            div { style: "font-size:13.5px;color:var(--ink);font-weight:600", "No events match your search" }
                            div { style: "font-size:12.5px;color:var(--dim);margin-top:4px", "Try a different command or agent name." }
                        } else {
                            div { style: "font-size:13.5px;color:var(--ink);font-weight:600", "Nothing destructive on the record" }
                            div { style: "font-size:12.5px;color:var(--dim);margin-top:4px;max-width:380px;margin-left:auto;margin-right:auto;line-height:1.5", "No non-safe command has run yet. When an agent attempts something that needs scrutiny, it lands here — hash-chained and tamper-evident. Search to see the full record." }
                        }
                    }
                }
                div { style: "display:flex;align-items:center;gap:12px;padding:12px 18px;border-top:1px solid var(--line)",
                    span { style: "font-size:12px;color:var(--dim)",
                        if total == 0 {
                            "No matching events"
                        } else if has_query {
                            "{total} event(s) · full record · newest first"
                        } else {
                            "{total} held or blocked · newest first"
                        }
                    }
                    if pages > 1 {
                        div { style: "margin-left:auto;display:flex;align-items:center;gap:9px",
                            span { style: "font-size:12px;color:var(--dim)", "Page {page_n} of {pages}" }
                            button { class: "kn-btn-ghost", style: "font-family:inherit;font-size:12px;font-weight:600;color:var(--ink);background:var(--panel2);border:1px solid var(--line);border-radius:7px;padding:6px 11px;cursor:pointer",
                                onclick: move |_| { if page_n > 1 { page.set(page_n - 1); } }, "‹ Prev" }
                            button { class: "kn-btn-ghost", style: "font-family:inherit;font-size:12px;font-weight:600;color:var(--ink);background:var(--panel2);border:1px solid var(--line);border-radius:7px;padding:6px 11px;cursor:pointer",
                                onclick: move |_| { if page_n < pages { page.set(page_n + 1); } }, "Next ›" }
                        }
                    }
                    span { style: "margin-left:{footer_ml};display:inline-flex;align-items:center;gap:6px;font-size:11.5px;color:var(--gold)",
                        svg { view_box: "0 0 24 24", width: "12", height: "12", fill: "none", stroke: "currentColor", stroke_width: "1.8", stroke_linecap: "round", stroke_linejoin: "round",
                            rect { x: "4", y: "11", width: "16", height: "9", rx: "2" }
                            path { d: "M8 11V8a4 4 0 0 1 8 0v3" }
                        }
                        "append-only · cannot be edited"
                    }
                }
            }
        }
    }
}
// (uses the shared `clock` helper at the top of the module)

/// One candidate session for the provenance left rail: the session id plus the
/// command and timestamp that drew our attention to it.
#[derive(Clone, PartialEq)]
struct ProvCandidate {
    session: String,
    command: String,
    ts: String,
    tainted: bool,
}

/// De-dupe rows by session (newest-first), keeping only the ones this view is
/// about: commands where a taint-driven rule actually fired (`provenance_block`,
/// i.e. a `TRIFECTA-*` reason). The screen's promise is "how untrusted content
/// reached a risky command" — a session that merely has an id but never ingested
/// anything untrusted is *not* provenance, so it doesn't belong in the rail (and
/// picking its newest, non-trifecta command is what produced the misleading
/// "carries a label / no trail" state). Shared by the left rail and the
/// default-selection effect so they never disagree.
fn prov_candidates(rows: &[crate::bindings::TimelineRow]) -> Vec<ProvCandidate> {
    let mut candidates: Vec<ProvCandidate> = Vec::new();
    for r in rows.iter() {
        if !r.provenance_block {
            continue;
        }
        let Some(session) = r.session.clone() else {
            continue;
        };
        if candidates.iter().any(|c| c.session == session) {
            continue;
        }
        candidates.push(ProvCandidate {
            session,
            command: r.command.clone(),
            ts: r.ts.clone(),
            tainted: true,
        });
    }
    candidates
}

/// "Where it came from." The left rail lists sessions whose commands were
/// taint-driven blocks (or simply carry a session id); selecting one pulls its
/// ordered provenance trail and renders it with the gold-seam connector —
/// the terminal rule step earns the single danger accent.
#[component]
pub fn Provenance() -> Element {
    let store = use_store();
    // Agent rows (fs-watch excluded so its firehose can't evict real tainted
    // sessions from the window), read off the UI thread on the slow tick.
    let rows_res = use_resource(move || async move {
        let _ = store.slow_tick.read();
        tokio::task::spawn_blocking(|| crate::bindings::commands(200))
            .await
            .unwrap_or_default()
    });
    let rows = rows_res().unwrap_or_default();
    let candidates = prov_candidates(&rows);

    // Selected (session, command). Default to the first candidate via an effect
    // (never a write-during-render), keyed on the rows resource so it seeds once
    // data arrives and leaves an explicit user pick alone.
    let mut selected = use_signal(|| None::<(String, String)>);
    use_effect(move || {
        let rows = rows_res().unwrap_or_default();
        if selected.peek().is_none() {
            if let Some(c) = prov_candidates(&rows).into_iter().next() {
                selected.set(Some((c.session, c.command)));
            }
        }
    });

    // The ordered trail for the selected session — fetched OFF the render thread
    // (a daemon IPC) and re-run only when the selection changes.
    let trail_res = use_resource(move || async move {
        let pick = selected.read().clone();
        match pick {
            Some((s, cmd)) => {
                tokio::task::spawn_blocking(move || crate::bindings::provenance(&s, Some(&cmd)))
                    .await
                    .ok()
                    .flatten()
            }
            None => None,
        }
    });

    // Calm empty state: nothing untrusted-influenced was ever seen.
    if candidates.is_empty() {
        return rsx! {
            div { style: "padding:26px;{FADE}",
                div { style: "border:1px solid rgba(90,247,142,.3);border-radius:14px;background:linear-gradient(100deg,rgba(90,247,142,.07),transparent);padding:40px 30px;text-align:center",
                    span { style: "display:inline-flex;align-items:center;justify-content:center;width:52px;height:52px;border-radius:14px;background:rgba(90,247,142,.13);margin-bottom:16px",
                        svg { view_box: "0 0 24 24", width: "26", height: "26", fill: "none", stroke: "var(--green)", stroke_width: "1.7", stroke_linecap: "round", stroke_linejoin: "round",
                            path { d: "M12 3l7 3v5c0 4-3 7-7 9-4-2-7-5-7-9V6z M9 12l2 2 4-4" }
                        }
                    }
                    div { style: "font-size:18px;font-weight:700;letter-spacing:-.2px", "✓ Nothing untrusted reached a command" }
                    div { style: "font-size:13.5px;color:var(--dim);margin-top:8px;line-height:1.55;max-width:520px;margin-left:auto;margin-right:auto",
                        "No command was causally influenced by untrusted content. When an agent reads from the web, an issue, or another tainted source and that data flows toward a sensitive read or egress, the whole path will show up here — source to sink."
                    }
                }
            }
        };
    }

    let sel_session = selected.read().as_ref().map(|(s, _)| s.clone());

    rsx! {
        div { style: "padding:26px;{FADE}",
            // header card — matches the design's provenance intro
            div { style: "border:1px solid var(--line);border-radius:12px;background:var(--panel);padding:16px 18px;margin-bottom:18px;display:flex;align-items:center;gap:13px",
                svg { view_box: "0 0 24 24", width: "18", height: "18", fill: "none", stroke: "var(--gold)", stroke_width: "1.7", stroke_linecap: "round", stroke_linejoin: "round",
                    circle { cx: "6", cy: "11", r: "2.2" }
                    circle { cx: "18", cy: "5", r: "2.2" }
                    circle { cx: "18", cy: "19", r: "2.2" }
                    path { d: "M8 10l8-4M8 12l8 6" }
                }
                div { style: "flex:1",
                    div { style: "font-size:13.5px;font-weight:700", "Trust-zone flow" }
                    div { style: "font-size:12px;color:var(--dim);margin-top:1px", "How untrusted content reached a risky command. The highlighted step is the trifecta that fired." }
                }
                span { style: "font-family:'IBM Plex Mono',monospace;font-size:11.5px;color:var(--dim)", "[provenance] · {candidates.len()} session(s)" }
            }

            div { style: "display:grid;grid-template-columns:300px minmax(0,1fr);gap:18px;align-items:start",

                // ── left rail: tainted sessions ──
                div { style: "border:1px solid var(--line);border-radius:12px;background:var(--panel);overflow:hidden",
                    div { style: "padding:11px 16px;border-bottom:1px solid var(--line);font-size:10.5px;font-weight:600;letter-spacing:.6px;color:var(--dim);text-transform:uppercase",
                        "Sessions"
                    }
                    for c in candidates.iter().cloned() {
                        {
                            let active = sel_session.as_deref() == Some(c.session.as_str());
                            let row_st = if active {
                                "border-color:var(--gold-line);background:rgba(212,175,55,.06)"
                            } else {
                                "border-color:transparent;background:transparent"
                            };
                            let sess = c.session.clone();
                            let cmd = c.command.clone();
                            let time = clock(&c.ts);
                            rsx! {
                                button {
                                    style: "width:100%;text-align:left;font-family:inherit;display:block;padding:13px 16px;border:none;border-left:2px solid transparent;border-bottom:1px solid var(--hair);cursor:pointer;{row_st}",
                                    onclick: move |_| selected.set(Some((sess.clone(), cmd.clone()))),
                                    div { style: "display:flex;align-items:center;gap:8px",
                                        if c.tainted {
                                            span { style: "font-size:11.5px;font-weight:600;color:var(--amber);display:inline-flex;align-items:center;gap:4px", "⚠ tainted" }
                                        } else {
                                            span { style: "font-size:11.5px;font-weight:600;color:var(--dim);display:inline-flex;align-items:center;gap:4px", "• session" }
                                        }
                                        span { style: "margin-left:auto;font-family:'IBM Plex Mono',monospace;font-size:11px;color:var(--dim);white-space:nowrap", "{time}" }
                                    }
                                    div { style: "font-family:'IBM Plex Mono',monospace;font-size:12px;font-weight:600;color:var(--ink);margin-top:6px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap", "{c.session}" }
                                    div { style: "font-family:'IBM Plex Mono',monospace;font-size:11.5px;color:var(--dim);margin-top:4px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap", "{c.command}" }
                                }
                            }
                        }
                    }
                }

                // ── right pane: the ordered trail for the selected session ──
                {
                    let chosen = sel_session
                        .as_ref()
                        .and_then(|s| candidates.iter().find(|c| &c.session == s).cloned());
                    match chosen {
                        Some(c) => {
                            // Resolved off the render thread by `trail_res` (keyed on the
                            // selection); `None` until the daemon round-trip lands.
                            let view = trail_res().flatten();
                            rsx! {
                                div { style: "border:1px solid var(--line);border-radius:12px;background:var(--panel);padding:20px 22px",
                                    div { style: "display:flex;align-items:center;gap:10px;margin-bottom:4px",
                                        span { style: "font-family:'IBM Plex Mono',monospace;font-size:13.5px;font-weight:700;color:var(--ink)", "{c.session}" }
                                        if c.tainted {
                                            span { style: "font-size:11px;font-weight:600;color:var(--amber);border:1px solid var(--gold-line);border-radius:6px;padding:3px 8px", "⚠ tainted" }
                                        }
                                    }
                                    div { style: "font-family:'IBM Plex Mono',monospace;font-size:12.5px;color:var(--dim);margin-bottom:6px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap", "{c.command}" }
                                    div { style: "font-size:11px;color:var(--dim);text-transform:uppercase;letter-spacing:.5px;margin:18px 0 4px", "Provenance trail — source to sink" }

                                    {
                                        match view {
                                            Some(v) if !v.trail.is_empty() => {
                                                let last = v.trail.len() - 1;
                                                rsx! {
                                                    div { style: "position:relative;padding:8px 0 2px",
                                                        // the gold seam connector
                                                        div { style: "position:absolute;left:13px;top:22px;bottom:30px;width:2px;background:linear-gradient(var(--gold-bright),var(--gold),var(--red));border-radius:2px" }
                                                        for (i, step) in v.trail.iter().enumerate() {
                                                            {
                                                                let (glyph, label) = step.glyph_label();
                                                                let value = step.value().to_string();
                                                                let is_rule = step.is_rule();
                                                                let terminal = i == last;
                                                                let dot_st = if is_rule {
                                                                    "background:rgba(255,93,93,.16);color:var(--red)"
                                                                } else if terminal {
                                                                    "background:rgba(212,175,55,.16);color:var(--gold)"
                                                                } else {
                                                                    "background:var(--panel2);color:var(--gold-bright)"
                                                                };
                                                                let title_st = if is_rule { "color:var(--red)" } else { "color:var(--ink)" };
                                                                rsx! {
                                                                    div { style: "display:flex;gap:16px;padding:9px 0;position:relative",
                                                                        span { style: "flex:none;width:28px;height:28px;border-radius:50%;display:inline-flex;align-items:center;justify-content:center;border:2px solid var(--bg);z-index:1;font-size:14px;font-weight:700;{dot_st}", "{glyph}" }
                                                                        div { style: "flex:1;padding-top:2px",
                                                                            div { style: "font-size:13.5px;font-weight:600;{title_st}", "{label}" }
                                                                            div { style: "font-size:12.5px;color:var(--dim);margin-top:2px;font-family:'IBM Plex Mono',monospace;overflow:hidden;text-overflow:ellipsis", "{value}" }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }

                                                    // closing rationale banner — only when the trail terminated in a rule
                                                    if v.trail.last().map(|s| s.is_rule()).unwrap_or(false) {
                                                        div { style: "margin-top:18px;border:1px solid rgba(255,93,93,.3);border-radius:12px;background:linear-gradient(90deg,rgba(255,93,93,.08),transparent);padding:15px 18px;display:flex;align-items:center;gap:14px",
                                                            span { style: "font-size:18px", "⛔" }
                                                            div { style: "flex:1;font-size:13px;line-height:1.5",
                                                                "This path satisfies all three trifecta conditions — untrusted input, a sensitive read, and an egress sink. "
                                                                span { style: "color:var(--dim)", "Coarse source-level taint is sound but over-approximate; tune sources in Rules if this is a false positive." }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                            // Tainted session, but this particular command has no
                                            // source→sink legs to chart (e.g. a later, safe command).
                                            Some(v) if v.tainted => rsx! {
                                                div { style: "padding:30px 8px;text-align:center",
                                                    div { style: "font-size:14px;font-weight:600;color:var(--ink)", "◌ No trail for this command" }
                                                    div { style: "font-size:12.5px;color:var(--dim);margin-top:6px;line-height:1.5;max-width:440px;margin-left:auto;margin-right:auto",
                                                        "This session is tainted, but the selected command has no untrusted-read → sink legs of its own. Pick the trifecta command to see the full chain."
                                                    }
                                                }
                                            },
                                            // Clean session — say so plainly; don't claim a label it doesn't have.
                                            Some(_) => rsx! {
                                                div { style: "padding:30px 8px;text-align:center",
                                                    div { style: "font-size:14px;font-weight:600;color:var(--green)", "✓ Nothing untrusted" }
                                                    div { style: "font-size:12.5px;color:var(--dim);margin-top:6px;line-height:1.5;max-width:440px;margin-left:auto;margin-right:auto",
                                                        "No untrusted content has touched this session — there's no provenance trail to show."
                                                    }
                                                }
                                            },
                                            // Daemon round-trip hasn't landed (or failed) yet.
                                            None => rsx! {
                                                div { style: "padding:30px 8px;text-align:center;color:var(--dim);font-size:12.5px", "Loading the provenance trail…" }
                                            },
                                        }
                                    }
                                }
                            }
                        }
                        None => rsx! {
                            div { style: "border:1px solid var(--line);border-radius:12px;background:var(--panel);padding:34px;text-align:center;font-size:13px;color:var(--dim)",
                                "◌ Select a session to see how untrusted content reached its command."
                            }
                        }
                    }
                }
            }
        }
    }
}
#[component]
pub fn Recorder() -> Element {
    let mut store = use_store();

    // Live, off the UI thread: the passive human-shell recorder (agent=="shell"),
    // fetched via the dedicated section read inside spawn_blocking so the heavy
    // log scan never blocks rendering. Refreshes on the fast tick.
    let res = use_resource(move || async move {
        let _ = store.tick.read();
        tokio::task::spawn_blocking(|| crate::bindings::shell_log(200))
            .await
            .unwrap_or_default()
    });
    let shell: Vec<crate::bindings::TimelineRow> = res().unwrap_or_default();

    // Search over command text (reuses the Feed search signal).
    let search = store.feed_search.read().to_lowercase();
    let filtered: Vec<crate::bindings::TimelineRow> = shell
        .iter()
        .filter(|r| search.is_empty() || r.command.to_lowercase().contains(&search))
        .cloned()
        .collect();

    // Pagination over the filtered rows (newest-first).
    let mut page = use_signal(|| 1usize);
    let f_total = filtered.len();
    let pages = ((f_total + FEED_PAGE_SIZE - 1) / FEED_PAGE_SIZE).max(1);
    let page_n = (*page.read()).min(pages).max(1);
    let pstart = (page_n - 1) * FEED_PAGE_SIZE;
    let pend = (pstart + FEED_PAGE_SIZE).min(f_total);
    let page_rows = filtered[pstart..pend].to_vec();
    let footer_ml2 = if pages > 1 { "20px" } else { "auto" };

    // Live metric tiles derived from the shell rows.
    let total = shell.len();
    let destructive = shell.iter().filter(|r| r.class == "catastrophic").count();
    let held = shell.iter().filter(|r| r.outcome == "held").count();
    let blocked = shell.iter().filter(|r| r.outcome == "denied").count();

    let metrics: [(&str, String, &str, &str); 4] = [
        (
            "Captured",
            total.to_string(),
            "color:var(--ink)",
            "commands on the chain",
        ),
        (
            "Destructive",
            destructive.to_string(),
            if destructive > 0 {
                "color:var(--red)"
            } else {
                "color:var(--ink)"
            },
            "rm / drop / overwrite",
        ),
        (
            "Held",
            held.to_string(),
            if held > 0 {
                "color:var(--amber)"
            } else {
                "color:var(--ink)"
            },
            "paused for review",
        ),
        (
            "Blocked",
            blocked.to_string(),
            if blocked > 0 {
                "color:var(--red)"
            } else {
                "color:var(--ink)"
            },
            "stopped before running",
        ),
    ];

    // Right-column capture sources (static posture rows from the design).
    let sources: [(&str, &str, &str, &str, &str); 3] = [
        (
            "$PATH shim",
            "active",
            "color:var(--green)",
            "background:var(--green)",
            "catches raw shell-outs & obfuscated execs the hook can't see",
        ),
        (
            "kintsugi record · PTY",
            "on demand",
            "color:var(--amber)",
            "background:var(--amber)",
            "higher-assurance logged shell, survives inner-hook tampering",
        ),
        (
            "auditd / eBPF",
            "root floor",
            "color:var(--dim)",
            "background:var(--dim)",
            "kernel-level attribution via auid through sudo/su",
        ),
    ];

    let cols = "grid-template-columns:64px 150px 1fr 110px;gap:14px";

    rsx! {
        div { style: "padding:26px;{FADE}",

            // ── gold "passive recorder active" banner ──
            div { style: "display:flex;align-items:center;gap:14px;border:1px solid var(--gold-line);border-radius:12px;background:linear-gradient(100deg,rgba(212,175,55,.06),transparent);padding:15px 18px;margin-bottom:18px",
                span { style: "display:inline-flex;align-items:center;justify-content:center;width:38px;height:38px;border-radius:10px;background:rgba(212,175,55,.13);flex:none",
                    svg { view_box: "0 0 24 24", width: "20", height: "20", fill: "none", stroke: "var(--gold)", stroke_width: "1.7", stroke_linecap: "round", stroke_linejoin: "round",
                        rect { x: "4", y: "5", width: "16", height: "14" }
                        path { d: "M7.5 9.5l2.5 2.5-2.5 2.5M13 15h3.5" }
                    }
                }
                div { style: "flex:1",
                    div { style: "font-size:14px;font-weight:700", "Passive recorder active · system-wide" }
                    div { style: "font-size:12.5px;color:var(--dim);margin-top:2px",
                        "Every command a human runs lands on the same tamper-evident log — no AI agent required. The daemon runs as a dedicated "
                        span { style: "font-family:'IBM Plex Mono',monospace", "kintsugi" }
                        " system account the audited user can't disable."
                    }
                }
                span { style: "font-size:11.5px;font-weight:600;color:var(--green);border:1px solid rgba(90,247,142,.3);border-radius:7px;padding:6px 11px;white-space:nowrap;display:inline-flex;align-items:center;gap:6px",
                    span { style: "width:7px;height:7px;border-radius:50%;background:var(--green);animation:kpulse 2s infinite" }
                    "recording"
                }
            }

            // ── metric tiles ──
            div { style: "display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:16px",
                for (label, value, val_color, note) in metrics {
                    div { style: "border:1px solid var(--line);border-radius:12px;padding:16px 17px;background:var(--panel)",
                        div { style: "font-size:11.5px;font-weight:600;letter-spacing:.4px;color:var(--dim);text-transform:uppercase", "{label}" }
                        div { style: "font-size:28px;font-weight:700;margin-top:7px;font-family:'IBM Plex Mono',monospace;letter-spacing:-.5px;{val_color}", "{value}" }
                        div { style: "font-size:11.5px;color:var(--dim);margin-top:3px", "{note}" }
                    }
                }
            }

            // ── table + right column ──
            div { style: "display:grid;grid-template-columns:1.55fr 1fr;gap:16px",

                // human commands table
                div { style: "border:1px solid var(--line);border-radius:12px;background:var(--panel);overflow:hidden",
                    div { style: "display:flex;align-items:center;gap:10px;padding:11px 17px;border-bottom:1px solid var(--line)",
                        span { style: "font-size:13.5px;font-weight:700", "Human terminal commands" }
                        div { style: "margin-left:auto;position:relative;width:170px",
                            svg { view_box: "0 0 24 24", width: "13", height: "13", fill: "none", stroke: "var(--dim)", stroke_width: "1.8", stroke_linecap: "round", stroke_linejoin: "round", style: "position:absolute;left:9px;top:50%;transform:translateY(-50%)",
                                circle { cx: "11", cy: "11", r: "7" }
                                path { d: "M21 21l-4-4" }
                            }
                            input { class: "kn-input", value: "{store.feed_search}", placeholder: "Search…",
                                style: "width:100%;height:30px;box-sizing:border-box;border-radius:7px;border:1px solid var(--line);background:var(--panel2);color:var(--ink);padding:0 10px 0 28px;font-family:inherit;font-size:12px",
                                oninput: move |e| store.feed_search.set(e.value()),
                            }
                        }
                    }
                    div { style: "display:grid;{cols};padding:10px 17px;border-bottom:1px solid var(--line);font-size:10px;font-weight:600;letter-spacing:.5px;color:var(--dim);text-transform:uppercase",
                        span { "Time" } span { "Class" } span { "Command" }
                        span { style: "text-align:right", "Decision" }
                    }

                    if filtered.is_empty() {
                        // Designed empty state — the recorder logs your typed
                        // commands with no AI agent in the loop.
                        div { style: "padding:38px 22px;text-align:center",
                            span { style: "display:inline-flex;align-items:center;justify-content:center;width:46px;height:46px;border-radius:12px;background:rgba(212,175,55,.1);margin-bottom:12px",
                                svg { view_box: "0 0 24 24", width: "22", height: "22", fill: "none", stroke: "var(--gold)", stroke_width: "1.6", stroke_linecap: "round", stroke_linejoin: "round",
                                    rect { x: "4", y: "5", width: "16", height: "14" }
                                    path { d: "M7.5 9.5l2.5 2.5-2.5 2.5M13 15h3.5" }
                                }
                            }
                            div { style: "font-size:14px;font-weight:700;color:var(--ink)",
                                if search.is_empty() { "Nothing typed yet" } else { "No commands match your search" }
                            }
                            div { style: "font-size:12.5px;color:var(--dim);margin-top:6px;line-height:1.55;max-width:380px;margin-left:auto;margin-right:auto",
                                if search.is_empty() {
                                    "The recorder logs what you type in the terminal — even with no AI agent running. Open a shell and the commands you run will appear here, hashed onto the tamper-evident chain."
                                } else {
                                    "Try a different command, or clear the search to see every recorded line."
                                }
                            }
                        }
                    } else {
                        for r in page_rows.iter().cloned() {
                            {
                                let mapped = if r.outcome == "denied" { "blocked" } else { r.outcome.as_str() };
                                let (glyph, color) = decision(mapped);
                                let (class_label, class_st) = crate::data::risk_style(&r.class);
                                let host = r.session.clone().unwrap_or_else(|| "local shell".to_string());
                                let detail_row = r.clone();
                                rsx! {
                                    div { style: "display:grid;{cols};padding:12px 17px;border-bottom:1px solid var(--hair);align-items:center;cursor:pointer",
                                        onclick: move |_| store.detail.set(Some(detail_row.clone())),
                                        TimeCell { ts: r.ts.clone() }
                                        span {
                                            if class_label.is_empty() {
                                                span { style: "font-size:11.5px;color:var(--dim)", "—" }
                                            } else {
                                                span { style: "font-size:11px;font-weight:600;border-radius:6px;padding:3px 9px;{class_st}", "{class_label}" }
                                            }
                                        }
                                        span { style: "min-width:0",
                                            span { style: "display:block;font-family:'IBM Plex Mono',monospace;font-size:12px;color:var(--ink);overflow:hidden;text-overflow:ellipsis;white-space:nowrap", "{r.command}" }
                                            // The model's plain-English summary, when it scored this row.
                                            if let Some(s) = r.summary.clone().filter(|s| !s.is_empty()) {
                                                span { style: "display:block;font-size:11px;color:var(--gold);margin-top:2px;line-height:1.4;overflow:hidden;text-overflow:ellipsis;white-space:nowrap",
                                                    title: "{s}",
                                                    "✦ {s}"
                                                }
                                            }
                                            span { style: "font-size:11px;color:var(--dim);font-family:'IBM Plex Mono',monospace", "{host}" }
                                        }
                                        span { style: "display:inline-flex;align-items:center;gap:6px;justify-content:flex-end;font-size:12px;font-weight:600;color:{color}", "{glyph} {mapped}" }
                                    }
                                }
                            }
                        }
                        div { style: "display:flex;align-items:center;gap:12px;padding:11px 17px;border-top:1px solid var(--line)",
                            span { style: "font-size:11.5px;color:var(--dim)", "{filtered.len()} of {shell.len()} recorded" }
                            if pages > 1 {
                                div { style: "margin-left:auto;display:flex;align-items:center;gap:9px",
                                    span { style: "font-size:12px;color:var(--dim)", "Page {page_n} of {pages}" }
                                    button { class: "kn-btn-ghost", style: "font-family:inherit;font-size:12px;font-weight:600;color:var(--ink);background:var(--panel2);border:1px solid var(--line);border-radius:7px;padding:6px 11px;cursor:pointer",
                                        onclick: move |_| { if page_n > 1 { page.set(page_n - 1); } }, "‹ Prev" }
                                    button { class: "kn-btn-ghost", style: "font-family:inherit;font-size:12px;font-weight:600;color:var(--ink);background:var(--panel2);border:1px solid var(--line);border-radius:7px;padding:6px 11px;cursor:pointer",
                                        onclick: move |_| { if page_n < pages { page.set(page_n + 1); } }, "Next ›" }
                                }
                            }
                            span { style: "margin-left:{footer_ml2};display:inline-flex;align-items:center;gap:7px;font-size:11.5px;color:var(--dim)",
                                span { style: "display:inline-flex;width:7px;height:7px;border-radius:50%;background:var(--green);animation:kpulse 1.6s infinite" }
                                "tamper-evident · hashed in order"
                            }
                        }
                    }
                }

                // right column: capture sources + redaction + coverage
                div { style: "display:flex;flex-direction:column;gap:16px",
                    div { style: "border:1px solid var(--line);border-radius:12px;background:var(--panel);padding:16px 17px",
                        div { style: "font-size:13.5px;font-weight:700;margin-bottom:11px", "Capture sources" }
                        for (name, tag, tag_color, dot, detail) in sources {
                            div { style: "display:flex;gap:10px;padding:8px 0;border-bottom:1px solid var(--hair)",
                                span { style: "display:inline-flex;width:7px;height:7px;border-radius:50%;margin-top:5px;flex:none;{dot}" }
                                div { style: "flex:1",
                                    div { style: "font-size:12.5px;font-weight:600;display:flex;align-items:center;gap:8px",
                                        span { "{name}" }
                                        span { style: "font-size:10px;font-weight:600;{tag_color}", "· {tag}" }
                                    }
                                    div { style: "font-size:11.5px;color:var(--dim);margin-top:2px;line-height:1.4", "{detail}" }
                                }
                            }
                        }
                    }
                    div { style: "border:1px solid var(--line);border-radius:12px;background:var(--panel);padding:16px 17px",
                        div { style: "display:flex;align-items:center;gap:8px;margin-bottom:6px",
                            svg { view_box: "0 0 24 24", width: "15", height: "15", fill: "none", stroke: "var(--green)", stroke_width: "1.8", stroke_linecap: "round", stroke_linejoin: "round",
                                rect { x: "4", y: "11", width: "16", height: "9", rx: "2" }
                                path { d: "M8 11V8a4 4 0 0 1 8 0v3" }
                            }
                            span { style: "font-size:13.5px;font-weight:700", "Secret redaction" }
                        }
                        div { style: "font-size:12px;color:var(--dim);line-height:1.5",
                            "Values are redacted at the source — before the line is hashed — leaving a "
                            span { style: "font-family:'IBM Plex Mono',monospace;color:var(--amber)", "‹redacted›" }
                            " marker. The audit log can never itself become the breach."
                        }
                    }
                    div { style: "border:1px solid var(--line);border-radius:12px;background:var(--panel);padding:16px 17px",
                        div { style: "font-size:13.5px;font-weight:700;margin-bottom:6px", "Honest coverage" }
                        div { style: "font-size:12px;color:var(--dim);line-height:1.5",
                            "A userspace recorder is evadable — "
                            span { style: "font-family:'IBM Plex Mono',monospace;color:var(--ink)", "bash --norc" }
                            ", absolute-path execs, commands inside "
                            span { style: "font-family:'IBM Plex Mono',monospace;color:var(--ink)", "psql \\!" }
                            ". Attribution follows "
                            span { style: "font-family:'IBM Plex Mono',monospace;color:var(--ink)", "auid" }
                            " through sudo/su; auditd/eBPF is the root-backed floor we integrate with, not reimplement."
                        }
                    }
                }
            }
        }
    }
}
#[component]
pub fn Snapshots() -> Element {
    let store = use_store();
    // Local re-fetch tick: bumped after a successful undo so the list reloads.
    let mut tick = use_signal(|| 0u32);

    let rows = use_resource(move || async move {
        let _ = tick(); // subscribe: a tick change re-runs this resource
        let _ = store.slow_tick.read(); // live refresh (undo is infrequent)
        tokio::task::spawn_blocking(crate::bindings::snapshots)
            .await
            .unwrap_or_default()
    });
    let loading = rows().is_none();
    let rows = rows().unwrap_or_default();
    let count = rows.len();

    rsx! {
        div { style: "padding:26px;{FADE}",

            // The honest promise — copied from the design's undo intro.
            div { style: "font-size:13px;color:var(--dim);margin-bottom:16px;line-height:1.5;max-width:760px",
                "Kintsugi snapshots files before any destructive op — reflink copy-on-write where the filesystem supports it. The honest promise is "
                b { style: "color:var(--ink)", "nothing unrecoverable" }
                ": every restore point below is one click from rollback."
            }

            if loading {
                Loader { label: "Loading restore points…".to_string() }
            } else if count == 0 {
                // Designed empty state — inviting, never blank.
                div { style: "border:1px solid var(--line);border-radius:14px;background:var(--panel);padding:40px 30px;text-align:center",
                    span { style: "display:inline-flex;align-items:center;justify-content:center;width:54px;height:54px;border-radius:14px;background:rgba(212,175,55,.12);margin-bottom:16px",
                        svg { view_box: "0 0 24 24", width: "26", height: "26", fill: "none", stroke: "var(--gold)", stroke_width: "1.6", stroke_linecap: "round", stroke_linejoin: "round",
                            // counter-clockwise undo arc
                            path { d: "M4 12a8 8 0 1 1 2.4 5.7 M4 18v-4h4 M12 8.5v4l3 1.8" }
                        }
                    }
                    div { style: "font-size:16px;font-weight:700;letter-spacing:-.2px", "No restore points yet" }
                    div { style: "font-size:13px;color:var(--dim);margin-top:7px;line-height:1.55;max-width:440px;margin-left:auto;margin-right:auto",
                        "Kintsugi snapshots before anything destructive. The first time an agent runs a risky file operation, a one-click rollback will appear here."
                    }
                }
            } else {
                // One card per restore point.
                div { style: "display:flex;flex-direction:column;gap:11px",
                    for s in rows {
                        {
                            let id = s.id.clone();
                            let paths = s.paths;
                            let path_word = if paths == 1 { "path" } else { "paths" };
                            rsx! {
                                div { key: "{s.id}",
                                    style: "display:flex;align-items:center;gap:15px;border:1px solid var(--line);border-radius:12px;background:var(--panel);padding:15px 18px",
                                    // restore-point glyph
                                    span { style: "display:inline-flex;align-items:center;justify-content:center;width:38px;height:38px;flex:none;border-radius:10px;background:rgba(212,175,55,.13)",
                                        svg { view_box: "0 0 24 24", width: "19", height: "19", fill: "none", stroke: "var(--gold)", stroke_width: "1.7", stroke_linecap: "round", stroke_linejoin: "round",
                                            path { d: "M4 12a8 8 0 1 1 2.4 5.7 M4 18v-4h4 M12 8.5v4l3 1.8" }
                                        }
                                    }
                                    div { style: "flex:1;min-width:0",
                                        div { style: "font-family:'IBM Plex Mono',monospace;font-size:13px;color:var(--ink);overflow:hidden;text-overflow:ellipsis;white-space:nowrap", "{s.command}" }
                                        div { style: "font-size:11.5px;color:var(--dim);margin-top:4px;display:inline-flex;align-items:center;gap:6px",
                                            svg { view_box: "0 0 24 24", width: "12", height: "12", fill: "none", stroke: "var(--green)", stroke_width: "1.9", stroke_linecap: "round", stroke_linejoin: "round", style: "flex:none",
                                                path { d: "M14 3v4a1 1 0 0 0 1 1h4 M5 21V5a2 2 0 0 1 2-2h7l5 5v13a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2z" }
                                            }
                                            "covers {paths} {path_word}"
                                        }
                                    }
                                    button { class: "kn-btn-ghost",
                                        style: "flex:none;display:inline-flex;align-items:center;gap:7px;font-family:inherit;font-size:12.5px;font-weight:600;color:var(--gold);background:transparent;border:1px solid var(--line);border-radius:8px;padding:8px 15px;cursor:pointer",
                                        onclick: move |_| {
                                            // undo returns anyhow::Result<()>; on Ok, bump tick to re-fetch. Ignore Err for now.
                                            if crate::bindings::undo(&id).is_ok() {
                                                let v = *tick.read();
                                                tick.set(v + 1);
                                            }
                                        },
                                        svg { view_box: "0 0 24 24", width: "14", height: "14", fill: "none", stroke: "currentColor", stroke_width: "1.8", stroke_linecap: "round", stroke_linejoin: "round",
                                            path { d: "M9 14L4 9l5-5 M4 9h11a5 5 0 0 1 0 10h-1" }
                                        }
                                        "Undo"
                                    }
                                }
                            }
                        }
                    }
                }

                // The honest caveat: snapshots cover files, not in-DB destruction.
                div { style: "margin-top:16px;font-size:11.5px;color:var(--dim);line-height:1.5;border-left:2px solid var(--amber);padding-left:12px;max-width:760px",
                    "⚠ File restore only. A database DROP or TRUNCATE leaves no file to roll back — those run inside the engine, not on disk, so Kintsugi holds them for your review rather than promising an undo."
                }
            }
        }
    }
}
#[component]
pub fn Settings() -> Element {
    let mut store = use_store();
    let theme = *store.theme.read();
    let dark_st = if theme == Theme::Dark {
        "background:var(--gold);color:#1a1206;border-color:var(--gold)"
    } else {
        "background:var(--panel2);color:var(--dim)"
    };
    let light_st = if theme == Theme::Light {
        "background:var(--gold);color:#1a1206;border-color:var(--gold)"
    } else {
        "background:var(--panel2);color:var(--dim)"
    };
    let search = store.model_search.read().to_lowercase();

    // ── refresh tick: any successful mutation bumps this so the resources re-run ──
    let mut tick = use_signal(|| 0u32);

    // ── live backend reads (every read inside spawn_blocking → never blocks UI) ──
    let status_res = use_resource(move || async move {
        let _ = tick();
        let _ = store.slow_tick.read(); // keep engine/scorer status live
        tokio::task::spawn_blocking(crate::bindings::status)
            .await
            .ok()
    });
    let status = status_res().flatten();
    let engine_running = status.as_ref().map(|s| s.running).unwrap_or(false);

    // The installed .gguf name + the plain-language scorer summary the user missed.
    let model_res = use_resource(move || async move {
        let _ = tick();
        let _ = store.slow_tick.read();
        tokio::task::spawn_blocking(|| {
            (
                crate::bindings::installed_model(),
                crate::bindings::scorer_summary(),
                crate::bindings::available_models(),
                crate::bindings::model_loaded(),
            )
        })
        .await
        .unwrap_or((None, "Engine offline".to_string(), Vec::new(), false))
    });
    let (installed_model, scorer_summary, local_models, model_active) =
        model_res().unwrap_or((None, String::new(), Vec::new(), false));
    // A selection is set but the daemon hasn't loaded THAT model yet → restart needed.
    let model_configured_not_loaded = installed_model.is_some() && !model_active;
    let mut restart_pending = use_signal(|| false);

    // ── software-update state (Settings → "Check for updates") ──
    use crate::bindings::UpdateStatus;
    let mut update_status = use_signal(|| None::<UpdateStatus>);
    let mut update_busy = use_signal(|| false); // a check OR an install is in flight

    // Whether a master-password vault exists → set vs change form.
    let vault_res = use_resource(move || async move {
        let _ = tick();
        tokio::task::spawn_blocking(crate::bindings::vault_provisioned)
            .await
            .unwrap_or(false)
    });
    let provisioned = vault_res().unwrap_or(false);

    // Fail-closed is a real config marker: read once, write on toggle.
    let fc_initial = use_resource(move || async move {
        tokio::task::spawn_blocking(crate::bindings::fail_closed)
            .await
            .unwrap_or(false)
    });
    let mut fail_closed_sig = use_signal(|| false);
    use_effect(move || {
        if let Some(v) = fc_initial() {
            fail_closed_sig.set(v);
        }
    });
    let fail_closed_on = *fail_closed_sig.read();

    // ── master-password local form state ──
    let mut pw_cur = use_signal(String::new);
    let mut pw_new = use_signal(String::new);
    let mut pw_confirm = use_signal(String::new);
    let mut pw_err = use_signal(String::new); // inline error (e.g. wrong current pw)
    let mut recovery_key = use_signal(|| None::<String>); // shown ONCE on success
    let mut pw_modal = use_signal(|| false); // the change/set-password modal
    let mut pw_remove_modal = use_signal(|| false); // the separate REMOVE-password modal
    let mut pw_remove_field = use_signal(String::new); // its own field so it can't accidentally reuse pw_cur
                                                       // Uninstall confirmation modal (password + purge + type-to-confirm).
    let mut uninst_modal = use_signal(|| false);
    let mut uninst_pw = use_signal(String::new);
    let mut uninst_purge = use_signal(|| false);
    let mut uninst_confirm = use_signal(String::new);
    let mut uninst_err = use_signal(String::new);
    let mut uninst_running = use_signal(|| false);
    let mut uninst_result = use_signal(|| None::<String>);

    // ── model action inline result ──
    let mut model_msg = use_signal(String::new);
    // Path pending a delete confirmation (two-step, so a 2GB file isn't one click).
    let mut delete_confirm = use_signal(|| None::<String>);

    // Live Hugging Face search — re-runs as the query changes; empty → suggested.
    let hf_res = use_resource(move || async move {
        let q = store.model_search.read().clone();
        tokio::task::spawn_blocking(move || crate::bindings::hf_search(&q))
            .await
            .unwrap_or_default()
    });
    let hf_loading = hf_res().is_none();
    let hf_models = hf_res().unwrap_or_default();
    // Repo ids with an in-flight download.
    let downloading = use_signal(std::collections::HashSet::<String>::new);

    // Live, REAL toggle state: the shell-recorder block and the OS service.
    let recording_res = use_resource(move || async move {
        let _ = tick();
        tokio::task::spawn_blocking(crate::bindings::recording_installed)
            .await
            .unwrap_or(false)
    });
    let recording_on = recording_res().unwrap_or(false);
    let service_res = use_resource(move || async move {
        let _ = tick();
        tokio::task::spawn_blocking(crate::bindings::service_installed)
            .await
            .unwrap_or(false)
    });
    let service_on = service_res().unwrap_or(false);

    // Detected agent CLIs + per-hook install state (refreshes on tick).
    let hooks_res = use_resource(move || async move {
        let _ = tick();
        tokio::task::spawn_blocking(crate::bindings::agent_hooks)
            .await
            .unwrap_or_default()
    });
    let agent_hooks = hooks_res().unwrap_or_default();

    // Engine dot + word (never color alone).
    let (engine_dot, engine_word, engine_color) = if engine_running {
        ("●", "engine running", "var(--green)")
    } else {
        ("○", "engine stopped", "var(--dim)")
    };

    // vault-state pill style (bound here — rsx attributes can't take format args).
    let pill_st = if provisioned {
        "color:var(--green);border:1px solid rgba(90,247,142,.3)"
    } else {
        "color:var(--dim);border:1px solid var(--line)"
    };

    rsx! {
        div { style: "padding:26px;{FADE}",
            // ── admin lock ──
            div { style: "border:1px solid var(--gold-line);border-radius:12px;background:linear-gradient(100deg,rgba(212,175,55,.06),transparent);padding:18px 20px;margin-bottom:16px;display:flex;align-items:center;gap:15px",
                span { style: "display:inline-flex;align-items:center;justify-content:center;width:40px;height:40px;border-radius:10px;background:rgba(212,175,55,.13);flex:none",
                    svg { view_box: "0 0 24 24", width: "20", height: "20", fill: "none", stroke: "var(--gold)", stroke_width: "1.7", stroke_linecap: "round", stroke_linejoin: "round",
                        rect { x: "4", y: "11", width: "16", height: "9", rx: "2" }
                        path { d: "M8 11V8a4 4 0 0 1 8 0v3" }
                    }
                }
                div { style: "flex:1",
                    div { style: "font-size:14px;font-weight:700", "Settings sealed · argon2id" }
                    div { style: "font-size:12.5px;color:var(--dim);margin-top:2px", "Loosening Kintsugi requires the admin password — enforced daemon-side with brute-force lockout." }
                }
                span { style: "font-size:11.5px;font-weight:600;color:var(--gold);border:1px solid var(--gold-line);border-radius:7px;padding:6px 11px;white-space:nowrap", "Locked" }
            }

            // ── appearance + lock ──
            div { style: "border:1px solid var(--line);border-radius:12px;background:var(--panel);padding:16px 20px;margin-bottom:16px;display:flex;align-items:center;gap:18px;flex-wrap:wrap",
                div { style: "flex:1;min-width:180px",
                    div { style: "font-size:13.5px;font-weight:600", "Appearance" }
                    div { style: "font-size:12px;color:var(--dim);margin-top:2px", "Choose a light or dark interface." }
                }
                div { style: "display:flex;gap:6px;background:var(--panel2);border:1px solid var(--line);border-radius:10px;padding:4px",
                    button { style: "font-family:inherit;font-size:12.5px;font-weight:600;border:1px solid transparent;border-radius:7px;padding:7px 14px;cursor:pointer;{dark_st}",
                        onclick: move |_| store.theme.set(Theme::Dark), "Dark" }
                    button { style: "font-family:inherit;font-size:12.5px;font-weight:600;border:1px solid transparent;border-radius:7px;padding:7px 14px;cursor:pointer;{light_st}",
                        onclick: move |_| store.theme.set(Theme::Light), "Light" }
                }
                div { style: "width:1px;height:34px;background:var(--line)" }
                button { class: "kn-btn-ghost", style: "display:inline-flex;align-items:center;gap:8px;font-family:inherit;font-size:12.5px;font-weight:600;color:var(--ink);background:var(--panel2);border:1px solid var(--line);border-radius:9px;padding:9px 15px;cursor:pointer",
                    onclick: move |_| store.lock(),
                    "Lock now"
                }
            }

            // ── software updates (mirrors `kintsugi update`) ──
            div { style: "border:1px solid var(--line);border-radius:12px;background:var(--panel);padding:16px 20px;margin-bottom:16px;display:flex;align-items:center;gap:18px;flex-wrap:wrap",
                div { style: "flex:1;min-width:180px",
                    div { style: "font-size:13.5px;font-weight:600", "Updates" }
                    div { style: "font-size:12px;color:var(--dim);margin-top:2px",
                        // The result line: idle prompt, the verdict, or an error.
                        match &*update_status.read() {
                            None => rsx!{ "Check GitHub for a newer Kintsugi release." },
                            Some(UpdateStatus::UpToDate { version }) => rsx!{
                                span { style: "color:var(--green)", "✓ Up to date" }
                                " — you're on {version}."
                            },
                            Some(UpdateStatus::Available { current, latest }) => rsx!{
                                span { style: "color:var(--gold);font-weight:700", "↑ Update available" }
                                " — {current} → {latest}."
                            },
                            Some(UpdateStatus::Failed { message }) => rsx!{
                                span { style: "color:var(--red)", "Check failed" }
                                " — {message}"
                            },
                        }
                    }
                }
                // Install button — only when a check found a newer release.
                if matches!(&*update_status.read(), Some(UpdateStatus::Available { .. })) {
                    button {
                        class: "kn-btn-ghost",
                        style: "font-family:inherit;font-size:12.5px;font-weight:700;color:#1a1206;background:var(--gold);border:1px solid var(--gold);border-radius:9px;padding:9px 15px;cursor:pointer",
                        disabled: *update_busy.read(),
                        onclick: move |_| {
                            update_busy.set(true);
                            store.toast(crate::state::ToastKind::Info, "Installing update — this can take a minute…");
                            spawn(async move {
                                let res = tokio::task::spawn_blocking(crate::bindings::apply_update).await;
                                update_busy.set(false);
                                match res {
                                    Ok(Ok(_)) => {
                                        update_status.set(None);
                                        store.toast(crate::state::ToastKind::Success, "Updated. Restart the app to run the new version.");
                                    }
                                    Ok(Err(e)) => { store.toast(crate::state::ToastKind::Error, format!("Update failed: {e}")); }
                                    Err(_) => { store.toast(crate::state::ToastKind::Error, "Update task crashed.".to_string()); }
                                }
                            });
                        },
                        if *update_busy.read() { "Installing…" } else { "Install update" }
                    }
                }
                button {
                    class: "kn-btn-ghost",
                    style: "display:inline-flex;align-items:center;gap:8px;font-family:inherit;font-size:12.5px;font-weight:600;color:var(--ink);background:var(--panel2);border:1px solid var(--line);border-radius:9px;padding:9px 15px;cursor:pointer",
                    disabled: *update_busy.read(),
                    onclick: move |_| {
                        update_busy.set(true);
                        spawn(async move {
                            let res = tokio::task::spawn_blocking(crate::bindings::check_for_update).await;
                            update_busy.set(false);
                            match res {
                                Ok(status) => {
                                    if let UpdateStatus::Failed { ref message } = status {
                                        store.toast(crate::state::ToastKind::Error, format!("Couldn't check: {message}"));
                                    }
                                    update_status.set(Some(status));
                                }
                                Err(_) => { store.toast(crate::state::ToastKind::Error, "Update check crashed.".to_string()); }
                            }
                        });
                    },
                    if *update_busy.read() { "Checking…" } else { "Check for updates" }
                }
            }

            // ── master password ──
            div { style: "border:1px solid var(--line);border-radius:12px;background:var(--panel);padding:18px 20px;margin-bottom:16px",
                div { style: "display:flex;align-items:flex-start;gap:13px;margin-bottom:15px",
                    span { style: "display:inline-flex;align-items:center;justify-content:center;width:38px;height:38px;border-radius:10px;background:rgba(212,175,55,.13);flex:none",
                        svg { view_box: "0 0 24 24", width: "20", height: "20", fill: "none", stroke: "var(--gold)", stroke_width: "1.7", stroke_linecap: "round", stroke_linejoin: "round",
                            rect { x: "4", y: "11", width: "16", height: "9", rx: "2" }
                            path { d: "M8 11V8a4 4 0 0 1 8 0v3M12 15v2" }
                        }
                    }
                    div { style: "flex:1",
                        div { style: "font-size:14px;font-weight:700",
                            if provisioned { "Change master password" } else { "Set a master password" }
                        }
                        div { style: "font-size:12.5px;color:var(--dim);margin-top:2px;line-height:1.5",
                            if provisioned {
                                "The argon2id vault that gates stopping and loosening Kintsugi. Changing it issues a fresh recovery key."
                            } else {
                                "No master password is set yet. One seals Settings and the kill-switch — verified in-process, never sent anywhere."
                            }
                        }
                    }
                    span { style: "flex:none;font-size:11.5px;font-weight:600;border-radius:7px;padding:6px 11px;white-space:nowrap;display:inline-flex;align-items:center;gap:6px;{pill_st}",
                        span { if provisioned { "●" } else { "○" } }
                        if provisioned { "vault set" } else { "no vault" }
                    }
                }
                div { style: "margin-top:15px;display:flex;align-items:center;gap:10px;flex-wrap:wrap",
                    button { class: "kn-btn-gold", style: "font-family:inherit;font-size:13px;font-weight:600;color:#1a1206;background:var(--gold);border:none;border-radius:9px;padding:10px 18px;cursor:pointer",
                        onclick: move |_| { pw_err.set(String::new()); pw_modal.set(true); },
                        if provisioned { "Change password" } else { "Set a master password" }
                    }
                    if provisioned {
                        button { title: "Remove the password entirely — stop and loosen will no longer need it.",
                            style: "font-family:inherit;font-size:12.5px;font-weight:600;color:var(--red);background:transparent;border:1px solid rgba(255,93,93,.35);border-radius:9px;padding:10px 16px;cursor:pointer",
                            onclick: move |_| { pw_err.set(String::new()); pw_remove_field.set(String::new()); pw_remove_modal.set(true); },
                            "Remove password"
                        }
                    }
                }
            }

            // ── change / set master password (modal) ──
            if *pw_modal.read() {
                div { style: "position:fixed;inset:0;z-index:60;background:rgba(0,0,0,.5);display:flex;align-items:center;justify-content:center;animation:kfade .15s ease",
                    onclick: move |_| pw_modal.set(false),
                    div { style: "width:460px;max-width:92vw;background:var(--bg2);border:1px solid var(--line);border-radius:14px;box-shadow:0 30px 80px rgba(0,0,0,.5);padding:22px 24px",
                        onclick: move |e| e.stop_propagation(),
                        div { style: "display:flex;align-items:center;margin-bottom:16px",
                            span { style: "font-size:15px;font-weight:700", if provisioned { "Change master password" } else { "Set a master password" } }
                            button { style: "margin-left:auto;display:inline-flex;align-items:center;justify-content:center;width:28px;height:28px;border:1px solid var(--line);border-radius:8px;background:var(--panel);color:var(--dim);font-size:16px;cursor:pointer", onclick: move |_| pw_modal.set(false), "×" }
                        }

                // The one-time recovery key — highlighted, shown once.
                if let Some(key) = recovery_key.read().clone() {
                    div { style: "border:1px solid var(--gold-line);border-radius:10px;background:rgba(212,175,55,.07);padding:14px 16px;margin-bottom:14px",
                        div { style: "font-size:12px;font-weight:700;color:var(--gold);display:flex;align-items:center;gap:7px",
                            span { "⚠" }
                            "Save this recovery key — it is shown once and never again."
                        }
                        div { style: "font-family:'IBM Plex Mono',monospace;font-size:13px;color:var(--ink);margin-top:9px;background:var(--term);border:1px solid var(--line);border-radius:8px;padding:11px 13px;overflow-x:auto;white-space:nowrap;color:#e7ecf6", "{key}" }
                        div { style: "font-size:11.5px;color:var(--dim);margin-top:8px", "It restores access if you forget the password. Store it somewhere safe, then dismiss." }
                        button { class: "kn-btn-ghost", style: "margin-top:10px;font-family:inherit;font-size:12px;font-weight:600;color:var(--dim);background:transparent;border:1px solid var(--line);border-radius:7px;padding:6px 12px;cursor:pointer",
                            onclick: move |_| { recovery_key.set(None); pw_modal.set(false); },
                            "I've saved it"
                        }
                    }
                } else {
                    // The mini-form (set or change).
                    div { style: "display:flex;flex-direction:column;gap:10px;max-width:360px",
                        if provisioned {
                            input { r#type: "password", class: "kn-input", value: "{pw_cur}", placeholder: "Current password",
                                style: "height:34px;box-sizing:border-box;border-radius:8px;border:1px solid var(--line);background:var(--panel2);color:var(--ink);padding:0 12px;font-family:inherit;font-size:12.5px;outline:none",
                                oninput: move |e| { pw_cur.set(e.value()); pw_err.set(String::new()); },
                            }
                        }
                        input { r#type: "password", class: "kn-input", value: "{pw_new}", placeholder: "New password",
                            style: "height:34px;box-sizing:border-box;border-radius:8px;border:1px solid var(--line);background:var(--panel2);color:var(--ink);padding:0 12px;font-family:inherit;font-size:12.5px;outline:none",
                            oninput: move |e| { pw_new.set(e.value()); pw_err.set(String::new()); },
                        }
                        input { r#type: "password", class: "kn-input", value: "{pw_confirm}", placeholder: "Confirm new password",
                            style: "height:34px;box-sizing:border-box;border-radius:8px;border:1px solid var(--line);background:var(--panel2);color:var(--ink);padding:0 12px;font-family:inherit;font-size:12.5px;outline:none",
                            oninput: move |e| { pw_confirm.set(e.value()); pw_err.set(String::new()); },
                        }

                        if !pw_err.read().is_empty() {
                            div { style: "font-size:12px;color:var(--red);display:inline-flex;align-items:center;gap:6px",
                                span { "⛔" }
                                "{pw_err}"
                            }
                        }

                        div { style: "display:flex;align-items:center;gap:10px;flex-wrap:wrap",
                            button { class: "kn-btn-gold", style: "font-family:inherit;font-size:13px;font-weight:600;color:#1a1206;background:var(--gold);border:none;border-radius:9px;padding:10px 18px;cursor:pointer",
                                onclick: move |_| {
                                    let cur = pw_cur.read().clone();
                                    let new = pw_new.read().clone();
                                    let confirm = pw_confirm.read().clone();
                                    if new.is_empty() {
                                        pw_err.set("Enter a new password.".to_string());
                                        return;
                                    }
                                    if new != confirm {
                                        pw_err.set("The two new passwords don't match.".to_string());
                                        return;
                                    }
                                    let result = if provisioned {
                                        crate::bindings::change_master_password(&cur, &new)
                                    } else {
                                        crate::bindings::set_master_password(&new)
                                    };
                                    match result {
                                        Ok(key) => {
                                            recovery_key.set(Some(key));
                                            // Keep the session credential in lockstep with the
                                            // new vault — otherwise Stop signs the daemon
                                            // challenge with the OLD password and is rejected.
                                            store.session_pw.set(Some(zeroize::Zeroizing::new(new.clone())));
                                            pw_err.set(String::new());
                                            pw_cur.set(String::new());
                                            pw_new.set(String::new());
                                            pw_confirm.set(String::new());
                                            let t = *tick.read();
                                            tick.set(t + 1);
                                        }
                                        Err(e) => pw_err.set(e.to_string()),
                                    }
                                },
                                if provisioned { "Change password" } else { "Set password" }
                            }
                        }
                    }
                }
                    }
                }
            }

            // ── remove-password modal (separate so it isn't confused with Change) ──
            if *pw_remove_modal.read() {
                div { style: "position:fixed;inset:0;z-index:60;background:rgba(0,0,0,.5);display:flex;align-items:center;justify-content:center;animation:kfade .15s ease",
                    onclick: move |_| pw_remove_modal.set(false),
                    div { style: "width:440px;max-width:92vw;background:var(--bg2);border:1px solid var(--line);border-radius:14px;box-shadow:0 30px 80px rgba(0,0,0,.5);padding:22px 24px",
                        onclick: move |e| e.stop_propagation(),
                        div { style: "display:flex;align-items:center;margin-bottom:8px",
                            span { style: "font-size:15px;font-weight:700;color:var(--red)", "Remove master password" }
                            button { style: "margin-left:auto;display:inline-flex;align-items:center;justify-content:center;width:28px;height:28px;border:1px solid var(--line);border-radius:8px;background:var(--panel);color:var(--dim);font-size:16px;cursor:pointer", onclick: move |_| pw_remove_modal.set(false), "×" }
                        }
                        div { style: "font-size:12.5px;color:var(--dim);line-height:1.55;margin-bottom:16px",
                            "After this, "
                            b { style: "color:var(--ink)", "stopping and loosening Kintsugi no longer needs a password" }
                            ". Enter your current password to confirm."
                        }
                        input { r#type: "password", class: "kn-input", value: "{pw_remove_field}", placeholder: "Current password",
                            style: "width:100%;height:36px;box-sizing:border-box;border-radius:8px;border:1px solid var(--line);background:var(--panel2);color:var(--ink);padding:0 12px;font-family:inherit;font-size:12.5px;outline:none;margin-bottom:12px",
                            oninput: move |e| { pw_remove_field.set(e.value()); pw_err.set(String::new()); },
                        }
                        if !pw_err.read().is_empty() {
                            div { style: "font-size:12px;color:var(--red);margin-bottom:12px;display:inline-flex;align-items:center;gap:6px",
                                span { "⛔" }
                                "{pw_err}"
                            }
                        }
                        div { style: "display:flex;gap:10px;justify-content:flex-end",
                            button { class: "kn-btn-ghost", style: "font-family:inherit;font-size:12.5px;font-weight:600;color:var(--dim);background:transparent;border:1px solid var(--line);border-radius:8px;padding:9px 14px;cursor:pointer",
                                onclick: move |_| pw_remove_modal.set(false),
                                "Cancel"
                            }
                            button { style: "font-family:inherit;font-size:13px;font-weight:600;color:#fff;background:var(--red);border:none;border-radius:9px;padding:10px 18px;cursor:pointer",
                                onclick: move |_| {
                                    let cur = pw_remove_field.read().clone();
                                    if cur.is_empty() {
                                        pw_err.set("Enter your current password.".to_string());
                                        return;
                                    }
                                    match crate::bindings::remove_master_password(&cur) {
                                        Ok(()) => {
                                            store.session_pw.set(None);
                                            pw_err.set(String::new());
                                            pw_remove_field.set(String::new());
                                            pw_remove_modal.set(false);
                                            let t = *tick.read();
                                            tick.set(t + 1);
                                        }
                                        Err(e) => pw_err.set(e.to_string()),
                                    }
                                },
                                "Remove password"
                            }
                        }
                    }
                }
            }

            // ── local model ──
            div { style: "border:1px solid var(--line);border-radius:12px;background:var(--panel);padding:18px 20px;margin-bottom:16px",
                div { style: "display:flex;align-items:flex-start;gap:13px;margin-bottom:14px",
                    span { style: "display:inline-flex;align-items:center;justify-content:center;width:38px;height:38px;border-radius:10px;background:rgba(212,175,55,.13);flex:none",
                        svg { view_box: "0 0 24 24", width: "20", height: "20", fill: "none", stroke: "var(--gold)", stroke_width: "1.6", stroke_linecap: "round", stroke_linejoin: "round",
                            rect { x: "5", y: "5", width: "14", height: "14", rx: "2" }
                            path { d: "M9 9h6v6H9zM9 2v3M15 2v3M9 19v3M15 19v3M2 9h3M2 15h3M19 9h3M19 15h3" }
                        }
                    }
                    div { style: "flex:1",
                        div { style: "font-size:14px;font-weight:700",
                            if model_active { "Local model active" } else if model_configured_not_loaded { "Model selected — restart to load" } else { "Heuristic scorer · offline" }
                        }
                        // The real "model summary" the user said was missing.
                        div { style: "font-size:12.5px;color:var(--dim);margin-top:2px;line-height:1.5", "{scorer_summary}" }
                    }
                    // real engine/scorer state, paired with a glyph + word (never color alone)
                    span { style: "flex:none;font-size:11.5px;font-weight:600;color:{engine_color};border:1px solid var(--line);border-radius:7px;padding:6px 11px;white-space:nowrap;display:inline-flex;align-items:center;gap:6px",
                        span { "{engine_dot}" }
                        "{engine_word}"
                    }
                }

                // The REAL installed .gguf, with a remove → heuristic action.
                if let Some(name) = installed_model.clone() {
                    div { style: "border:1px solid var(--gold-line);border-radius:10px;background:rgba(212,175,55,.05);padding:13px 15px;margin-bottom:16px",
                        div { style: "display:flex;align-items:center;gap:8px;margin-bottom:7px",
                            span { style: "font-size:11.5px;font-weight:600;color:var(--green);display:inline-flex;align-items:center;gap:6px",
                                svg { view_box: "0 0 24 24", width: "14", height: "14", fill: "none", stroke: "currentColor", stroke_width: "2", stroke_linecap: "round", stroke_linejoin: "round", path { d: "M20 6L9 17l-5-5" } }
                                "Active model"
                            }
                        }
                        div { style: "font-family:'IBM Plex Mono',monospace;font-size:13px;color:var(--ink);overflow-x:auto;white-space:nowrap", "{name}" }
                        button { class: "kn-btn-ghost", style: "margin-top:11px;font-family:inherit;font-size:12px;font-weight:600;color:var(--dim);background:transparent;border:1px solid var(--line);border-radius:7px;padding:6px 12px;cursor:pointer",
                            onclick: move |_| {
                                match crate::bindings::clear_model() {
                                    Ok(()) => {
                                        model_msg.set("Removed — restart to drop back to the heuristic scorer.".to_string());
                                        store.toast(crate::state::ToastKind::Success, "Cleared model selection. Restart to apply.");
                                        restart_pending.set(true);
                                        let t = *tick.read();
                                        tick.set(t + 1);
                                    }
                                    Err(e) => model_msg.set(format!("Couldn't remove: {e}")),
                                }
                            },
                            "Remove · back to heuristic"
                        }
                    }
                }

                if !model_msg.read().is_empty() {
                    div { style: "font-size:12px;color:var(--gold);margin-bottom:14px;display:inline-flex;align-items:center;gap:6px",
                        span { "✓" }
                        "{model_msg}"
                    }
                }

                // The design model LIST — kept for browsing, no fake download.
                div { style: "position:relative;margin-bottom:13px;width:260px;max-width:100%",
                    svg { view_box: "0 0 24 24", width: "14", height: "14", fill: "none", stroke: "var(--dim)", stroke_width: "1.8", stroke_linecap: "round", stroke_linejoin: "round", style: "position:absolute;left:10px;top:50%;transform:translateY(-50%)",
                        circle { cx: "11", cy: "11", r: "7" }
                        path { d: "M21 21l-4-4" }
                    }
                    input { class: "kn-input", value: "{store.model_search}", placeholder: "4B Instruct GGUF",
                        style: "width:100%;height:32px;box-sizing:border-box;border-radius:8px;border:1px solid var(--line);background:var(--panel2);color:var(--ink);padding:0 10px 0 31px;font-family:inherit;font-size:12px",
                        oninput: move |e| store.model_search.set(e.value()),
                    }
                }

                // Restart-to-apply: changing the selection needs a daemon reload.
                if *restart_pending.read() || model_configured_not_loaded {
                    div { style: "border:1px solid var(--gold-line);border-radius:10px;background:rgba(212,175,55,.07);padding:12px 15px;margin-bottom:14px;display:flex;align-items:center;gap:12px",
                        span { style: "font-size:12.5px;color:var(--ink);flex:1;line-height:1.45", "Your model choice is saved. Restart Kintsugi so the daemon loads it (a few seconds)." }
                        button { class: "kn-btn-gold", style: "flex:none;font-family:inherit;font-size:12.5px;font-weight:600;color:#1a1206;background:var(--gold);border:none;border-radius:8px;padding:9px 14px;cursor:pointer",
                            onclick: move |_| {
                                let pw = store.session_pw.peek().clone();
                                let res = match pw {
                                    Some(p) => crate::bindings::restart_engine_with_password(&p),
                                    None => crate::bindings::start_engine(),
                                };
                                match res {
                                    Ok(()) => {
                                        restart_pending.set(false);
                                        model_msg.set("Restarted — the daemon is loading your model.".to_string());
                                        store.toast(crate::state::ToastKind::Success, "Daemon restarted — loading the model.");
                                    }
                                    Err(e) => {
                                        let m = e.to_string();
                                        model_msg.set(format!("Restart failed: {m}"));
                                        store.toast(crate::state::ToastKind::Error, format!("Restart failed: {m}"));
                                    }
                                }
                                let t = *tick.read(); tick.set(t + 1);
                            },
                            "Restart to apply"
                        }
                    }
                }

                // Real downloaded models on disk — selectable (no mock catalog).
                if local_models.is_empty() {
                    div { style: "font-size:12.5px;color:var(--dim);line-height:1.5;border:1px dashed var(--line);border-radius:10px;padding:14px",
                        "No .gguf models found on disk. Download one with "
                        span { style: "font-family:'IBM Plex Mono',monospace;color:var(--ink)", "kintsugi model pick" }
                        " in your terminal, then it'll appear here to select."
                    }
                } else {
                    div { style: "display:flex;flex-direction:column;gap:9px",
                        for m in local_models.iter().filter(|m| search.is_empty() || m.name.to_lowercase().contains(&search)).cloned() {
                            {
                                let row_st = if m.active { "border-color:var(--gold-line);background:rgba(212,175,55,.05)" } else { "" };
                                let path = m.path.clone();
                                let del_path = m.path.clone();
                                let confirming = delete_confirm.read().as_deref() == Some(m.path.as_str());
                                rsx! {
                                    div { style: "display:flex;align-items:center;gap:13px;border:1px solid var(--line);border-radius:10px;background:var(--panel2);padding:12px 14px;{row_st}",
                                        div { style: "flex:1;min-width:0",
                                            span { style: "display:block;font-family:'IBM Plex Mono',monospace;font-size:13px;font-weight:600;color:var(--ink);overflow:hidden;text-overflow:ellipsis;white-space:nowrap", "{m.name}" }
                                            div { style: "font-size:11.5px;color:var(--dim);margin-top:3px", "{m.size} · on disk" }
                                        }
                                        if m.active {
                                            span { style: "flex:none;font-size:12.5px;font-weight:600;color:var(--green);display:inline-flex;align-items:center;gap:6px",
                                                svg { view_box: "0 0 24 24", width: "14", height: "14", fill: "none", stroke: "currentColor", stroke_width: "2", stroke_linecap: "round", stroke_linejoin: "round", path { d: "M20 6L9 17l-5-5" } }
                                                "Selected"
                                            }
                                        } else {
                                            button { class: "kn-btn-ghost", style: "flex:none;font-family:inherit;font-size:12px;font-weight:600;color:var(--gold);background:var(--panel);border:1px solid var(--gold-line);border-radius:7px;padding:7px 13px;cursor:pointer",
                                                onclick: move |_| {
                                                    match crate::bindings::set_model(&path) {
                                                        Ok(()) => {
                                                            // Auto-restart so the daemon loads the pick in one click,
                                                            // like the CLI's `model use`. Reuse the in-memory session
                                                            // password (present after unlock when a vault is set);
                                                            // a plain start otherwise.
                                                            let pw = store.session_pw.peek().clone();
                                                            let restart = match pw {
                                                                Some(p) => crate::bindings::restart_engine_with_password(&p),
                                                                None => crate::bindings::start_engine(),
                                                            };
                                                            match restart {
                                                                Ok(()) => {
                                                                    restart_pending.set(false);
                                                                    model_msg.set("Switched — the daemon restarted with this model.".to_string());
                                                                    store.toast(crate::state::ToastKind::Success, "Model switched — daemon restarted with it.");
                                                                }
                                                                Err(e) => {
                                                                    // The pick is saved; only the auto-restart failed —
                                                                    // fall back to the manual Restart banner.
                                                                    restart_pending.set(true);
                                                                    let m = e.to_string();
                                                                    model_msg.set(format!("Selected — auto-restart failed ({m}); use Restart to apply."));
                                                                    store.toast(crate::state::ToastKind::Error, format!("Selected, but restart failed: {m}"));
                                                                }
                                                            }
                                                            let t = *tick.read(); tick.set(t + 1);
                                                        }
                                                        Err(e) => {
                                                            let m = e.to_string();
                                                            model_msg.set(format!("Couldn't select: {m}"));
                                                            store.toast(crate::state::ToastKind::Error, format!("Couldn't select model: {m}"));
                                                        }
                                                    }
                                                },
                                                "Use this"
                                            }
                                        }
                                        // Two-step delete of the .gguf from disk.
                                        if confirming {
                                            button { style: "flex:none;font-family:inherit;font-size:12px;font-weight:600;color:#fff;background:var(--red);border:none;border-radius:7px;padding:7px 12px;cursor:pointer",
                                                onclick: move |_| {
                                                    match crate::bindings::delete_model_file(&del_path) {
                                                        Ok(()) => {
                                                            let name = del_path.rsplit('/').next().unwrap_or(&del_path).to_string();
                                                            model_msg.set(format!("Deleted {name} from disk."));
                                                            store.toast(crate::state::ToastKind::Success, format!("Deleted {name} from disk."));
                                                        }
                                                        Err(e) => {
                                                            let m = e.to_string();
                                                            model_msg.set(format!("Couldn't delete: {m}"));
                                                            store.toast(crate::state::ToastKind::Error, format!("Couldn't delete model: {m}"));
                                                        }
                                                    }
                                                    delete_confirm.set(None);
                                                    let t = *tick.read(); tick.set(t + 1);
                                                },
                                                "Confirm delete"
                                            }
                                            button { class: "kn-btn-ghost", style: "flex:none;font-family:inherit;font-size:12px;font-weight:600;color:var(--dim);background:transparent;border:1px solid var(--line);border-radius:7px;padding:7px 10px;cursor:pointer",
                                                onclick: move |_| delete_confirm.set(None),
                                                "Cancel"
                                            }
                                        } else {
                                            button { title: "Delete this .gguf from disk", style: "flex:none;display:inline-flex;align-items:center;justify-content:center;width:32px;height:32px;font-family:inherit;color:var(--dim);background:transparent;border:1px solid var(--line);border-radius:7px;cursor:pointer",
                                                onclick: move |_| delete_confirm.set(Some(m.path.clone())),
                                                svg { view_box: "0 0 24 24", width: "15", height: "15", fill: "none", stroke: "currentColor", stroke_width: "1.7", stroke_linecap: "round", stroke_linejoin: "round",
                                                    path { d: "M4 7h16M9 7V5a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2m-8 0v12a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1V7" }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // ── browse Hugging Face (live search + download) ──
                div { style: "margin-top:20px;margin-bottom:9px;font-size:10.5px;font-weight:600;letter-spacing:.6px;text-transform:uppercase;color:var(--dim)",
                    if store.model_search.read().trim().is_empty() { "Suggested on Hugging Face" } else { "Hugging Face results" }
                }
                if hf_loading {
                    Loader { label: "Searching Hugging Face…".to_string() }
                } else if hf_models.is_empty() {
                    div { style: "font-size:12px;color:var(--dim)", "No models found (or you're offline). Try another search." }
                } else {
                    div { style: "display:flex;flex-direction:column;gap:9px",
                        for hm in hf_models.iter().cloned() {
                            {
                                let dl_id = hm.id.clone();
                                let is_dl = downloading.read().contains(&hm.id);
                                rsx! {
                                    div { style: "display:flex;align-items:center;gap:13px;border:1px solid var(--line);border-radius:10px;background:var(--panel2);padding:12px 14px",
                                        div { style: "flex:1;min-width:0",
                                            span { style: "display:block;font-family:'IBM Plex Mono',monospace;font-size:12.5px;font-weight:600;color:var(--ink);overflow:hidden;text-overflow:ellipsis;white-space:nowrap", "{hm.id}" }
                                            div { style: "font-size:11px;color:var(--dim);margin-top:3px", "{hm.downloads} downloads · {hm.likes} likes" }
                                        }
                                        if is_dl {
                                            span { style: "flex:none;font-size:12px;color:var(--gold);display:inline-flex;align-items:center;gap:7px",
                                                span { style: "width:13px;height:13px;border-radius:50%;border:2px solid var(--line);border-top-color:var(--gold);animation:kspin .7s linear infinite" }
                                                "Downloading…"
                                            }
                                        } else {
                                            button { class: "kn-btn-ghost", style: "flex:none;font-family:inherit;font-size:12px;font-weight:600;color:var(--gold);background:var(--panel);border:1px solid var(--gold-line);border-radius:7px;padding:7px 13px;cursor:pointer",
                                                onclick: move |_| {
                                                    let id = dl_id.clone();
                                                    let mut downloading = downloading;
                                                    let mut model_msg = model_msg;
                                                    let mut tick = tick;
                                                    downloading.write().insert(id.clone());
                                                    model_msg.set(format!("Downloading {id} — a few GB; it'll appear under 'on disk' when done."));
                                                    spawn(async move {
                                                        let id2 = id.clone();
                                                        let res = tokio::task::spawn_blocking(move || crate::bindings::download_model(&id2)).await;
                                                        match res {
                                                            Ok(Ok(name)) => model_msg.set(format!("Downloaded {name} — select it under 'on disk'.")),
                                                            Ok(Err(e)) => model_msg.set(format!("Download failed: {e}")),
                                                            Err(_) => model_msg.set("Download task crashed.".to_string()),
                                                        }
                                                        downloading.write().remove(&id);
                                                        let t = *tick.read(); tick.set(t + 1);
                                                    });
                                                },
                                                "Download"
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                div { style: "font-size:11.5px;color:var(--dim);line-height:1.5;margin-top:14px;border-left:2px solid var(--gold);padding-left:12px",
                    "A model you pick is your choice — trusted because you selected it. The daemon never downloads on its own; this search and download happen only when you ask."
                }
            }

            // ── protection toggles (all REAL — read + write the actual config) ──
            div { style: "border:1px solid var(--line);border-radius:12px;background:var(--panel);overflow:hidden",
                // Fail-closed: marker file the shim/hook read even when the daemon is down.
                div { style: "display:flex;align-items:center;gap:15px;padding:15px 20px;border-bottom:1px solid var(--hair)",
                    div { style: "flex:1",
                        div { style: "font-size:13.5px;font-weight:600", "Fail-closed" }
                        div { style: "font-size:12px;color:var(--dim);margin-top:2px", "If the daemon is unreachable, block rather than run unguarded." }
                        if fc_initial().is_none() {
                            div { style: "font-size:11px;color:var(--dim);margin-top:3px;display:inline-flex;align-items:center;gap:5px",
                                span { style: "color:var(--gold)", "◌" }
                                "reading current posture…"
                            }
                        }
                    }
                    Toggle {
                        on: fail_closed_on,
                        on_click: move |_| {
                            let cur = *fail_closed_sig.read();
                            let next = !cur;
                            match crate::bindings::set_fail_closed(next) {
                                Ok(()) => {
                                    fail_closed_sig.set(next);
                                    store.toast(crate::state::ToastKind::Success,
                                        if next { "Fail-closed enabled — unreachable daemon now blocks." } else { "Fail-closed disabled." });
                                }
                                Err(e) => { store.toast(crate::state::ToastKind::Error, format!("Couldn't change fail-closed: {e}")); }
                            }
                        }
                    }
                }

                // Passive session recording — writes to shell rc.
                div { style: "display:flex;align-items:center;gap:15px;padding:15px 20px;border-bottom:1px solid var(--hair)",
                    div { style: "flex:1",
                        div { style: "font-size:13.5px;font-weight:600", "Passive session recording" }
                        div { style: "font-size:12px;color:var(--dim);margin-top:2px", "Log every human shell command to the tamper-evident audit trail." }
                        div { style: "font-size:11px;color:var(--dim);margin-top:3px", "writes a managed fenced block in your shell rc — restart your shell to apply" }
                    }
                    Toggle {
                        on: recording_on,
                        on_click: move |_| {
                            let res = if recording_on { crate::bindings::uninstall_recording() } else { crate::bindings::install_recording() };
                            match res {
                                Ok(()) => {
                                    store.toast(crate::state::ToastKind::Success,
                                        if recording_on { "Recorder removed from your shell rc." } else { "Recorder installed — restart your shell to start recording." });
                                    let t = *tick.read(); tick.set(t + 1);
                                }
                                Err(e) => { store.toast(crate::state::ToastKind::Error, format!("Couldn't change recorder: {e}")); }
                            }
                        }
                    }
                }

                // Auto-restart service (systemd/launchd) — covers both "auto-restart" and "start on login".
                div { style: "display:flex;align-items:center;gap:15px;padding:15px 20px",
                    div { style: "flex:1",
                        div { style: "font-size:13.5px;font-weight:600", "Auto-restart on boot" }
                        div { style: "font-size:12px;color:var(--dim);margin-top:2px", "Run under launchd / systemd with restart-always — a kill/pkill brings it back." }
                        div { style: "font-size:11px;color:var(--dim);margin-top:3px", "uninstalling needs the admin password when locked" }
                    }
                    Toggle {
                        on: service_on,
                        on_click: move |_| {
                            let res = if service_on { crate::bindings::uninstall_service() } else { crate::bindings::install_service() };
                            match res {
                                Ok(()) => {
                                    store.toast(crate::state::ToastKind::Success,
                                        if service_on { "Auto-restart disabled." } else { "Auto-restart installed — Kintsugi will relaunch after a crash or kill." });
                                    let t = *tick.read(); tick.set(t + 1);
                                }
                                Err(e) => { store.toast(crate::state::ToastKind::Error, format!("Couldn't change auto-restart: {e}")); }
                            }
                        }
                    }
                }
            }

            // ── agent CLI hooks (per-CLI on/off + refresh) ──
            div { style: "border:1px solid var(--line);border-radius:12px;background:var(--panel);overflow:hidden;margin-top:16px",
                div { style: "display:flex;align-items:center;gap:12px;padding:15px 20px;border-bottom:1px solid var(--hair)",
                    div { style: "flex:1",
                        div { style: "font-size:13.5px;font-weight:600", "Agent CLI hooks" }
                        div { style: "font-size:12px;color:var(--dim);margin-top:2px", "Which agent CLIs Kintsugi is wired into. Toggle to enable or strip the hook per CLI; refresh to re-detect newly installed CLIs." }
                    }
                    button { class: "kn-btn-ghost", title: "Re-detect installed agent CLIs",
                        style: "font-family:inherit;font-size:12px;font-weight:600;color:var(--ink);background:var(--panel2);border:1px solid var(--line);border-radius:7px;padding:7px 12px;cursor:pointer;display:inline-flex;align-items:center;gap:6px",
                        onclick: move |_| {
                            let t = *tick.read(); tick.set(t + 1);
                            store.toast(crate::state::ToastKind::Info, "Re-detecting agent CLIs…");
                        },
                        svg { view_box: "0 0 24 24", width: "13", height: "13", fill: "none", stroke: "currentColor", stroke_width: "1.8", stroke_linecap: "round", stroke_linejoin: "round",
                            path { d: "M21 12a9 9 0 1 1-3.5-7.1 M21 3v6h-6" }
                        }
                        "Refresh"
                    }
                }
                if hooks_res().is_none() {
                    Loader { label: "Detecting agent CLIs…".to_string() }
                } else if agent_hooks.is_empty() {
                    div { style: "padding:24px;text-align:center;color:var(--dim);font-size:12.5px;line-height:1.55",
                        "No agent CLIs detected. Install one (e.g. Claude Code) and click Refresh."
                    }
                } else {
                    for h in agent_hooks.iter().cloned() {
                        {
                            let id = h.id.clone();
                            let name = h.name.clone();
                            let path = h.config_path.clone();
                            let installed = h.installed;
                            let pill_color = if installed { "var(--green)" } else { "var(--dim)" };
                            let pill_border = if installed { "rgba(90,247,142,.4)" } else { "var(--line)" };
                            rsx! {
                                div { style: "display:flex;align-items:center;gap:15px;padding:14px 20px;border-bottom:1px solid var(--hair)",
                                    div { style: "flex:1;min-width:0",
                                        div { style: "font-size:13px;font-weight:600", "{name}" }
                                        div { style: "font-size:11px;color:var(--dim);margin-top:2px;font-family:'IBM Plex Mono',monospace;overflow:hidden;text-overflow:ellipsis;white-space:nowrap", "{path}" }
                                    }
                                    span { style: "flex:none;font-size:11px;font-weight:600;border-radius:6px;padding:3px 9px;color:{pill_color};border:1px solid {pill_border}",
                                        if installed { "wired" } else { "off" }
                                    }
                                    Toggle {
                                        on: installed,
                                        on_click: move |_| {
                                            let id_s = id.clone();
                                            let name_s = name.clone();
                                            let res = if installed {
                                                crate::bindings::disable_agent_hook(&id_s)
                                            } else {
                                                crate::bindings::enable_agent_hook(&id_s)
                                            };
                                            match res {
                                                Ok(()) => {
                                                    store.toast(crate::state::ToastKind::Success,
                                                        if installed { format!("Disabled hook for {name_s}.") } else { format!("Wired Kintsugi into {name_s}.") });
                                                    let t = *tick.read(); tick.set(t + 1);
                                                }
                                                Err(e) => { store.toast(crate::state::ToastKind::Error, format!("Couldn't change {name_s} hook: {e}")); }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // ── danger zone: uninstall ──
            div { style: "border:1px solid rgba(255,93,93,.3);border-radius:12px;background:linear-gradient(100deg,rgba(255,93,93,.05),transparent);padding:18px 20px;margin-top:20px;margin-bottom:16px",
                div { style: "display:flex;align-items:flex-start;gap:13px;margin-bottom:12px",
                    span { style: "display:inline-flex;align-items:center;justify-content:center;width:38px;height:38px;border-radius:10px;background:rgba(255,93,93,.13);flex:none;color:var(--red);font-size:18px;font-weight:700", "!" }
                    div { style: "flex:1",
                        div { style: "font-size:14px;font-weight:700", "Uninstall Kintsugi" }
                        div { style: "font-size:12.5px;color:var(--dim);margin-top:2px;line-height:1.5",
                            "Stops the daemon, strips the agent hooks, and removes the installed binaries. By default your stored data (event log, vault, model config) is kept. Opens a terminal to confirm — password-gated."
                        }
                    }
                }
                div { style: "display:flex;gap:10px;flex-wrap:wrap",
                    button {
                        style: "font-family:inherit;font-size:12.5px;font-weight:600;color:#fff;background:var(--red);border:none;border-radius:9px;padding:10px 16px;cursor:pointer",
                        onclick: move |_| {
                            uninst_err.set(String::new());
                            uninst_pw.set(String::new());
                            uninst_confirm.set(String::new());
                            uninst_purge.set(false);
                            uninst_result.set(None);
                            uninst_modal.set(true);
                        },
                        "Uninstall Kintsugi…"
                    }
                }
            }

            // ── uninstall modal (password + purge + type-to-confirm) ──
            if *uninst_modal.read() {
                div { style: "position:fixed;inset:0;z-index:60;background:rgba(0,0,0,.55);display:flex;align-items:center;justify-content:center;animation:kfade .15s ease",
                    onclick: move |_| { if !*uninst_running.peek() { uninst_modal.set(false); } },
                    div { style: "width:500px;max-width:92vw;background:var(--bg2);border:1px solid rgba(255,93,93,.4);border-radius:14px;box-shadow:0 30px 80px rgba(0,0,0,.5);padding:22px 24px",
                        onclick: move |e| e.stop_propagation(),
                        if let Some(out) = uninst_result.read().clone() {
                            // Success/finished state.
                            div { style: "display:flex;align-items:center;margin-bottom:10px",
                                span { style: "font-size:15px;font-weight:700;color:var(--green)", "Uninstalled" }
                                button { style: "margin-left:auto;display:inline-flex;align-items:center;justify-content:center;width:28px;height:28px;border:1px solid var(--line);border-radius:8px;background:var(--panel);color:var(--dim);font-size:16px;cursor:pointer", onclick: move |_| uninst_modal.set(false), "×" }
                            }
                            div { style: "font-size:12.5px;color:var(--dim);line-height:1.55;margin-bottom:14px",
                                "Kintsugi has been removed. You can close the app now."
                            }
                            pre { style: "max-height:240px;overflow-y:auto;font-family:'IBM Plex Mono',monospace;font-size:12px;color:var(--ink);background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:11px 13px;white-space:pre-wrap;word-break:break-word", "{out}" }
                        } else {
                            // Confirmation form.
                            div { style: "display:flex;align-items:center;margin-bottom:8px",
                                span { style: "font-size:15px;font-weight:700;color:var(--red)", "Uninstall Kintsugi" }
                                button { style: "margin-left:auto;display:inline-flex;align-items:center;justify-content:center;width:28px;height:28px;border:1px solid var(--line);border-radius:8px;background:var(--panel);color:var(--dim);font-size:16px;cursor:pointer", onclick: move |_| uninst_modal.set(false), "×" }
                            }
                            div { style: "font-size:12.5px;color:var(--dim);line-height:1.55;margin-bottom:14px",
                                "This stops the daemon, strips Kintsugi hooks from every agent's config, and removes the installed binaries. "
                                if *uninst_purge.read() { b { style: "color:var(--red)", "All stored data (event log, vault, model config) will also be erased." } } else { span { "Your stored data is kept unless you check the purge box." } }
                            }
                            if provisioned {
                                input { r#type: "password", class: "kn-input", value: "{uninst_pw}", placeholder: "Master password",
                                    style: "width:100%;height:36px;box-sizing:border-box;border-radius:8px;border:1px solid var(--line);background:var(--panel2);color:var(--ink);padding:0 12px;font-family:inherit;font-size:12.5px;outline:none;margin-bottom:11px",
                                    oninput: move |e| { uninst_pw.set(e.value()); uninst_err.set(String::new()); },
                                }
                            }
                            label { style: "display:flex;align-items:flex-start;gap:9px;font-size:12.5px;color:var(--ink);cursor:pointer;margin-bottom:11px;line-height:1.4",
                                input { r#type: "checkbox", checked: *uninst_purge.read(),
                                    style: "margin-top:3px",
                                    onchange: move |e| uninst_purge.set(e.value() == "true"),
                                }
                                span { "Also erase all stored data (event log, vault, model config) — "
                                    span { style: "color:var(--red);font-weight:600", "unrecoverable" }
                                    "."
                                }
                            }
                            input { r#type: "text", class: "kn-input", value: "{uninst_confirm}", placeholder: "Type 'uninstall' to confirm",
                                style: "width:100%;height:36px;box-sizing:border-box;border-radius:8px;border:1px solid var(--line);background:var(--panel2);color:var(--ink);padding:0 12px;font-family:inherit;font-size:12.5px;outline:none;margin-bottom:12px",
                                oninput: move |e| { uninst_confirm.set(e.value()); uninst_err.set(String::new()); },
                            }
                            if !uninst_err.read().is_empty() {
                                div { style: "font-size:12px;color:var(--red);margin-bottom:12px;display:inline-flex;align-items:center;gap:6px",
                                    span { "⛔" }
                                    "{uninst_err}"
                                }
                            }
                            div { style: "display:flex;gap:10px;justify-content:flex-end",
                                button { class: "kn-btn-ghost", style: "font-family:inherit;font-size:12.5px;font-weight:600;color:var(--dim);background:transparent;border:1px solid var(--line);border-radius:8px;padding:9px 14px;cursor:pointer",
                                    disabled: *uninst_running.read(),
                                    onclick: move |_| uninst_modal.set(false),
                                    "Cancel"
                                }
                                button {
                                    style: "font-family:inherit;font-size:13px;font-weight:600;color:#fff;background:var(--red);border:none;border-radius:9px;padding:10px 18px;cursor:pointer",
                                    disabled: *uninst_running.read(),
                                    onclick: move |_| {
                                        if uninst_confirm.read().trim() != "uninstall" {
                                            uninst_err.set("Type 'uninstall' to confirm.".to_string());
                                            return;
                                        }
                                        if provisioned && uninst_pw.read().is_empty() {
                                            uninst_err.set("Enter your master password.".to_string());
                                            return;
                                        }
                                        let pw = uninst_pw.read().clone();
                                        let purge = *uninst_purge.read();
                                        uninst_running.set(true);
                                        spawn(async move {
                                            let res = tokio::task::spawn_blocking(move || {
                                                crate::bindings::run_uninstall(&pw, purge)
                                            }).await;
                                            match res {
                                                Ok(Ok(out)) => uninst_result.set(Some(out)),
                                                Ok(Err(e)) => uninst_err.set(e.to_string()),
                                                Err(_) => uninst_err.set("Uninstall task crashed.".to_string()),
                                            }
                                            uninst_running.set(false);
                                        });
                                    },
                                    if *uninst_running.read() { "Uninstalling…" } else if *uninst_purge.read() { "Uninstall + purge" } else { "Uninstall" }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
#[component]
pub fn Policy() -> Element {
    // ---- live backend reads, off the UI thread (the #1 complaint: lag) ----
    // Fetched once on mount; policy/builtins are static-ish, no fast timer.
    let policy_res = use_resource(move || async move {
        tokio::task::spawn_blocking(|| crate::bindings::policy_view())
            .await
            .ok()
    });
    let builtins_res = use_resource(move || async move {
        tokio::task::spawn_blocking(|| crate::bindings::builtin_protections())
            .await
            .unwrap_or_default()
    });
    // What provenance tracks — sourced from the engine so the list can't drift.
    let prov_res = use_resource(move || async move {
        tokio::task::spawn_blocking(|| {
            (
                crate::bindings::untrusted_sources(),
                crate::bindings::egress_channels(),
            )
        })
        .await
        .unwrap_or_default()
    });

    let policy = policy_res().flatten();
    let builtins = builtins_res().unwrap_or_default();
    let (untrusted_sources, egress_channels) = prov_res().unwrap_or_default();

    // Mode → a plain-language line + accent, so it's a word, never color alone.
    let (mode_label, mode_note, mode_color) = match policy.as_ref().map(|p| p.mode.as_str()) {
        Some("autonomous") => (
            "Autonomous",
            "Safe commands run on their own; only real danger is paused.",
            "var(--green)",
        ),
        Some("unattended") => (
            "Unattended",
            "Nobody's watching — anything risky is blocked outright, not queued.",
            "var(--amber)",
        ),
        Some(_) => (
            "Attended",
            "You're in the loop — ambiguous commands wait for your decision.",
            "var(--gold)",
        ),
        None => ("…", "Reading your effective policy.", "var(--dim)"),
    };

    rsx! {
        div { style: "padding:26px;{FADE}",

            // ── (a) Built-in protections ─────────────────────────────────
            div { style: "border:1px solid var(--line);border-radius:14px;background:var(--panel);overflow:hidden;margin-bottom:18px",
                div { style: "display:flex;align-items:center;gap:12px;padding:15px 20px;border-bottom:1px solid var(--line);background:linear-gradient(100deg,rgba(90,247,142,.06),transparent)",
                    span { style: "display:inline-flex;align-items:center;justify-content:center;width:34px;height:34px;border-radius:9px;background:rgba(90,247,142,.13);flex:none",
                        svg { view_box: "0 0 24 24", width: "19", height: "19", fill: "none", stroke: "var(--green)", stroke_width: "1.8", stroke_linecap: "round", stroke_linejoin: "round",
                            path { d: "M12 3l7 3v5c0 4-3 7-7 9-4-2-7-5-7-9V6z" }
                            path { d: "M9 12l2 2 4-4" }
                        }
                    }
                    div { style: "flex:1",
                        div { style: "font-size:14.5px;font-weight:700", "Built-in protections" }
                        div { style: "font-size:12px;color:var(--dim);margin-top:1px", "Deterministic rules at the heart of the gate. These never turn off." }
                    }
                    span { style: "font-size:11.5px;font-weight:600;color:var(--green);border:1px solid rgba(90,247,142,.3);border-radius:7px;padding:5px 10px;white-space:nowrap", "always on" }
                }

                for (name, examples) in builtins.iter() {
                    div { style: "display:flex;align-items:center;gap:14px;padding:14px 20px;border-bottom:1px solid var(--hair)",
                        span { style: "display:inline-flex;align-items:center;justify-content:center;width:22px;height:22px;border-radius:6px;flex:none;background:rgba(90,247,142,.12);color:var(--green);font-size:12px;font-weight:700", "✓" }
                        div { style: "flex:1;min-width:0",
                            div { style: "font-size:13.5px;font-weight:600;color:var(--ink)", "{name}" }
                            div { style: "font-family:'IBM Plex Mono',monospace;font-size:11.5px;color:var(--dim);margin-top:2px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap", "{examples}" }
                        }
                        span { style: "font-size:11px;font-weight:600;color:var(--green);flex:none", "always on" }
                    }
                }
                if builtins.is_empty() {
                    div { style: "padding:24px 20px;text-align:center;font-size:12.5px;color:var(--dim)", "◌ Loading protections…" }
                }
            }

            // ── (a2) Provenance tracking ─────────────────────────────────
            // Make the lethal-trifecta machinery legible: what the engine treats
            // as untrusted input, and what it counts as data leaving the machine.
            div { style: "border:1px solid var(--line);border-radius:14px;background:var(--panel);overflow:hidden;margin-bottom:18px",
                div { style: "display:flex;align-items:center;gap:12px;padding:15px 20px;border-bottom:1px solid var(--line);background:linear-gradient(100deg,rgba(212,175,55,.06),transparent)",
                    span { style: "display:inline-flex;align-items:center;justify-content:center;width:34px;height:34px;border-radius:9px;background:rgba(212,175,55,.13);flex:none",
                        svg { view_box: "0 0 24 24", width: "19", height: "19", fill: "none", stroke: "var(--gold)", stroke_width: "1.8", stroke_linecap: "round", stroke_linejoin: "round",
                            circle { cx: "6", cy: "6", r: "2.5" }
                            circle { cx: "18", cy: "18", r: "2.5" }
                            path { d: "M8 7.5l8 9" }
                        }
                    }
                    div { style: "flex:1",
                        div { style: "font-size:14.5px;font-weight:700", "Provenance tracking" }
                        div { style: "font-size:12px;color:var(--dim);margin-top:1px", "Untrusted input + a secret read + an egress sink → the lethal trifecta is blocked. These are the channels watched." }
                    }
                    span { style: "font-size:11.5px;font-weight:600;color:var(--gold);border:1px solid var(--gold-line);border-radius:7px;padding:5px 10px;white-space:nowrap", "tracked" }
                }

                // Untrusted sources (taint a session)
                div { style: "padding:13px 20px 6px;font-size:11px;font-weight:700;letter-spacing:.5px;text-transform:uppercase;color:var(--dim)", "Untrusted input — taints the session" }
                for (name, detail) in untrusted_sources.iter() {
                    div { style: "display:flex;align-items:center;gap:14px;padding:11px 20px;border-bottom:1px solid var(--hair)",
                        span { style: "display:inline-flex;align-items:center;justify-content:center;width:22px;height:22px;border-radius:6px;flex:none;background:rgba(212,175,55,.12);color:var(--gold);font-size:12px;font-weight:700", "↓" }
                        div { style: "flex:1;min-width:0",
                            div { style: "font-size:13.5px;font-weight:600;color:var(--ink)", "{name}" }
                            div { style: "font-size:11.5px;color:var(--dim);margin-top:2px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap", "{detail}" }
                        }
                    }
                }

                // Egress sinks (data leaves the machine)
                div { style: "padding:13px 20px 6px;font-size:11px;font-weight:700;letter-spacing:.5px;text-transform:uppercase;color:var(--dim)", "Egress — data leaves the machine" }
                for (name, detail) in egress_channels.iter() {
                    div { style: "display:flex;align-items:center;gap:14px;padding:11px 20px;border-bottom:1px solid var(--hair)",
                        span { style: "display:inline-flex;align-items:center;justify-content:center;width:22px;height:22px;border-radius:6px;flex:none;background:rgba(255,93,93,.12);color:var(--red);font-size:12px;font-weight:700", "↑" }
                        div { style: "flex:1;min-width:0",
                            div { style: "font-family:'IBM Plex Mono',monospace;font-size:13px;font-weight:600;color:var(--ink)", "{name}" }
                            div { style: "font-size:11.5px;color:var(--dim);margin-top:2px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap", "{detail}" }
                        }
                    }
                }
                if untrusted_sources.is_empty() && egress_channels.is_empty() {
                    div { style: "padding:24px 20px;text-align:center;font-size:12.5px;color:var(--dim)", "◌ Loading…" }
                }
            }

            // ── (b) Your policy ──────────────────────────────────────────
            div { style: "border:1px solid var(--line);border-radius:14px;background:var(--panel);overflow:hidden;margin-bottom:14px",
                div { style: "display:flex;align-items:center;gap:12px;padding:15px 20px;border-bottom:1px solid var(--line)",
                    span { style: "display:inline-flex;align-items:center;justify-content:center;width:34px;height:34px;border-radius:9px;background:rgba(212,175,55,.13);flex:none",
                        svg { view_box: "0 0 24 24", width: "19", height: "19", fill: "none", stroke: "var(--gold)", stroke_width: "1.8", stroke_linecap: "round", stroke_linejoin: "round",
                            path { d: "M4 7h16 M4 17h16 M9 5v4 M15 15v4" }
                        }
                    }
                    div { style: "flex:1",
                        div { style: "font-size:14.5px;font-weight:700", "Your policy" }
                        div { style: "font-size:12px;color:var(--dim);margin-top:1px", "The effective settings for this repo, merged global ← local." }
                    }
                }

                // mode + threshold + flags as a calm key/value grid
                div { style: "padding:18px 20px;border-bottom:1px solid var(--hair)",
                    div { style: "display:flex;align-items:flex-start;gap:14px",
                        div { style: "flex:1;min-width:0",
                            div { style: "font-size:11px;color:var(--dim);text-transform:uppercase;letter-spacing:.5px", "Mode" }
                            div { style: "font-size:14.5px;font-weight:700;margin-top:4px;color:{mode_color}", "{mode_label}" }
                            div { style: "font-size:12px;color:var(--dim);margin-top:2px;line-height:1.5", "{mode_note}" }
                        }
                    }

                    div { style: "display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-top:18px",
                        // ambiguous threshold
                        div { style: "border:1px solid var(--line);border-radius:10px;padding:13px 14px;background:var(--panel2)",
                            div { style: "font-size:11px;color:var(--dim);text-transform:uppercase;letter-spacing:.5px", "Ambiguous threshold" }
                            div { style: "font-size:22px;font-weight:700;font-family:'IBM Plex Mono',monospace;margin-top:5px;color:var(--gold)",
                                if let Some(p) = policy.as_ref() { "{p.threshold}" } else { "—" }
                            }
                            div { style: "font-size:11px;color:var(--dim);margin-top:2px", "risk at or above is paused" }
                        }
                        // provenance / trifecta
                        {
                            let on = policy.as_ref().map(|p| p.provenance_enabled);
                            let (glyph, word, color) = match on {
                                Some(true) => ("✓", "enabled", "var(--green)"),
                                Some(false) => ("○", "disabled", "var(--dim)"),
                                None => ("◌", "—", "var(--dim)"),
                            };
                            rsx! {
                                div { style: "border:1px solid var(--line);border-radius:10px;padding:13px 14px;background:var(--panel2)",
                                    div { style: "font-size:11px;color:var(--dim);text-transform:uppercase;letter-spacing:.5px", "Provenance / trifecta" }
                                    div { style: "font-size:15px;font-weight:700;margin-top:7px;color:{color};display:inline-flex;align-items:center;gap:7px", "{glyph} {word}" }
                                    div { style: "font-size:11px;color:var(--dim);margin-top:3px", "untrusted → secret → egress" }
                                }
                            }
                        }
                        // rule counts at a glance
                        div { style: "border:1px solid var(--line);border-radius:10px;padding:13px 14px;background:var(--panel2)",
                            div { style: "font-size:11px;color:var(--dim);text-transform:uppercase;letter-spacing:.5px", "Custom rules" }
                            div { style: "font-size:15px;font-weight:700;margin-top:7px;color:var(--ink);font-family:'IBM Plex Mono',monospace",
                                if let Some(p) = policy.as_ref() { "{p.allow.len()} allow · {p.deny.len()} deny" } else { "—" }
                            }
                            div { style: "font-size:11px;color:var(--dim);margin-top:3px", "your overrides, below" }
                        }
                    }
                }

                // allow list
                {
                    let allow: Vec<String> = policy.as_ref().map(|p| p.allow.clone()).unwrap_or_default();
                    rsx! {
                        div { style: "padding:16px 20px;border-bottom:1px solid var(--hair)",
                            div { style: "display:flex;align-items:center;gap:8px;margin-bottom:11px",
                                span { style: "font-size:12px;font-weight:700;color:var(--green)", "✓ Allow" }
                                span { style: "font-size:11.5px;color:var(--dim)", "patterns that always pass" }
                            }
                            if allow.is_empty() {
                                div { style: "font-size:12.5px;color:var(--dim);font-style:italic", "none set" }
                            } else {
                                div { style: "display:flex;flex-wrap:wrap;gap:8px",
                                    for pat in allow.iter() {
                                        span { style: "font-family:'IBM Plex Mono',monospace;font-size:12px;color:var(--ink);background:var(--panel2);border:1px solid rgba(90,247,142,.3);border-radius:7px;padding:5px 11px", "{pat}" }
                                    }
                                }
                            }
                        }
                    }
                }

                // deny list
                {
                    let deny: Vec<String> = policy.as_ref().map(|p| p.deny.clone()).unwrap_or_default();
                    rsx! {
                        div { style: "padding:16px 20px",
                            div { style: "display:flex;align-items:center;gap:8px;margin-bottom:11px",
                                span { style: "font-size:12px;font-weight:700;color:var(--red)", "✕ Deny" }
                                span { style: "font-size:11.5px;color:var(--dim)", "patterns that are always blocked" }
                            }
                            if deny.is_empty() {
                                div { style: "font-size:12.5px;color:var(--dim);font-style:italic", "none set" }
                            } else {
                                div { style: "display:flex;flex-wrap:wrap;gap:8px",
                                    for pat in deny.iter() {
                                        span { style: "font-family:'IBM Plex Mono',monospace;font-size:12px;color:var(--ink);background:var(--panel2);border:1px solid rgba(255,93,93,.34);border-radius:7px;padding:5px 11px", "{pat}" }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // ── (c) read-only footer ─────────────────────────────────────
            div { style: "display:flex;align-items:center;gap:9px;font-size:12.5px;color:var(--dim);padding:4px 2px",
                svg { view_box: "0 0 24 24", width: "14", height: "14", fill: "none", stroke: "var(--dim)", stroke_width: "1.8", stroke_linecap: "round", stroke_linejoin: "round", style: "flex:none",
                    rect { x: "4", y: "11", width: "16", height: "9", rx: "2" }
                    path { d: "M8 11V8a4 4 0 0 1 8 0v3" }
                }
                span {
                    "Edit "
                    span { style: "font-family:'IBM Plex Mono',monospace;color:var(--ink)", ".kintsugi.toml" }
                    " in your repo to change these."
                }
            }
        }
    }
}

#[component]
pub fn Placeholder() -> Element {
    let store = use_store();
    let (title, sub) = store.screen.read().meta();
    rsx! {
        div { style: "padding:26px;max-width:1000px;{FADE}",
            div { style: "border:1px solid var(--line);border-radius:14px;background:var(--panel);padding:30px 28px",
                div { style: "font-size:18px;font-weight:700;letter-spacing:-.2px", "{title}" }
                div { style: "font-size:13px;color:var(--dim);margin-top:6px;line-height:1.55;max-width:560px", "{sub}" }
                div { style: "margin-top:18px;display:inline-flex;align-items:center;gap:9px;font-size:12px;color:var(--gold);border:1px solid var(--gold-line);border-radius:8px;padding:8px 13px",
                    span { style: "width:7px;height:7px;border-radius:50%;background:var(--gold)" }
                    "Planned — V2."
                }
            }
        }
    }
}

#[cfg(test)]
mod prov_candidate_tests {
    use super::*;
    use crate::bindings::TimelineRow;

    fn row(session: Option<&str>, command: &str, provenance_block: bool) -> TimelineRow {
        TimelineRow {
            id: command.to_string(),
            ts: "2026-06-21T00:00:00Z".to_string(),
            agent: "claude-code".to_string(),
            session: session.map(str::to_string),
            command: command.to_string(),
            class: "ambiguous".to_string(),
            outcome: "held".to_string(),
            reason: if provenance_block {
                "TRIFECTA-01:provenance (sink)".to_string()
            } else {
                "safe:ls".to_string()
            },
            provenance_block,
            risk: None,
            summary: None,
            cwd: "/tmp".to_string(),
            tier: 1,
        }
    }

    #[test]
    fn only_trifecta_sessions_are_candidates() {
        // The fix: a clean session that merely carries an id must NOT appear —
        // the rail is "how untrusted content reached a risky command".
        let clean = vec![
            row(Some("clean-sess"), "grep foo .", false),
            row(Some("clean-sess"), "echo hi", false),
        ];
        assert!(
            prov_candidates(&clean).is_empty(),
            "a session with no trifecta event is not provenance"
        );

        // A session with a trifecta block appears exactly once (deduped), tainted,
        // and shows the newest trifecta command (not a later safe one).
        let dirty = vec![
            row(Some("dirty"), "newest-safe-cmd", false),
            row(Some("dirty"), "exfil-attempt-A", true),
            row(Some("dirty"), "exfil-attempt-B", true),
        ];
        let cands = prov_candidates(&dirty);
        assert_eq!(cands.len(), 1, "one row per session");
        assert_eq!(cands[0].session, "dirty");
        assert!(cands[0].tainted);
        assert_eq!(cands[0].command, "exfil-attempt-A", "newest trifecta wins the slot");
    }

    #[test]
    fn a_block_row_without_a_session_is_skipped() {
        let rows = vec![row(None, "exfil-attempt", true)];
        assert!(
            prov_candidates(&rows).is_empty(),
            "no session id → cannot chart provenance"
        );
    }
}
