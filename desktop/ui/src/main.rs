//! Kintsugi Control Room — Dioxus (WASM) frontend.
//!
//! A dashboard, not a gate: it renders what the daemon and the append-only event
//! log already decided. Data arrives over Tauri `invoke`, deserialized into the
//! shared [`kintsugi_app_types`] view-models (the same types the native engine
//! returns — one compiler-checked contract, no npm, no hand-kept JSON shape).
//!
//! Design language carried from the codebase's TUI rules into the GUI: calm until
//! it must shout — one gold seam accent, the single danger accent reserved for a
//! trifecta block; every state pairs a glyph or word with color (never color
//! alone); mono for every command, path, and source id; designed empty states.

use dioxus::prelude::*;
use kintsugi_app_types::{
    ChainVerify, EngineStatus, Metrics, ProvenanceView, QueueRow, TimelineRow,
};

mod invoke;
use invoke::invoke;

fn main() {
    dioxus::launch(App);
}

/// How often the dashboard re-polls the daemon for live updates (ms).
const POLL_MS: u32 = 1500;

/// The top-level screens (the left-nav).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Screen {
    Dashboard,
    Feed,
    Queue,
    Audit,
    Settings,
}

impl Screen {
    const ALL: [Screen; 5] = [
        Screen::Dashboard,
        Screen::Feed,
        Screen::Queue,
        Screen::Audit,
        Screen::Settings,
    ];
    fn glyph(self) -> &'static str {
        match self {
            Screen::Dashboard => "◑",
            Screen::Feed => "≋",
            Screen::Queue => "❚",
            Screen::Audit => "✓",
            Screen::Settings => "⚙",
        }
    }
    fn label(self) -> &'static str {
        match self {
            Screen::Dashboard => "Dashboard",
            Screen::Feed => "Live feed",
            Screen::Queue => "Held queue",
            Screen::Audit => "Audit log",
            Screen::Settings => "Settings",
        }
    }
}

// ---- args structs (serialize to the Tauri command parameter shapes) ----------
#[derive(serde::Serialize)]
struct LimitArgs {
    limit: usize,
}
#[derive(serde::Serialize)]
struct AuditArgs {
    query: String,
    limit: usize,
}
#[derive(serde::Serialize)]
struct ProvenanceArgs {
    session: String,
    command: Option<String>,
}
#[derive(serde::Serialize)]
struct ResolveArgs {
    id: String,
    allow: bool,
}
/// Serializes to `{}` for commands that take no arguments.
#[derive(serde::Serialize)]
struct NoArgs {}

#[component]
fn App() -> Element {
    let screen = use_signal(|| Screen::Dashboard);
    let selected = use_signal(|| None::<TimelineRow>);

    // A tick that increments on a timer so the data resources re-fetch — live
    // updates without a restart, the non-blocking way (the await never freezes the
    // render loop).
    let tick = use_signal(|| 0u64);
    use_future(move || async move {
        let mut tick = tick;
        loop {
            gloo_timers::future::TimeoutFuture::new(POLL_MS).await;
            tick += 1;
        }
    });

    let status = use_resource(move || async move {
        tick();
        invoke::<EngineStatus, _>("status", NoArgs {}).await.ok()
    });

    rsx! {
        div { class: "app",
            Sidebar { screen, status: status().flatten() }
            main { class: "stage",
                match screen() {
                    Screen::Dashboard => rsx! { Dashboard { tick, screen, selected } },
                    Screen::Feed => rsx! { Feed { tick, selected } },
                    Screen::Queue => rsx! { Queue { tick } },
                    Screen::Audit => rsx! { Audit { tick, selected } },
                    Screen::Settings => rsx! { Settings { status: status().flatten() } },
                }
            }
        }
    }
}

#[component]
fn Sidebar(screen: Signal<Screen>, status: Option<EngineStatus>) -> Element {
    let up = status.as_ref().map(|s| s.running).unwrap_or(false);
    rsx! {
        nav { class: "sidebar",
            div { class: "brand",
                span { class: "seam", aria_hidden: "true" }
                div {
                    h1 { "Kintsugi" }
                    span { class: "subtitle", "Control Room" }
                }
            }
            ul { class: "nav", role: "list",
                for s in Screen::ALL {
                    {
                        let glyph = s.glyph();
                        let label = s.label();
                        let cls = if screen() == s { "nav-item active" } else { "nav-item" };
                        rsx! {
                            li {
                                class: "{cls}",
                                onclick: move |_| screen.set(s),
                                span { class: "nav-glyph", aria_hidden: "true", "{glyph}" }
                                span { "{label}" }
                            }
                        }
                    }
                }
            }
            div { class: "engine-state",
                if up {
                    span { class: "pill up", "● engine up" }
                } else {
                    span { class: "pill down", "○ engine down" }
                }
            }
        }
    }
}

// ---- Dashboard ---------------------------------------------------------------
#[component]
fn Dashboard(
    tick: Signal<u64>,
    screen: Signal<Screen>,
    selected: Signal<Option<TimelineRow>>,
) -> Element {
    let metrics = use_resource(move || async move {
        tick();
        invoke::<Metrics, _>("metrics", NoArgs {})
            .await
            .unwrap_or_default()
    });
    let recent = use_resource(move || async move {
        tick();
        invoke::<Vec<TimelineRow>, _>("timeline", LimitArgs { limit: 8 })
            .await
            .unwrap_or_default()
    });
    let held = use_resource(move || async move {
        tick();
        invoke::<Vec<QueueRow>, _>("queue", NoArgs {})
            .await
            .unwrap_or_default()
    });

    let m = metrics().unwrap_or_default();
    let rows = recent().unwrap_or_default();
    let queue_len = held().map(|q| q.len()).unwrap_or(0);

    rsx! {
        Header { title: "Dashboard" }
        if queue_len > 0 {
            div { class: "alert",
                span { class: "glyph", "❚" }
                span { "{queue_len} command(s) held for your decision." }
                button { class: "btn", onclick: move |_| screen.set(Screen::Queue), "Review" }
            }
        }
        div { class: "cards",
            Card { label: "Commands", value: "{m.total}", tone: "" }
            Card { label: "Allowed", value: "{m.allowed}", tone: "ok" }
            Card { label: "Held", value: "{m.held}", tone: "warn" }
            Card { label: "Blocked", value: "{m.denied}", tone: "danger" }
            Card { label: "Trifecta blocks", value: "{m.trifecta_blocks}", tone: "danger" }
        }
        section { class: "panel",
            div { class: "panel-head", h2 { "Recent activity" } }
            if rows.is_empty() {
                p { class: "empty", "All quiet — no recent activity." }
            } else {
                ul { class: "rows", role: "list",
                    for row in rows {
                        Row { row, selected }
                    }
                }
            }
        }
        Detail { selected, refresh: tick }
    }
}

#[component]
fn Card(label: String, value: String, tone: String) -> Element {
    rsx! {
        div { class: "card",
            span { class: "card-value tone-{tone}", "{value}" }
            span { class: "card-label", "{label}" }
        }
    }
}

// ---- Live feed ---------------------------------------------------------------
#[component]
fn Feed(tick: Signal<u64>, selected: Signal<Option<TimelineRow>>) -> Element {
    let filter = use_signal(String::new);
    let rows = use_resource(move || async move {
        tick();
        invoke::<Vec<TimelineRow>, _>("timeline", LimitArgs { limit: 200 })
            .await
            .unwrap_or_default()
    });
    let needle = filter().to_lowercase();
    let visible: Vec<TimelineRow> = rows()
        .unwrap_or_default()
        .into_iter()
        .filter(|r| needle.is_empty() || r.command.to_lowercase().contains(&needle))
        .collect();

    rsx! {
        Header { title: "Live feed" }
        div { class: "split",
            section { class: "panel",
                div { class: "panel-head",
                    h2 { "Commands" }
                    FilterBox { filter }
                }
                RowList { rows: visible, selected, empty: "All quiet. Intercepted commands appear here as your agents work." }
            }
            Detail { selected, refresh: tick }
        }
    }
}

// ---- Held queue --------------------------------------------------------------
#[component]
fn Queue(tick: Signal<u64>) -> Element {
    let items = use_resource(move || async move {
        tick();
        invoke::<Vec<QueueRow>, _>("queue", NoArgs {})
            .await
            .unwrap_or_default()
    });
    let q = items().unwrap_or_default();

    rsx! {
        Header { title: "Held queue" }
        if q.is_empty() {
            div { class: "panel", p { class: "empty", "Nothing held. Kintsugi only interrupts when it must." } }
        } else {
            div { class: "queue",
                for item in q {
                    QueueCard { item, tick }
                }
            }
        }
    }
}

#[component]
fn QueueCard(item: QueueRow, tick: Signal<u64>) -> Element {
    let id_allow = item.id.clone();
    let id_deny = item.id.clone();
    rsx! {
        article { class: if item.provenance_block { "qcard trifecta" } else { "qcard" },
            div { class: "decision",
                span { class: "badge held", "held" }
                span { class: "muted", "{item.class}" }
                if item.provenance_block {
                    span { class: "badge trifecta", "⛔ lethal-trifecta" }
                }
            }
            pre { class: "command", "{item.command}" }
            dl { class: "meta",
                dt { "agent" } dd { "{item.agent}" }
                dt { "reason" } dd { "{item.reason}" }
            }
            div { class: "actions",
                button {
                    class: "btn allow",
                    onclick: move |_| {
                        let id = id_allow.clone();
                        let mut tick = tick;
                        async move {
                            let _ = invoke::<bool, _>("resolve", ResolveArgs { id, allow: true }).await;
                            tick += 1;
                        }
                    },
                    "Allow once"
                }
                button {
                    class: "btn deny",
                    onclick: move |_| {
                        let id = id_deny.clone();
                        let mut tick = tick;
                        async move {
                            let _ = invoke::<bool, _>("resolve", ResolveArgs { id, allow: false }).await;
                            tick += 1;
                        }
                    },
                    "Deny"
                }
            }
        }
    }
}

// ---- Audit log ---------------------------------------------------------------
#[component]
fn Audit(tick: Signal<u64>, selected: Signal<Option<TimelineRow>>) -> Element {
    let query = use_signal(String::new);
    let chain = use_resource(move || async move {
        tick();
        invoke::<ChainVerify, _>("verify", NoArgs {}).await.ok()
    });
    let results = use_resource(move || async move {
        let q = query();
        invoke::<Vec<TimelineRow>, _>(
            "audit",
            AuditArgs {
                query: q,
                limit: 300,
            },
        )
        .await
        .unwrap_or_default()
    });
    let rows = results().unwrap_or_default();

    rsx! {
        Header { title: "Audit log" }
        if let Some(Some(v)) = chain() {
            ChainBadge { verify: v }
        }
        div { class: "split",
            section { class: "panel",
                div { class: "panel-head",
                    h2 { "Search" }
                    FilterBox { filter: query }
                }
                RowList { rows, selected, empty: "No commands match." }
            }
            Detail { selected, refresh: tick }
        }
    }
}

#[component]
fn ChainBadge(verify: ChainVerify) -> Element {
    let length = verify.length;
    let seq = verify.broken_seq.unwrap_or(0);
    let detail = verify.detail.clone().unwrap_or_default();
    let cls = if verify.intact {
        "chain ok"
    } else {
        "chain broken"
    };
    rsx! {
        div { class: "{cls}",
            if verify.intact {
                span { "✓ hash chain intact — {length} events, tamper-evident" }
            } else {
                span { "⛔ hash chain BROKEN at #{seq}: {detail}" }
            }
        }
    }
}

// ---- Settings ----------------------------------------------------------------
#[component]
fn Settings(status: Option<EngineStatus>) -> Element {
    let (up, scorer) = match status {
        Some(s) => (s.running, s.scorer),
        None => (false, None),
    };
    let engine_txt = if up { "running" } else { "not reachable" };
    let scorer_txt = scorer.unwrap_or_else(|| "—".to_string());
    let version = env!("CARGO_PKG_VERSION");
    rsx! {
        Header { title: "Settings" }
        section { class: "panel",
            dl { class: "meta wide",
                dt { "engine" } dd { "{engine_txt}" }
                dt { "scorer" } dd { "{scorer_txt}" }
                dt { "version" } dd { "{version}" }
            }
            p { class: "muted",
                "Kintsugi runs locally. This window is a dashboard — the gate is the daemon, "
                "which decides deterministically whether or not this app is open."
            }
        }
    }
}

// ---- shared pieces -----------------------------------------------------------
#[component]
fn Header(title: String) -> Element {
    rsx! { header { class: "stage-head", h2 { "{title}" } } }
}

#[component]
fn FilterBox(filter: Signal<String>) -> Element {
    rsx! {
        input {
            class: "filter",
            r#type: "search",
            placeholder: "filter…",
            aria_label: "Filter",
            value: "{filter}",
            oninput: move |e| filter.set(e.value()),
        }
    }
}

#[component]
fn RowList(
    rows: Vec<TimelineRow>,
    selected: Signal<Option<TimelineRow>>,
    empty: String,
) -> Element {
    if rows.is_empty() {
        return rsx! { p { class: "empty", "{empty}" } };
    }
    rsx! {
        ul { class: "rows", role: "list",
            for row in rows {
                Row { row, selected }
            }
        }
    }
}

#[component]
fn Row(row: TimelineRow, selected: Signal<Option<TimelineRow>>) -> Element {
    let is_sel = selected().as_ref().map(|s| s.id == row.id).unwrap_or(false);
    let class = format!(
        "row{}{}",
        if is_sel { " selected" } else { "" },
        if row.provenance_block {
            " trifecta"
        } else {
            ""
        }
    );
    let pick = row.clone();
    rsx! {
        li {
            class: "{class}",
            onclick: move |_| selected.set(Some(pick.clone())),
            span { class: "agent", "{row.agent}" }
            span { class: "cmd", "{row.command}" }
            span { class: "badge {row.outcome}", "{row.outcome}" }
        }
    }
}

#[component]
fn Detail(selected: Signal<Option<TimelineRow>>, refresh: Signal<u64>) -> Element {
    let Some(ev) = selected() else {
        return rsx! {
            section { class: "panel detail",
                div { class: "empty", "Select a command to see why Kintsugi decided what it did." }
            }
        };
    };

    let session = ev.session.clone();
    let command = ev.command.clone();
    let trail = use_resource(move || {
        let session = session.clone();
        let command = command.clone();
        async move {
            refresh();
            let session = session?;
            invoke::<ProvenanceView, _>(
                "provenance",
                ProvenanceArgs {
                    session,
                    command: Some(command),
                },
            )
            .await
            .ok()
        }
    });

    let sess = ev.session.clone().unwrap_or_default();
    let trail_view = trail().flatten();
    rsx! {
        section { class: "panel detail",
            article {
                div { class: "decision",
                    span { class: "badge {ev.outcome}", "{ev.outcome}" }
                    span { class: "muted", "{ev.class}" }
                    if ev.provenance_block {
                        span { class: "badge trifecta", "⛔ lethal-trifecta" }
                    }
                }
                pre { class: "command", "{ev.command}" }
                dl { class: "meta",
                    dt { "agent" } dd { "{ev.agent}" }
                    dt { "session" } dd { "{sess}" }
                    dt { "reason" } dd { "{ev.reason}" }
                }
                if let Some(view) = trail_view {
                    if view.tainted && !view.trail.is_empty() {
                        Trail { view }
                    }
                }
            }
        }
    }
}

#[component]
fn Trail(view: ProvenanceView) -> Element {
    rsx! {
        section { class: "trail-wrap",
            h3 { "Provenance trail" }
            ol { class: "trail", aria_label: "How untrusted content reached this command",
                for step in view.trail {
                    {
                        let (glyph, label) = step.glyph_label();
                        let li_class = if step.is_rule() { "rule" } else { "" };
                        let value = step.value().to_string();
                        rsx! {
                            li { class: "{li_class}",
                                span { class: "dot", aria_hidden: "true" }
                                span { class: "glyph", "{glyph}" }
                                span { class: "step-label", "{label}  " }
                                span { class: "val", "{value}" }
                            }
                        }
                    }
                }
            }
        }
    }
}
