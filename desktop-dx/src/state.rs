//! App state. One `Store` of `Copy` signals shared via context — the Rust
//! analogue of the original component's `this.state`.

use dioxus::prelude::*;
use crate::theme::Theme;

/// The four stops of the first-run setup wizard. `Welcome` is the intro;
/// `Password` proposes setting a master password; `Model` proposes picking a
/// local model; `Done` is the success card with a "What can it do?" pointer.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum WizardStep {
    Welcome,
    Password,
    Model,
    Done,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ToastKind {
    Success,
    Error,
    Info,
}

#[derive(Clone, PartialEq, Eq)]
pub struct Toast {
    pub id: u64,
    pub kind: ToastKind,
    pub message: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Dashboard,
    Held,
    Feed,
    Provenance,
    Recorder,
    Audit,
    Policy,
    Snapshots,
    Settings,
    Verified,
    Capability,
    Fleet,
}

impl Screen {
    /// Title + subtitle shown in the title bar and topbar.
    pub fn meta(self) -> (&'static str, &'static str) {
        use Screen::*;
        match self {
            Dashboard => ("Home", "A calm overview of what your agents are doing"),
            Held => ("Needs review", "One command is paused, waiting for your decision"),
            Feed => ("Activity", "Everything your agents do, as it happens"),
            Provenance => ("Where it came from", "How untrusted content reached a risky command"),
            Recorder => ("Recorder", "Also records what you type in the terminal — no AI needed"),
            Audit => ("History", "What Kintsugi held or blocked — the tamper-proof enforcement record"),
            Policy => ("Rules", "What gets allowed, paused, or blocked"),
            Snapshots => ("Undo", "Restore points saved before anything destructive"),
            Settings => ("Settings", "Protection, recording, and how agents are connected"),
            Verified => ("Verified gate", "Proven-correct safety guarantees — planned for V2"),
            Capability => ("Capability scopes", "Give each tool only what it needs — planned for V2"),
            Fleet => ("Team & fleet", "Manage protection across a whole team — planned for V2"),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ModelStatus {
    None,
    Downloading,
    Installed,
}

/// All signals are `Copy`, so the whole store is `Copy` and can be pulled from
/// context anywhere with `use_store()` and mutated directly.
#[derive(Clone, Copy)]
pub struct Store {
    pub screen: Signal<Screen>,
    pub nav_open: Signal<bool>,
    pub theme: Signal<Theme>,

    // auth
    pub unlocked: Signal<bool>,
    pub pw: Signal<String>,
    pub pw_error: Signal<bool>,
    pub attempts: Signal<u32>,
    /// Master password held in memory for the unlocked session, so privileged
    /// ops (daemon shutdown) can sign the daemon's challenge without re-prompting.
    /// Cleared on lock; `None` until the first successful unlock. `Zeroizing` so
    /// the bytes are scrubbed when the value is dropped or overwritten.
    pub session_pw: Signal<Option<zeroize::Zeroizing<String>>>,

    // held command
    pub held_resolved: Signal<Option<&'static str>>, // "denied" | "allowed" | "always"
    pub panic: Signal<bool>,

    // activity feed
    pub feed_filter: Signal<&'static str>, // all | held | blocked | tainted
    pub feed_search: Signal<String>,
    pub feed_page: Signal<usize>,

    // settings
    pub recording: Signal<bool>,
    pub watchdog: Signal<bool>,
    pub fail_closed: Signal<bool>,
    pub require_pw: Signal<bool>,
    pub autostart: Signal<bool>,

    // local model
    pub model_status: Signal<ModelStatus>,
    pub model_id: Signal<Option<&'static str>>,
    pub model_progress: Signal<f64>,
    pub model_search: Signal<String>,

    /// The activity row whose detail drawer is open (None = closed). Any screen
    /// sets this on a row click; the drawer renders at the app shell.
    pub detail: Signal<Option<crate::bindings::TimelineRow>>,

    /// Stack of transient notifications shown at the bottom-right. Push via
    /// `Store::toast(...)`; each entry auto-dismisses after a few seconds.
    pub toasts: Signal<Vec<Toast>>,

    /// First-run setup wizard step (None = not active / dismissed).
    pub wizard_step: Signal<Option<WizardStep>>,
    /// Whether the always-available help drawer is open.
    pub help_open: Signal<bool>,

    // live-refresh heartbeats. `tick` fires every 250ms and drives the light
    // reads (row lists, engine status); `slow_tick` fires every 2s for the heavy
    // aggregates (metrics full-scan, chain verify) so a 4 Hz refresh never
    // re-runs a full-table scan and reintroduces the lag we just fixed.
    pub tick: Signal<u64>,
    pub slow_tick: Signal<u64>,
}

pub const FEED_PAGE_SIZE: usize = 9;

impl Store {
    pub fn new() -> Self {
        // Restore the user's persisted look (theme + menu-bar visibility) so the
        // app reopens the way they left it; defaults to dark + menu-open.
        let (theme0, nav_open0) = crate::bindings::load_ui_prefs();
        Store {
            screen: Signal::new(Screen::Dashboard),
            nav_open: Signal::new(nav_open0),
            theme: Signal::new(theme0),
            unlocked: Signal::new(false),
            pw: Signal::new(String::new()),
            pw_error: Signal::new(false),
            attempts: Signal::new(0),
            session_pw: Signal::new(None),
            held_resolved: Signal::new(None),
            panic: Signal::new(false),
            feed_filter: Signal::new("all"),
            feed_search: Signal::new(String::new()),
            feed_page: Signal::new(1),
            recording: Signal::new(true),
            watchdog: Signal::new(true),
            fail_closed: Signal::new(true),
            require_pw: Signal::new(true),
            autostart: Signal::new(true),
            model_status: Signal::new(ModelStatus::None),
            model_id: Signal::new(None),
            model_progress: Signal::new(0.0),
            model_search: Signal::new(String::new()),
            detail: Signal::new(None),
            toasts: Signal::new(Vec::new()),
            wizard_step: Signal::new(None),
            help_open: Signal::new(false),
            tick: Signal::new(0),
            slow_tick: Signal::new(0),
        }
    }

    /// Push a toast and return its id (so the caller can dismiss it early).
    pub fn toast(&mut self, kind: ToastKind, message: impl Into<String>) -> u64 {
        let mut toasts = self.toasts.write();
        let id = toasts.last().map(|t| t.id + 1).unwrap_or(1);
        toasts.push(Toast { id, kind, message: message.into() });
        id
    }
    pub fn dismiss_toast(&mut self, id: u64) {
        self.toasts.write().retain(|t| t.id != id);
    }

    pub fn try_unlock(&mut self) {
        let attempts = *self.attempts.read();
        if attempts >= 5 {
            return;
        }
        // Verify against the REAL argon2id master-password vault (in-process). If
        // no password has been set yet, the first unlock is allowed and the user
        // is invited to set one in Settings.
        let pw = self.pw.read().clone();
        if crate::bindings::verify_master_password(&pw) {
            self.unlocked.set(true);
            // Hold the password for the session so Stop can authenticate to the
            // daemon without asking again (you already proved it at login).
            self.session_pw.set(Some(zeroize::Zeroizing::new(pw)));
            self.pw.set(String::new());
            self.pw_error.set(false);
            self.attempts.set(0);
        } else {
            self.pw_error.set(true);
            self.pw.set(String::new());
            self.attempts.set(attempts + 1);
        }
    }

    pub fn lock(&mut self) {
        self.unlocked.set(false);
        self.session_pw.set(None);
        self.pw.set(String::new());
        self.pw_error.set(false);
        self.screen.set(Screen::Dashboard);
    }
}

pub fn use_store() -> Store {
    use_context::<Store>()
}
