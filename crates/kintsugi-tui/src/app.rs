//! TUI application state and input handling — pure and terminal-free, so it is
//! fully unit-testable. The render layer ([`crate::ui`]) and the event loop
//! ([`crate::run`]) build on this.

use crossterm::event::KeyCode;
use kintsugi_core::LoggedEvent;

/// Minimum usable terminal size; below this we show a "too small" notice.
pub const MIN_WIDTH: u16 = 60;
pub const MIN_HEIGHT: u16 = 10;

/// The human-facing word for a decision (shared by the list, detail, and filter).
pub fn outcome_word(d: kintsugi_core::Decision) -> &'static str {
    match d {
        kintsugi_core::Decision::Allow => "allowed",
        kintsugi_core::Decision::Deny => "denied",
        kintsugi_core::Decision::Hold => "held",
    }
}

/// A parsed filter query. Bare words are a substring match over the row's text;
/// `agent:`, `session:`, `since:`, and `before:` are structured predicates.
/// `since:`/`before:` take a relative age (`30m`, `2h`, `3d`, `day`, `week`,
/// `month`): `since:1h` = within the last hour, `before:1d` = older than a day.
#[derive(Default)]
struct Query {
    agent: Option<String>,
    session: Option<String>,
    since: Option<time::OffsetDateTime>,
    before: Option<time::OffsetDateTime>,
    text: String,
}

impl Query {
    fn parse(input: &str) -> Self {
        let mut q = Query::default();
        let mut text = Vec::new();
        for tok in input.split_whitespace() {
            if let Some(v) = tok.strip_prefix("agent:") {
                q.agent = Some(v.to_lowercase());
            } else if let Some(v) = tok.strip_prefix("session:") {
                q.session = Some(v.to_lowercase());
            } else if let Some(v) = tok.strip_prefix("since:") {
                q.since = parse_ago(v);
            } else if let Some(v) = tok.strip_prefix("before:") {
                q.before = parse_ago(v);
            } else {
                text.push(tok.to_lowercase());
            }
        }
        q.text = text.join(" ");
        q
    }

    fn matches(&self, e: &LoggedEvent) -> bool {
        if let Some(a) = &self.agent {
            if !e.agent.to_lowercase().contains(a) {
                return false;
            }
        }
        if let Some(s) = &self.session {
            if !e
                .session
                .as_deref()
                .is_some_and(|es| es.to_lowercase().contains(s))
            {
                return false;
            }
        }
        if let Some(since) = self.since {
            if e.ts < since {
                return false;
            }
        }
        if let Some(before) = self.before {
            if e.ts >= before {
                return false;
            }
        }
        if !self.text.is_empty() {
            let n = &self.text;
            let hit = e.command.to_lowercase().contains(n)
                || e.agent.to_lowercase().contains(n)
                || e.class.as_str().contains(n)
                || e.decision.as_str().contains(n)
                || outcome_word(e.decision).contains(n)
                || e.reason.to_lowercase().contains(n)
                || e.session
                    .as_deref()
                    .is_some_and(|s| s.to_lowercase().contains(n));
            if !hit {
                return false;
            }
        }
        true
    }
}

/// Parse a relative age spec into an absolute instant that long ago.
fn parse_ago(s: &str) -> Option<time::OffsetDateTime> {
    use time::{Duration, OffsetDateTime};
    let d = match s {
        "day" => Duration::days(1),
        "week" => Duration::weeks(1),
        "month" => Duration::days(30),
        _ => {
            let split = s.find(|c: char| c.is_alphabetic())?;
            let n: i64 = s[..split].parse().ok()?;
            match &s[split..] {
                "m" => Duration::minutes(n),
                "h" => Duration::hours(n),
                "d" => Duration::days(n),
                "w" => Duration::weeks(n),
                _ => return None,
            }
        }
    };
    Some(OffsetDateTime::now_utc() - d)
}

/// Which view/mode the UI is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// The timeline list.
    Normal,
    /// Editing the filter string.
    Filter,
    /// The detail view for the selected event.
    Detail,
}

/// The top-level views, switched with `Tab` / `1`,`2`,`3`. Each is the same
/// table over a different *slice* of the same live log — the structure (which
/// slice you're looking at) is the information, not decoration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    /// Everything, newest first — the full agent + human + watcher stream.
    Timeline,
    /// Only the destructive band (catastrophic + ambiguous) — the audit lens.
    Audit,
    /// Only passively-recorded human shell commands (agent = `shell`).
    Recorder,
}

impl Tab {
    /// All tabs in display order.
    pub const ALL: [Tab; 3] = [Tab::Timeline, Tab::Audit, Tab::Recorder];

    /// The short label shown in the tab bar.
    pub fn title(self) -> &'static str {
        match self {
            Tab::Timeline => "Timeline",
            Tab::Audit => "Audit",
            Tab::Recorder => "Recorder",
        }
    }

    /// One-line empty-state copy when this tab's slice is empty.
    pub fn empty_copy(self) -> &'static str {
        match self {
            Tab::Timeline => {
                "Run a command through a wired agent (or the $PATH shim) — it appears here."
            }
            Tab::Audit => {
                "Nothing destructive yet. Catastrophic and ambiguous commands surface here."
            }
            Tab::Recorder => {
                "No recorded shell sessions. Install the hook: kintsugi record install."
            }
        }
    }

    /// Whether an event belongs in this tab's slice.
    fn includes(self, e: &LoggedEvent) -> bool {
        match self {
            Tab::Timeline => true,
            Tab::Audit => e.class != kintsugi_core::Class::Safe,
            Tab::Recorder => e.agent == "shell",
        }
    }

    fn next(self) -> Tab {
        match self {
            Tab::Timeline => Tab::Audit,
            Tab::Audit => Tab::Recorder,
            Tab::Recorder => Tab::Timeline,
        }
    }
}

/// The top-level screen: launch animation, optional password gate, then the app.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    /// The animated launch logo (auto-advances; any key skips it).
    Splash,
    /// The admin password gate, shown when the settings vault is locked.
    Login,
    /// The live application (tabs, timeline, detail, …).
    Main,
    /// The settings control panel (view + toggle the locked settings).
    Settings,
}

/// The toggleable locked settings, in display order. Booleans flip; `Enforcement`
/// cycles. Every row is a *tightening* control — there is no row that loosens the
/// catastrophic floor (spine #1/#2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingRow {
    Recording,
    Autostart,
    RequirePasswordToStop,
    FailClosed,
    Enforcement,
}

impl SettingRow {
    pub const ALL: [SettingRow; 5] = [
        SettingRow::Recording,
        SettingRow::Autostart,
        SettingRow::RequirePasswordToStop,
        SettingRow::FailClosed,
        SettingRow::Enforcement,
    ];

    pub fn label(self) -> &'static str {
        match self {
            SettingRow::Recording => "recording",
            SettingRow::Autostart => "autostart",
            SettingRow::RequirePasswordToStop => "require-password-to-stop",
            SettingRow::FailClosed => "fail-closed",
            SettingRow::Enforcement => "enforcement",
        }
    }

    /// The current value of this row, as display text.
    pub fn value(self, s: &kintsugi_core::admin::LockedSettings) -> String {
        use kintsugi_core::admin::Enforcement;
        let yn = |b: bool| if b { "on" } else { "off" }.to_string();
        match self {
            SettingRow::Recording => yn(s.recording),
            SettingRow::Autostart => yn(s.autostart),
            SettingRow::RequirePasswordToStop => yn(s.require_password_to_stop),
            SettingRow::FailClosed => yn(s.fail_closed),
            SettingRow::Enforcement => match s.enforcement {
                Enforcement::Attended => "attended".into(),
                Enforcement::Unattended => "unattended".into(),
                Enforcement::Notify => "notify".into(),
            },
        }
    }

    /// Apply this row's toggle to the settings in place.
    fn apply(self, s: &mut kintsugi_core::admin::LockedSettings) {
        use kintsugi_core::admin::Enforcement;
        match self {
            SettingRow::Recording => s.recording = !s.recording,
            SettingRow::Autostart => s.autostart = !s.autostart,
            SettingRow::RequirePasswordToStop => {
                s.require_password_to_stop = !s.require_password_to_stop
            }
            SettingRow::FailClosed => s.fail_closed = !s.fail_closed,
            SettingRow::Enforcement => {
                s.enforcement = match s.enforcement {
                    Enforcement::Attended => Enforcement::Unattended,
                    Enforcement::Unattended => Enforcement::Notify,
                    Enforcement::Notify => Enforcement::Attended,
                }
            }
        }
    }
}

/// A side-effecting action the event loop must perform (kept out of pure state).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    None,
    Quit,
    Undo,
    /// Approve the held command with this id.
    Approve(String),
    /// Deny the held command with this id.
    Deny(String),
}

/// The whole UI state.
pub struct App {
    /// All loaded events, chronological (oldest first).
    events: Vec<LoggedEvent>,
    /// Selection index into the *filtered* view.
    pub selected: usize,
    /// The active filter string.
    pub filter: String,
    /// Current mode.
    pub mode: Mode,
    /// A transient status message (e.g. the result of an undo).
    pub status: Option<String>,
    /// Whether to use color (respects `NO_COLOR`).
    pub color: bool,
    /// Number of timeline data-rows visible in the last render, used as the step
    /// for `PageUp`/`PageDown`. Set by the renderer each frame; 0 until the first.
    pub page_rows: usize,
    /// The active top-level view.
    pub tab: Tab,
    /// Whether the daemon answered on the last refresh (for the vitals strip).
    pub daemon_up: bool,
    /// The active Tier-2 scorer backend id, if the daemon reported one.
    pub scorer: Option<String>,
    /// The current top-level screen (splash → [login] → main).
    pub screen: Screen,
    /// Animation frame for the launch splash (advanced by the event loop).
    pub splash_frame: usize,
    /// The sealed admin vault, when settings are locked (drives the login gate).
    pub vault: Option<kintsugi_core::admin::SealedVault>,
    /// Whether the admin password has been entered this session.
    pub authed: bool,
    /// The password being typed on the login screen (never echoed verbatim).
    /// Zeroized on drop and on a failed attempt so a wrong guess isn't left in
    /// freed heap.
    pub login_input: zeroize::Zeroizing<String>,
    /// The last login error, shown under the prompt.
    pub login_error: Option<String>,
    /// The verified admin password, held for the session so settings changes can
    /// re-seal the vault without re-prompting. Zeroized on drop.
    pub(crate) password: Option<zeroize::Zeroizing<String>>,
    /// The decrypted locked settings (populated on entering the Settings screen).
    pub settings: Option<kintsugi_core::admin::LockedSettings>,
    /// Selection index on the Settings screen.
    pub settings_selected: usize,
    /// Transient result/error line on the Settings screen.
    pub settings_status: Option<String>,
    /// The viewer's local UTC offset, captured once at startup. Events are stored
    /// in UTC; the timeline renders them in this offset. Defaults to UTC (also the
    /// value tests run with, for deterministic formatting).
    pub local_offset: time::UtcOffset,
}

impl App {
    pub fn new(color: bool) -> Self {
        Self {
            events: Vec::new(),
            selected: 0,
            filter: String::new(),
            mode: Mode::Normal,
            status: None,
            color,
            page_rows: 0,
            tab: Tab::Timeline,
            daemon_up: false,
            scorer: None,
            // Default to the live app; `run()` opts into the splash at startup, so
            // unit tests exercise the app directly without animating through it.
            screen: Screen::Main,
            splash_frame: 0,
            vault: None,
            authed: false,
            login_input: zeroize::Zeroizing::new(String::new()),
            login_error: None,
            password: None,
            settings: None,
            settings_selected: 0,
            settings_status: None,
            local_offset: time::UtcOffset::UTC,
        }
    }

    /// Set the local UTC offset used to render timestamps (called once at startup
    /// from [`crate::run`], where the process is single-threaded).
    pub fn set_local_offset(&mut self, offset: time::UtcOffset) {
        self.local_offset = offset;
    }

    /// How many events fall in a tab's slice (ignoring the active filter) — for
    /// the count badges in the tab bar.
    pub fn tab_total(&self, tab: Tab) -> usize {
        self.events.iter().filter(|e| tab.includes(e)).count()
    }

    /// Whether locked settings can be edited (provisioned + authenticated).
    pub fn settings_editable(&self) -> bool {
        self.vault.is_some() && self.password.is_some()
    }

    /// Open the Settings control panel. Decrypts the live settings when we can;
    /// otherwise falls back to defaults shown read-only (unprovisioned host).
    pub fn open_settings(&mut self) {
        if self.settings.is_none() {
            self.settings = match (&self.vault, &self.password) {
                (Some(v), Some(pw)) => v.unseal(pw).ok(),
                _ => None,
            };
        }
        if self.settings.is_none() {
            self.settings = Some(kintsugi_core::admin::LockedSettings::default());
        }
        self.settings_selected = 0;
        self.settings_status = None;
        self.screen = Screen::Settings;
    }

    /// Toggle the selected setting and re-seal the vault. Read-only when the host
    /// isn't provisioned/authenticated (then it only explains, never pretends).
    pub fn toggle_selected_setting(&mut self) {
        let Some(row) = SettingRow::ALL.get(self.settings_selected).copied() else {
            return;
        };
        if !self.settings_editable() {
            self.settings_status =
                Some("read-only — provision with `kintsugi admin provision` first".into());
            return;
        }
        let (Some(settings), Some(vault), Some(pw)) =
            (self.settings.as_mut(), &self.vault, &self.password)
        else {
            return;
        };
        row.apply(settings);
        // Re-seal under the held password and persist atomically.
        match vault.update_settings(pw, settings) {
            Ok(new_vault) => {
                let path = kintsugi_core::admin::default_vault_path();
                match kintsugi_core::admin::save_vault(&path, &new_vault) {
                    Ok(()) => {
                        self.vault = Some(new_vault);
                        self.settings_status =
                            Some(format!("saved · {} = {}", row.label(), row.value(settings)));
                    }
                    Err(e) => {
                        // Roll back the in-memory toggle so the screen matches disk.
                        row.apply(settings);
                        self.settings_status = Some(format!("could not save: {e}"));
                    }
                }
            }
            Err(e) => {
                row.apply(settings);
                self.settings_status = Some(format!("could not re-seal: {e}"));
            }
        }
    }

    /// Begin on the animated launch splash (used by `run()` at startup).
    pub fn start_on_splash(&mut self) {
        self.screen = Screen::Splash;
        self.splash_frame = 0;
    }

    /// Attach the loaded vault state. A `Locked` vault gates the app behind the
    /// admin password; `Unprovisioned`/`Degraded` leave it open (viewing the
    /// audit log was never password-gated — only *changing* settings is).
    pub fn set_vault(&mut self, vault: Option<kintsugi_core::admin::SealedVault>) {
        self.vault = vault;
    }

    /// Whether the password gate must be shown before the app.
    pub fn needs_login(&self) -> bool {
        self.vault.is_some() && !self.authed
    }

    /// Submit the typed password. On success, authenticate and enter the app;
    /// on failure, clear the field and show an error. The password never appears
    /// on the wire or in a log — only a constant-time verify against the vault.
    pub fn submit_login(&mut self) {
        // Move the typed buffer out (zeroized when dropped on the failure path).
        let input = std::mem::take(&mut self.login_input);
        match &self.vault {
            Some(v) if v.verify_password(input.as_str()) => {
                self.authed = true;
                self.password = Some(input);
                self.login_error = None;
                self.screen = Screen::Main;
            }
            Some(_) => {
                self.login_error = Some("incorrect password".to_string());
            }
            None => {
                // No vault → nothing to authenticate against; just enter.
                self.screen = Screen::Main;
            }
        }
    }

    /// Advance the splash animation one tick; once it completes, enter the app.
    /// Returns true while the splash is still showing (so the loop keeps the
    /// fast animation cadence).
    pub fn tick_splash(&mut self) -> bool {
        if self.screen != Screen::Splash {
            return false;
        }
        self.splash_frame += 1;
        if self.splash_frame >= crate::splash::FRAMES {
            self.enter_main();
        }
        self.screen == Screen::Splash
    }

    /// Leave the splash and show the application — via the login gate when the
    /// vault is locked and the password hasn't been entered yet.
    fn enter_main(&mut self) {
        self.screen = if self.needs_login() {
            Screen::Login
        } else {
            Screen::Main
        };
    }

    /// Counts for the header vitals strip: (total, held, catastrophic) over the
    /// full loaded set (not the filtered/tab slice — vitals are global).
    pub fn vitals(&self) -> (usize, usize, usize) {
        let mut held = 0;
        let mut catastrophic = 0;
        for e in &self.events {
            if e.decision == kintsugi_core::Decision::Hold {
                held += 1;
            }
            if e.class == kintsugi_core::Class::Catastrophic {
                catastrophic += 1;
            }
        }
        (self.events.len(), held, catastrophic)
    }

    /// Switch to a specific tab, resetting selection to the top of its slice.
    pub fn select_tab(&mut self, tab: Tab) {
        if self.tab != tab {
            self.tab = tab;
            self.selected = 0;
        }
    }

    /// Replace the event set (from a fresh log read), keeping selection in range.
    pub fn set_events(&mut self, events: Vec<LoggedEvent>) {
        self.events = events;
        self.clamp_selection();
    }

    /// Indices into `events` that match the active tab's slice AND the current
    /// filter (both must hold — the tab narrows, the filter narrows further).
    pub fn filtered_indices(&self) -> Vec<usize> {
        let q = Query::parse(&self.filter);
        self.events
            .iter()
            .enumerate()
            .filter(|(_, e)| self.tab.includes(e) && q.matches(e))
            .map(|(i, _)| i)
            .collect()
    }

    /// The events currently visible (after filtering), in display order.
    pub fn visible(&self) -> Vec<&LoggedEvent> {
        self.filtered_indices()
            .into_iter()
            .map(|i| &self.events[i])
            .collect()
    }

    /// The currently selected event, if any.
    pub fn selected_event(&self) -> Option<&LoggedEvent> {
        self.visible().get(self.selected).copied()
    }

    /// Whether there are no events at all (for the empty state).
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    fn visible_len(&self) -> usize {
        self.filtered_indices().len()
    }

    fn clamp_selection(&mut self) {
        let len = self.visible_len();
        if len == 0 {
            self.selected = 0;
        } else if self.selected >= len {
            self.selected = len - 1;
        }
    }

    /// Handle a keypress, returning any side-effecting action for the loop.
    pub fn on_key(&mut self, key: KeyCode) -> Action {
        // On the splash, any key except quit skips straight into the app (or the
        // login gate, if the vault is locked).
        if self.screen == Screen::Splash {
            if matches!(key, KeyCode::Char('q') | KeyCode::Esc) {
                return Action::Quit;
            }
            self.enter_main();
            return Action::None;
        }
        if self.screen == Screen::Login {
            return self.on_key_login(key);
        }
        if self.screen == Screen::Settings {
            return self.on_key_settings(key);
        }
        // A keypress dismisses a transient status message.
        self.status = None;
        match self.mode {
            Mode::Normal => self.on_key_normal(key),
            Mode::Filter => self.on_key_filter(key),
            Mode::Detail => self.on_key_detail(key),
        }
    }

    /// Settings screen: j/k move, enter/space toggle, esc/q back to the app.
    fn on_key_settings(&mut self, key: KeyCode) -> Action {
        match key {
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('s') => {
                self.screen = Screen::Main;
            }
            KeyCode::Char('j') | KeyCode::Down => {
                if self.settings_selected + 1 < SettingRow::ALL.len() {
                    self.settings_selected += 1;
                }
                self.settings_status = None;
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.settings_selected = self.settings_selected.saturating_sub(1);
                self.settings_status = None;
            }
            KeyCode::Enter | KeyCode::Char(' ') => self.toggle_selected_setting(),
            _ => {}
        }
        Action::None
    }

    /// Login screen: type the password, Enter submits, Esc quits (no bypass).
    fn on_key_login(&mut self, key: KeyCode) -> Action {
        match key {
            KeyCode::Esc => return Action::Quit,
            KeyCode::Enter => self.submit_login(),
            KeyCode::Backspace => {
                self.login_input.pop();
            }
            KeyCode::Char(c) => self.login_input.push(c),
            _ => {}
        }
        Action::None
    }

    fn on_key_normal(&mut self, key: KeyCode) -> Action {
        match key {
            KeyCode::Char('q') | KeyCode::Esc => return Action::Quit,
            KeyCode::Char('j') | KeyCode::Down => self.move_down(),
            KeyCode::Char('k') | KeyCode::Up => self.move_up(),
            // Space/b are the primary page keys (pager convention) since Mac
            // keyboards lack PageUp/PageDown; f and PgUp/PgDn are aliases.
            KeyCode::Char(' ') | KeyCode::Char('f') | KeyCode::PageDown => self.page_down(),
            KeyCode::Char('b') | KeyCode::PageUp => self.page_up(),
            KeyCode::Char('g') | KeyCode::Home => self.selected = 0,
            KeyCode::Char('G') | KeyCode::End => {
                let len = self.visible_len();
                self.selected = len.saturating_sub(1);
            }
            KeyCode::Enter => {
                if self.selected_event().is_some() {
                    self.mode = Mode::Detail;
                }
            }
            KeyCode::Char('/') => {
                self.mode = Mode::Filter;
            }
            // Tab cycles views; 1/2/3 jump straight to one (the bar shows order).
            KeyCode::Tab | KeyCode::BackTab => self.select_tab(self.tab.next()),
            KeyCode::Char('1') => self.select_tab(Tab::Timeline),
            KeyCode::Char('2') => self.select_tab(Tab::Audit),
            KeyCode::Char('3') => self.select_tab(Tab::Recorder),
            KeyCode::Char('u') => return Action::Undo,
            KeyCode::Char('a') => return self.resolve_selected(true),
            KeyCode::Char('d') => return self.resolve_selected(false),
            KeyCode::Char('s') => self.open_settings(),
            _ => {}
        }
        Action::None
    }

    /// Approve/deny the selected row, but only if it is actually a held command.
    fn resolve_selected(&self, approve: bool) -> Action {
        match self.selected_event() {
            Some(ev) if ev.decision == kintsugi_core::Decision::Hold => {
                let id = ev.id.to_string();
                if approve {
                    Action::Approve(id)
                } else {
                    Action::Deny(id)
                }
            }
            _ => Action::None,
        }
    }

    fn on_key_filter(&mut self, key: KeyCode) -> Action {
        match key {
            KeyCode::Enter | KeyCode::Esc => self.mode = Mode::Normal,
            KeyCode::Backspace => {
                self.filter.pop();
                self.clamp_selection();
            }
            KeyCode::Char(c) => {
                self.filter.push(c);
                self.selected = 0;
            }
            _ => {}
        }
        Action::None
    }

    fn on_key_detail(&mut self, key: KeyCode) -> Action {
        match key {
            KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => self.mode = Mode::Normal,
            KeyCode::Char('j') | KeyCode::Down => {
                self.move_down();
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.move_up();
            }
            _ => {}
        }
        Action::None
    }

    fn move_down(&mut self) {
        let len = self.visible_len();
        if len > 0 && self.selected + 1 < len {
            self.selected += 1;
        }
    }

    fn move_up(&mut self) {
        self.selected = self.selected.saturating_sub(1);
    }

    /// Step the selection down by one screenful (the last-rendered row count,
    /// at least 1), clamped to the last row.
    fn page_down(&mut self) {
        let len = self.visible_len();
        if len == 0 {
            return;
        }
        let step = self.page_rows.max(1);
        self.selected = (self.selected + step).min(len - 1);
    }

    /// Step the selection up by one screenful.
    fn page_up(&mut self) {
        let step = self.page_rows.max(1);
        self.selected = self.selected.saturating_sub(step);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kintsugi_core::{Class, Decision, EventLog, ProposedCommand, Verdict};

    fn ev(agent: &str, raw: &str, class: Class, decision: Decision) -> LoggedEvent {
        let log = EventLog::open_in_memory().unwrap();
        let cmd = ProposedCommand::new(agent, "/tmp", vec![raw.into()], raw);
        log.log_event(&cmd, &Verdict::rules(class, decision, "r"), None)
            .unwrap()
    }

    fn sample_app() -> App {
        let mut app = App::new(false);
        app.set_events(vec![
            ev("claude-code", "ls", Class::Safe, Decision::Allow),
            ev("shim", "rm -rf /", Class::Catastrophic, Decision::Hold),
            ev("qwen", "make build", Class::Ambiguous, Decision::Hold),
        ]);
        app
    }

    fn ev_session(agent: &str, session: &str, raw: &str) -> LoggedEvent {
        let log = EventLog::open_in_memory().unwrap();
        let cmd = ProposedCommand::new(agent, "/tmp", vec![raw.into()], raw)
            .with_session(Some(session.into()));
        log.log_event(
            &cmd,
            &Verdict::rules(Class::Safe, Decision::Allow, "r"),
            None,
        )
        .unwrap()
    }

    #[test]
    fn page_keys_step_by_a_screenful_and_clamp() {
        let mut app = App::new(false);
        let many: Vec<_> = (0..50)
            .map(|i| ev("shim", &format!("cmd {i}"), Class::Safe, Decision::Allow))
            .collect();
        app.set_events(many);
        app.page_rows = 10;

        // PageDown jumps a screenful, never past the last row.
        app.on_key(KeyCode::PageDown);
        assert_eq!(app.selected, 10);
        // Space is the Mac-friendly alias and pages identically.
        app.on_key(KeyCode::Char(' '));
        assert_eq!(app.selected, 20);

        // PageUp steps back symmetrically and clamps at the top.
        app.on_key(KeyCode::PageUp);
        assert_eq!(app.selected, 10);
        app.on_key(KeyCode::PageUp);
        app.on_key(KeyCode::PageUp);
        assert_eq!(app.selected, 0);

        // Near the end, PageDown stops on the last row rather than overshooting.
        app.on_key(KeyCode::End);
        assert_eq!(app.selected, 49);
        app.on_key(KeyCode::PageDown);
        assert_eq!(app.selected, 49);
    }

    #[test]
    fn structured_filter_tokens() {
        let mut app = App::new(false);
        app.set_events(vec![
            ev_session("claude-code", "s1", "ls"),
            ev_session("claude-code", "s2", "make build"),
            ev_session("cursor", "s2", "npm test"),
        ]);

        app.filter = "agent:claude-code".into();
        assert_eq!(app.visible().len(), 2);

        app.filter = "session:s2".into();
        assert_eq!(app.visible().len(), 2);

        app.filter = "agent:cursor session:s2".into();
        assert_eq!(app.visible().len(), 1);

        // Structured token + free text combine (AND).
        app.filter = "agent:claude-code build".into();
        assert_eq!(app.visible().len(), 1);

        // Recent window includes everything just logged.
        app.filter = "since:1h".into();
        assert_eq!(app.visible().len(), 3);

        // Empty filter shows all.
        app.filter = String::new();
        assert_eq!(app.visible().len(), 3);
    }

    #[test]
    fn parse_ago_accepts_known_forms() {
        assert!(parse_ago("10m").is_some());
        assert!(parse_ago("2h").is_some());
        assert!(parse_ago("3d").is_some());
        assert!(parse_ago("week").is_some());
        assert!(parse_ago("nonsense").is_none());
        assert!(parse_ago("5x").is_none());
    }

    #[test]
    fn navigation_clamps() {
        let mut app = sample_app();
        assert_eq!(app.selected, 0);
        app.on_key(KeyCode::Char('k')); // up at top stays
        assert_eq!(app.selected, 0);
        app.on_key(KeyCode::Char('j'));
        app.on_key(KeyCode::Char('j'));
        app.on_key(KeyCode::Char('j')); // past end clamps
        assert_eq!(app.selected, 2);
        app.on_key(KeyCode::Char('g'));
        assert_eq!(app.selected, 0);
        app.on_key(KeyCode::Char('G'));
        assert_eq!(app.selected, 2);
    }

    #[test]
    fn quit_and_undo_actions() {
        let mut app = sample_app();
        assert_eq!(app.on_key(KeyCode::Char('u')), Action::Undo);
        assert_eq!(app.on_key(KeyCode::Char('q')), Action::Quit);
        assert_eq!(app.on_key(KeyCode::Esc), Action::Quit);
    }

    #[test]
    fn approve_deny_only_on_held_rows() {
        let mut app = sample_app();
        // Row 0 is the allowed `ls` → a/d do nothing.
        app.selected = 0;
        assert_eq!(app.on_key(KeyCode::Char('a')), Action::None);
        assert_eq!(app.on_key(KeyCode::Char('d')), Action::None);
        // Row 1 is the held `rm -rf /` → a/d resolve it.
        app.selected = 1;
        let held_id = app.selected_event().unwrap().id.to_string();
        assert_eq!(
            app.on_key(KeyCode::Char('a')),
            Action::Approve(held_id.clone())
        );
        assert_eq!(app.on_key(KeyCode::Char('d')), Action::Deny(held_id));
    }

    #[test]
    fn filter_mode_edits_and_narrows() {
        let mut app = sample_app();
        app.on_key(KeyCode::Char('/'));
        assert_eq!(app.mode, Mode::Filter);
        for c in "rm".chars() {
            app.on_key(KeyCode::Char(c));
        }
        assert_eq!(app.filter, "rm");
        assert_eq!(app.visible().len(), 1);
        assert_eq!(app.visible()[0].command, "rm -rf /");
        app.on_key(KeyCode::Backspace);
        app.on_key(KeyCode::Backspace);
        assert_eq!(app.visible().len(), 3);
        app.on_key(KeyCode::Enter);
        assert_eq!(app.mode, Mode::Normal);
    }

    #[test]
    fn enter_opens_detail_and_esc_closes() {
        let mut app = sample_app();
        app.on_key(KeyCode::Enter);
        assert_eq!(app.mode, Mode::Detail);
        assert!(app.selected_event().is_some());
        app.on_key(KeyCode::Esc);
        assert_eq!(app.mode, Mode::Normal);
    }

    #[test]
    fn empty_app_is_safe() {
        let mut app = App::new(false);
        assert!(app.is_empty());
        assert!(app.selected_event().is_none());
        // Keys never panic on an empty list.
        app.on_key(KeyCode::Char('j'));
        app.on_key(KeyCode::Enter);
        assert_eq!(app.mode, Mode::Normal);
    }

    #[test]
    fn tabs_slice_the_log_and_compose_with_filter() {
        let mut app = App::new(false);
        app.set_events(vec![
            ev("claude-code", "ls", Class::Safe, Decision::Allow),
            ev("shim", "rm -rf /", Class::Catastrophic, Decision::Hold),
            ev("qwen", "make build", Class::Ambiguous, Decision::Hold),
            // A passively-recorded human command (agent = shell).
            ev("shell", "psql prod", Class::Safe, Decision::Allow),
        ]);

        // Timeline shows everything.
        assert_eq!(app.tab, Tab::Timeline);
        assert_eq!(app.visible().len(), 4);

        // Audit = destructive band only (catastrophic + ambiguous).
        app.on_key(KeyCode::Char('2'));
        assert_eq!(app.tab, Tab::Audit);
        assert_eq!(app.visible().len(), 2);
        assert!(app.visible().iter().all(|e| e.class != Class::Safe));

        // Recorder = agent == shell only.
        app.on_key(KeyCode::Char('3'));
        assert_eq!(app.tab, Tab::Recorder);
        assert_eq!(app.visible().len(), 1);
        assert_eq!(app.visible()[0].command, "psql prod");

        // Tab cycles back to Timeline.
        app.on_key(KeyCode::Tab);
        assert_eq!(app.tab, Tab::Timeline);

        // Tab predicate AND the text filter both apply.
        app.on_key(KeyCode::Char('2')); // Audit
        app.filter = "rm".into();
        assert_eq!(app.visible().len(), 1);
        assert_eq!(app.visible()[0].command, "rm -rf /");
    }

    #[test]
    fn vitals_count_held_and_catastrophic_globally() {
        let mut app = App::new(false);
        app.set_events(vec![
            ev("claude-code", "ls", Class::Safe, Decision::Allow),
            ev("shim", "rm -rf /", Class::Catastrophic, Decision::Hold),
            ev("qwen", "make build", Class::Ambiguous, Decision::Hold),
        ]);
        // Vitals are global (independent of the active tab/filter).
        app.on_key(KeyCode::Char('3')); // Recorder (empty slice)
        assert_eq!(app.visible().len(), 0);
        assert_eq!(app.vitals(), (3, 2, 1)); // total, held, catastrophic
    }

    #[test]
    fn splash_ticks_to_main_and_any_key_skips_it() {
        let mut app = App::new(false);
        app.start_on_splash();
        assert_eq!(app.screen, Screen::Splash);
        // Ticking eventually completes the animation and enters the app.
        for _ in 0..crate::splash::FRAMES {
            app.tick_splash();
        }
        assert_eq!(app.screen, Screen::Main);

        // From the splash, a non-quit key skips straight in; quit still quits.
        let mut app = App::new(false);
        app.start_on_splash();
        assert_eq!(app.on_key(KeyCode::Char('j')), Action::None);
        assert_eq!(app.screen, Screen::Main);

        let mut app = App::new(false);
        app.start_on_splash();
        assert_eq!(app.on_key(KeyCode::Char('q')), Action::Quit);
    }

    // Runtime-built test password (not a hard-coded credential literal).
    fn test_pw(tag: &str) -> String {
        format!("kintsugi-test-pw-{}-{tag}", std::process::id())
    }

    #[test]
    fn login_gate_blocks_until_correct_password() {
        let password = test_pw("ok");
        let prov = kintsugi_core::admin::provision(
            &password,
            &kintsugi_core::admin::LockedSettings::default(),
        )
        .unwrap();
        let mut app = App::new(false);
        app.set_vault(Some(prov.vault));
        app.start_on_splash();

        // Skipping the splash lands on the login gate (vault is locked).
        app.on_key(KeyCode::Char(' '));
        assert_eq!(app.screen, Screen::Login);

        // A wrong password is rejected and stays on the gate.
        for c in test_pw("bad").chars() {
            app.on_key(KeyCode::Char(c));
        }
        app.on_key(KeyCode::Enter);
        assert_eq!(app.screen, Screen::Login);
        assert!(app.login_error.is_some());
        assert!(app.login_input.is_empty(), "field cleared after a failure");

        // The correct password authenticates and enters the app.
        for c in password.chars() {
            app.on_key(KeyCode::Char(c));
        }
        app.on_key(KeyCode::Enter);
        assert_eq!(app.screen, Screen::Main);
        assert!(app.authed);

        // Esc on the gate quits rather than bypassing it.
        let mut app2 = App::new(false);
        app2.set_vault(Some(
            kintsugi_core::admin::provision(
                &test_pw("other"),
                &kintsugi_core::admin::LockedSettings::default(),
            )
            .unwrap()
            .vault,
        ));
        app2.start_on_splash();
        app2.on_key(KeyCode::Char(' '));
        assert_eq!(app2.on_key(KeyCode::Esc), Action::Quit);
    }

    #[test]
    fn settings_screen_toggles_persist_to_the_sealed_vault() {
        // Isolate the vault on disk so the toggle's save round-trips.
        let dir = tempfile::tempdir().unwrap();
        let vault_path = dir.path().join("vault.json");
        std::env::set_var("KINTSUGI_VAULT", &vault_path);

        let password = test_pw("ok");
        let prov = kintsugi_core::admin::provision(
            &password,
            &kintsugi_core::admin::LockedSettings::default(),
        )
        .unwrap();
        kintsugi_core::admin::save_vault(&vault_path, &prov.vault).unwrap();

        let mut app = App::new(false);
        app.set_vault(Some(prov.vault));
        // Authenticate (so the password is held for re-sealing).
        app.start_on_splash();
        app.on_key(KeyCode::Char(' ')); // skip splash → Login
        for c in password.chars() {
            app.on_key(KeyCode::Char(c));
        }
        app.on_key(KeyCode::Enter);
        assert_eq!(app.screen, Screen::Main);

        // Open settings, move to "recording" (row 0), and toggle it off.
        app.on_key(KeyCode::Char('s'));
        assert_eq!(app.screen, Screen::Settings);
        assert!(app.settings_editable());
        assert!(app.settings.as_ref().unwrap().recording);
        app.on_key(KeyCode::Enter); // toggle recording
        assert!(!app.settings.as_ref().unwrap().recording);
        assert!(app.settings_status.as_deref().unwrap().contains("saved"));

        // The change is durable: re-load the vault from disk and unseal it.
        let reloaded = match kintsugi_core::admin::load_vault(&vault_path) {
            kintsugi_core::admin::VaultState::Locked(v) => *v,
            _ => panic!("vault should be locked"),
        };
        let s = reloaded.unseal(&password).unwrap();
        assert!(!s.recording, "toggle must persist to disk");

        std::env::remove_var("KINTSUGI_VAULT");
    }

    #[test]
    fn settings_are_read_only_without_a_vault() {
        let mut app = App::new(false);
        app.open_settings();
        assert_eq!(app.screen, Screen::Settings);
        assert!(!app.settings_editable());
        // Toggling explains rather than pretending to change anything.
        let before = app.settings.clone();
        app.on_key(KeyCode::Enter);
        assert_eq!(app.settings, before);
        assert!(app
            .settings_status
            .as_deref()
            .unwrap()
            .contains("read-only"));
    }

    #[test]
    fn no_vault_skips_the_login_gate() {
        let mut app = App::new(false);
        app.start_on_splash();
        app.on_key(KeyCode::Char(' '));
        assert_eq!(app.screen, Screen::Main);
        assert!(!app.needs_login());
    }

    #[test]
    fn switching_tab_resets_selection() {
        let mut app = sample_app();
        app.selected = 2;
        app.on_key(KeyCode::Char('2'));
        assert_eq!(app.selected, 0);
    }

    #[test]
    fn filter_for_nothing_clamps_selection() {
        let mut app = sample_app();
        app.selected = 2;
        app.on_key(KeyCode::Char('/'));
        for c in "zzz".chars() {
            app.on_key(KeyCode::Char(c));
        }
        assert_eq!(app.visible().len(), 0);
        assert!(app.selected_event().is_none());
    }
}
