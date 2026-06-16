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
        }
    }

    /// Replace the event set (from a fresh log read), keeping selection in range.
    pub fn set_events(&mut self, events: Vec<LoggedEvent>) {
        self.events = events;
        self.clamp_selection();
    }

    /// Indices into `events` that match the current filter.
    pub fn filtered_indices(&self) -> Vec<usize> {
        let q = Query::parse(&self.filter);
        self.events
            .iter()
            .enumerate()
            .filter(|(_, e)| q.matches(e))
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
        // A keypress dismisses a transient status message.
        self.status = None;
        match self.mode {
            Mode::Normal => self.on_key_normal(key),
            Mode::Filter => self.on_key_filter(key),
            Mode::Detail => self.on_key_detail(key),
        }
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
            KeyCode::Char('u') => return Action::Undo,
            KeyCode::Char('a') => return self.resolve_selected(true),
            KeyCode::Char('d') => return self.resolve_selected(false),
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
