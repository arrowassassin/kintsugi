//! TUI application state and input handling — pure and terminal-free, so it is
//! fully unit-testable. The render layer ([`crate::ui`]) and the event loop
//! ([`crate::run`]) build on this.

use aegis_core::LoggedEvent;
use crossterm::event::KeyCode;

/// Minimum usable terminal size; below this we show a "too small" notice.
pub const MIN_WIDTH: u16 = 60;
pub const MIN_HEIGHT: u16 = 10;

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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    None,
    Quit,
    Undo,
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
        }
    }

    /// Replace the event set (from a fresh log read), keeping selection in range.
    pub fn set_events(&mut self, events: Vec<LoggedEvent>) {
        self.events = events;
        self.clamp_selection();
    }

    /// Indices into `events` that match the current filter.
    pub fn filtered_indices(&self) -> Vec<usize> {
        if self.filter.is_empty() {
            return (0..self.events.len()).collect();
        }
        let needle = self.filter.to_lowercase();
        self.events
            .iter()
            .enumerate()
            .filter(|(_, e)| {
                e.command.to_lowercase().contains(&needle)
                    || e.agent.to_lowercase().contains(&needle)
                    || e.class.as_str().contains(&needle)
                    || e.decision.as_str().contains(&needle)
                    || e.reason.to_lowercase().contains(&needle)
            })
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
            _ => {}
        }
        Action::None
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::{Class, Decision, EventLog, ProposedCommand, Verdict};

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
