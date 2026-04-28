use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::model::{CommandAction, OpsSnapshot, Pane, ViewMode};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppIntent {
    None,
    Quit,
    Refresh,
    Execute(CommandAction),
    AllowApproval(String),
    DenyApproval(String),
}

#[derive(Debug, Clone)]
pub struct App {
    snapshot: OpsSnapshot,
    active_pane: Pane,
    mode: ViewMode,
    selected_env: usize,
    selected_approval: usize,
    command_buffer: String,
    status: Option<String>,
    dirty: bool,
}

impl App {
    pub fn new(snapshot: OpsSnapshot) -> Self {
        Self {
            snapshot,
            active_pane: Pane::Envs,
            mode: ViewMode::Normal,
            selected_env: 0,
            selected_approval: 0,
            command_buffer: String::new(),
            status: None,
            dirty: true,
        }
    }

    pub fn active_pane(&self) -> Pane {
        self.active_pane
    }

    pub fn mode(&self) -> ViewMode {
        self.mode
    }

    pub fn selected_env_name(&self) -> Option<&str> {
        self.snapshot
            .envs
            .get(self.selected_env)
            .map(|row| row.name.as_str())
    }

    pub fn selected_env_index(&self) -> usize {
        self.selected_env
    }

    pub fn selected_approval_index(&self) -> usize {
        self.selected_approval
    }

    pub fn status(&self) -> Option<&str> {
        self.status.as_deref()
    }

    pub fn command_buffer(&self) -> &str {
        &self.command_buffer
    }

    pub fn snapshot(&self) -> &OpsSnapshot {
        &self.snapshot
    }

    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    pub fn take_dirty(&mut self) -> bool {
        let dirty = self.dirty;
        self.dirty = false;
        dirty
    }

    pub fn apply_snapshot(&mut self, snapshot: OpsSnapshot) {
        if self.snapshot != snapshot {
            self.snapshot = snapshot;
            if self.selected_env >= self.snapshot.envs.len() {
                self.selected_env = self.snapshot.envs.len().saturating_sub(1);
            }
            if self.selected_approval >= self.snapshot.approvals.len() {
                self.selected_approval = self.snapshot.approvals.len().saturating_sub(1);
            }
            self.dirty = true;
        }
    }

    pub fn set_status(&mut self, status: impl Into<String>) {
        self.status = Some(status.into());
        self.dirty = true;
    }

    pub fn clear_status(&mut self) {
        self.status = None;
        self.dirty = true;
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> AppIntent {
        if self.mode == ViewMode::Command {
            return self.handle_command_key(key);
        }

        match key.code {
            KeyCode::Char('q') => AppIntent::Quit,
            KeyCode::Tab => {
                self.active_pane = match self.active_pane {
                    Pane::Envs => Pane::Events,
                    Pane::Events => Pane::Approvals,
                    Pane::Approvals => Pane::Detail,
                    Pane::Detail => Pane::Envs,
                };
                self.dirty = true;
                AppIntent::None
            }
            KeyCode::BackTab => {
                self.active_pane = match self.active_pane {
                    Pane::Envs => Pane::Detail,
                    Pane::Events => Pane::Envs,
                    Pane::Approvals => Pane::Events,
                    Pane::Detail => Pane::Approvals,
                };
                self.dirty = true;
                AppIntent::None
            }
            KeyCode::Char('j') => self.move_selection(1),
            KeyCode::Char('k') => self.move_selection(-1),
            KeyCode::Char('A') if key.modifiers.contains(KeyModifiers::SHIFT) => {
                self.active_pane = Pane::Approvals;
                self.dirty = true;
                AppIntent::None
            }
            KeyCode::Char('L') if key.modifiers.contains(KeyModifiers::SHIFT) => {
                self.mode = ViewMode::Logs;
                self.dirty = true;
                AppIntent::None
            }
            KeyCode::Char('P') if key.modifiers.contains(KeyModifiers::SHIFT) => {
                self.mode = ViewMode::Policy;
                self.dirty = true;
                AppIntent::None
            }
            KeyCode::Char('?') => {
                self.mode = ViewMode::Help;
                self.dirty = true;
                AppIntent::None
            }
            KeyCode::Esc => {
                self.mode = ViewMode::Normal;
                self.dirty = true;
                AppIntent::None
            }
            KeyCode::Char(':') => {
                self.mode = ViewMode::Command;
                self.command_buffer.clear();
                self.dirty = true;
                AppIntent::None
            }
            KeyCode::Char(ch) if self.active_pane == Pane::Envs && ch.is_ascii_lowercase() => {
                let index = (ch as u8 - b'a') as usize;
                if index < self.snapshot.envs.len() {
                    self.selected_env = index;
                    self.dirty = true;
                    AppIntent::Refresh
                } else {
                    AppIntent::None
                }
            }
            KeyCode::Char('y') | KeyCode::Char('a') if self.active_pane == Pane::Approvals => self
                .selected_approval_id()
                .map(AppIntent::AllowApproval)
                .unwrap_or(AppIntent::None),
            KeyCode::Char('n') | KeyCode::Char('d') if self.active_pane == Pane::Approvals => self
                .selected_approval_id()
                .map(AppIntent::DenyApproval)
                .unwrap_or(AppIntent::None),
            _ => AppIntent::None,
        }
    }

    fn move_selection(&mut self, delta: isize) -> AppIntent {
        match self.active_pane {
            Pane::Envs => {
                self.selected_env = move_index(self.selected_env, self.snapshot.envs.len(), delta);
                self.dirty = true;
                AppIntent::Refresh
            }
            Pane::Approvals => {
                self.selected_approval =
                    move_index(self.selected_approval, self.snapshot.approvals.len(), delta);
                self.dirty = true;
                AppIntent::None
            }
            Pane::Events | Pane::Detail => AppIntent::None,
        }
    }

    fn handle_command_key(&mut self, key: KeyEvent) -> AppIntent {
        match key.code {
            KeyCode::Esc => {
                self.mode = ViewMode::Normal;
                self.command_buffer.clear();
                self.dirty = true;
                AppIntent::None
            }
            KeyCode::Enter => {
                let command = self.command_buffer.clone();
                self.mode = ViewMode::Normal;
                self.command_buffer.clear();
                self.dirty = true;
                match crate::command::parse_command(&command) {
                    Ok(action) => AppIntent::Execute(action),
                    Err(error) => {
                        self.status = Some(error);
                        AppIntent::None
                    }
                }
            }
            KeyCode::Backspace => {
                self.command_buffer.pop();
                self.dirty = true;
                AppIntent::None
            }
            KeyCode::Char(ch) => {
                self.command_buffer.push(ch);
                self.dirty = true;
                AppIntent::None
            }
            _ => AppIntent::None,
        }
    }

    fn selected_approval_id(&self) -> Option<String> {
        self.snapshot
            .approvals
            .get(self.selected_approval)
            .map(|row| row.request_id.clone())
    }
}

fn move_index(current: usize, len: usize, delta: isize) -> usize {
    if len == 0 {
        return 0;
    }
    if delta.is_negative() {
        current.saturating_sub(delta.unsigned_abs()).min(len - 1)
    } else {
        current.saturating_add(delta as usize).min(len - 1)
    }
}

#[cfg(test)]
mod tests {
    use super::{App, AppIntent};
    use crate::model::{ApprovalRow, CommandAction, EnvRow, OpsSnapshot, Pane, ViewMode};
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn app_with_rows() -> App {
        App::new(OpsSnapshot {
            envs: vec![
                EnvRow {
                    name: "alpha".to_owned(),
                    agent: "codex".to_owned(),
                    sandbox: "openshell".to_owned(),
                    context: "filesystem".to_owned(),
                    status: "running".to_owned(),
                },
                EnvRow {
                    name: "beta".to_owned(),
                    agent: "claude".to_owned(),
                    sandbox: "openshell".to_owned(),
                    context: "mcp".to_owned(),
                    status: "running".to_owned(),
                },
            ],
            approvals: vec![ApprovalRow {
                request_id: "req_1".to_owned(),
                env: "alpha".to_owned(),
                agent: Some("codex".to_owned()),
                subject: "api.stripe.com:443".to_owned(),
                reason: "egress".to_owned(),
            }],
            ..OpsSnapshot::empty()
        })
    }

    #[test]
    fn tab_cycles_panes() {
        let mut app = app_with_rows();

        assert_eq!(app.handle_key(key(KeyCode::Tab)), AppIntent::None);

        assert_eq!(app.active_pane(), Pane::Events);
        assert!(app.is_dirty());
    }

    #[test]
    fn backtab_cycles_panes_backward() {
        let mut app = app_with_rows();

        assert_eq!(app.handle_key(key(KeyCode::BackTab)), AppIntent::None);

        assert_eq!(app.active_pane(), Pane::Detail);
    }

    #[test]
    fn jump_letter_selects_env_by_index() {
        let mut app = app_with_rows();

        assert_eq!(app.handle_key(key(KeyCode::Char('b'))), AppIntent::Refresh);

        assert_eq!(app.selected_env_name(), Some("beta"));
    }

    #[test]
    fn approval_keys_emit_intents_in_approval_pane() {
        let mut app = app_with_rows();
        app.handle_key(KeyEvent::new(KeyCode::Char('A'), KeyModifiers::SHIFT));

        assert_eq!(
            app.handle_key(key(KeyCode::Char('y'))),
            AppIntent::AllowApproval("req_1".to_owned())
        );
        assert_eq!(
            app.handle_key(key(KeyCode::Char('n'))),
            AppIntent::DenyApproval("req_1".to_owned())
        );
        assert_eq!(
            app.handle_key(key(KeyCode::Char('a'))),
            AppIntent::AllowApproval("req_1".to_owned())
        );
        assert_eq!(
            app.handle_key(key(KeyCode::Char('d'))),
            AppIntent::DenyApproval("req_1".to_owned())
        );
    }

    #[test]
    fn command_mode_parses_destroy() {
        let mut app = app_with_rows();
        app.handle_key(key(KeyCode::Char(':')));
        for ch in "destroy alpha".chars() {
            app.handle_key(key(KeyCode::Char(ch)));
        }

        assert_eq!(
            app.handle_key(key(KeyCode::Enter)),
            AppIntent::Execute(CommandAction::DestroyEnv("alpha".to_owned()))
        );
    }

    #[test]
    fn command_mode_tracks_buffer_and_escape_cancels() {
        let mut app = app_with_rows();
        app.handle_key(key(KeyCode::Char(':')));
        app.handle_key(key(KeyCode::Char('x')));
        app.handle_key(key(KeyCode::Char('y')));
        app.handle_key(key(KeyCode::Backspace));

        assert_eq!(app.command_buffer(), "x");
        assert_eq!(app.handle_key(key(KeyCode::Esc)), AppIntent::None);
        assert_eq!(app.mode(), ViewMode::Normal);
        assert_eq!(app.command_buffer(), "");
    }

    #[test]
    fn invalid_command_sets_status() {
        let mut app = app_with_rows();
        app.handle_key(key(KeyCode::Char(':')));

        assert_eq!(app.handle_key(key(KeyCode::Enter)), AppIntent::None);

        assert_eq!(app.status(), Some("empty command"));
    }

    #[test]
    fn help_overlay_toggles() {
        let mut app = app_with_rows();

        app.handle_key(key(KeyCode::Char('?')));
        assert_eq!(app.mode(), ViewMode::Help);
        app.handle_key(key(KeyCode::Esc));
        assert_eq!(app.mode(), ViewMode::Normal);
    }

    #[test]
    fn shortcuts_switch_modes_and_panes() {
        let mut app = app_with_rows();

        app.handle_key(KeyEvent::new(KeyCode::Char('L'), KeyModifiers::SHIFT));
        assert_eq!(app.mode(), ViewMode::Logs);
        app.handle_key(KeyEvent::new(KeyCode::Char('P'), KeyModifiers::SHIFT));
        assert_eq!(app.mode(), ViewMode::Policy);
        app.handle_key(KeyEvent::new(KeyCode::Char('A'), KeyModifiers::SHIFT));
        assert_eq!(app.active_pane(), Pane::Approvals);
    }

    #[test]
    fn dirty_flag_can_be_cleared_and_set_again() {
        let mut app = app_with_rows();
        assert!(app.take_dirty());
        assert!(!app.take_dirty());

        app.handle_key(key(KeyCode::Tab));

        assert!(app.take_dirty());
    }

    #[test]
    fn status_mutators_mark_dirty() {
        let mut app = app_with_rows();
        app.take_dirty();

        app.set_status("working");
        assert_eq!(app.status(), Some("working"));
        assert!(app.take_dirty());

        app.clear_status();
        assert_eq!(app.status(), None);
        assert!(app.take_dirty());
    }

    #[test]
    fn snapshot_update_clamps_selection() {
        let mut app = app_with_rows();
        assert_eq!(app.handle_key(key(KeyCode::Char('b'))), AppIntent::Refresh);
        assert_eq!(app.selected_env_name(), Some("beta"));

        app.apply_snapshot(OpsSnapshot {
            envs: vec![EnvRow {
                name: "alpha".to_owned(),
                agent: "codex".to_owned(),
                sandbox: "openshell".to_owned(),
                context: "filesystem".to_owned(),
                status: "running".to_owned(),
            }],
            ..OpsSnapshot::empty()
        });

        assert_eq!(app.selected_env_name(), Some("alpha"));
    }

    #[test]
    fn empty_rows_are_safe_to_navigate() {
        let mut app = App::new(OpsSnapshot::empty());

        assert_eq!(app.selected_env_name(), None);
        assert_eq!(app.handle_key(key(KeyCode::Char('j'))), AppIntent::Refresh);
        assert_eq!(app.handle_key(key(KeyCode::Char('k'))), AppIntent::Refresh);
        assert_eq!(app.handle_key(key(KeyCode::Char('a'))), AppIntent::None);

        app.handle_key(KeyEvent::new(KeyCode::Char('A'), KeyModifiers::SHIFT));
        assert_eq!(app.handle_key(key(KeyCode::Char('y'))), AppIntent::None);
        assert_eq!(app.handle_key(key(KeyCode::Char('n'))), AppIntent::None);
    }

    #[test]
    fn snapshot_accessor_returns_current_snapshot() {
        let app = app_with_rows();

        assert_eq!(app.snapshot().envs.len(), 2);
    }
}
