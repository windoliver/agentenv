#![forbid(unsafe_code)]

/// Placeholder surface for the M1 workspace scaffold.
pub const CRATE_NAME: &str = "tui";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalPaneRow {
    pub request_id: String,
    pub env: String,
    pub kind: String,
    pub subject: String,
    pub reason: String,
    pub age: String,
    pub expires_in: String,
    pub default_scope: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalPaneAction {
    Approve { request_id: String, scope: String },
    Deny { request_id: String },
    Refresh,
    Close,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalPaneKey {
    ApproveDefault,
    Deny,
    Refresh,
    Close,
    Down,
    Up,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalPaneState {
    rows: Vec<ApprovalPaneRow>,
    selected_index: Option<usize>,
}

pub fn render_approval_pane_text(state: &ApprovalPaneState) -> String {
    use std::fmt::Write as _;

    let mut output = String::new();
    output.push_str("PENDING APPROVALS\n");
    if state.rows().is_empty() {
        output.push_str("No pending approvals\n");
        return output;
    }

    let _ = writeln!(
        output,
        "{:<2} {:<20} {:<26} {:<16} {:<24} {:<12} {:<12} {:<22} REASON",
        "", "ENV", "REQUEST", "KIND", "SUBJECT", "AGE", "EXPIRES", "DEFAULT_SCOPE"
    );
    for (index, row) in state.rows().iter().enumerate() {
        let marker = if state.selected_index() == Some(index) {
            ">"
        } else {
            ""
        };
        let _ = writeln!(
            output,
            "{:<2} {:<20} {:<26} {:<16} {:<24} {:<12} {:<12} {:<22} {}",
            marker,
            row.env,
            row.request_id,
            row.kind,
            truncate_cell(&row.subject, 24),
            row.age,
            row.expires_in,
            row.default_scope,
            row.reason
        );
    }
    output
}

impl ApprovalPaneState {
    pub fn new(rows: Vec<ApprovalPaneRow>) -> Self {
        let selected_index = first_index(&rows);
        Self {
            rows,
            selected_index,
        }
    }

    pub fn rows(&self) -> &[ApprovalPaneRow] {
        &self.rows
    }

    pub fn selected_index(&self) -> Option<usize> {
        self.selected_index
    }

    pub fn selected_row(&self) -> Option<&ApprovalPaneRow> {
        self.selected_index.and_then(|index| self.rows.get(index))
    }

    pub fn set_rows(&mut self, rows: Vec<ApprovalPaneRow>) {
        self.rows = rows;
        self.selected_index = self
            .selected_index
            .filter(|index| *index < self.rows.len())
            .or_else(|| first_index(&self.rows));
    }

    pub fn handle_key(&mut self, key: ApprovalPaneKey) -> Option<ApprovalPaneAction> {
        match key {
            ApprovalPaneKey::ApproveDefault => {
                self.selected_row().map(|row| ApprovalPaneAction::Approve {
                    request_id: row.request_id.clone(),
                    scope: row.default_scope.clone(),
                })
            }
            ApprovalPaneKey::Deny => self.selected_row().map(|row| ApprovalPaneAction::Deny {
                request_id: row.request_id.clone(),
            }),
            ApprovalPaneKey::Refresh => Some(ApprovalPaneAction::Refresh),
            ApprovalPaneKey::Close => Some(ApprovalPaneAction::Close),
            ApprovalPaneKey::Down => {
                self.move_down();
                None
            }
            ApprovalPaneKey::Up => {
                self.move_up();
                None
            }
        }
    }

    fn move_down(&mut self) {
        if let Some(index) = self.selected_index {
            let last_index = self.rows.len().saturating_sub(1);
            self.selected_index = Some(index.saturating_add(1).min(last_index));
        }
    }

    fn move_up(&mut self) {
        if let Some(index) = self.selected_index {
            self.selected_index = Some(index.saturating_sub(1));
        }
    }
}

fn first_index(rows: &[ApprovalPaneRow]) -> Option<usize> {
    if rows.is_empty() {
        None
    } else {
        Some(0)
    }
}

fn truncate_cell(value: &str, width: usize) -> String {
    let mut chars = value.chars();
    let truncated: String = chars.by_ref().take(width).collect();
    if chars.next().is_some() {
        truncated
    } else {
        value.to_owned()
    }
}

#[cfg(test)]
mod approval_tests {
    use super::*;

    #[test]
    fn approve_key_uses_default_scope() {
        let mut state = ApprovalPaneState::new(vec![ApprovalPaneRow {
            request_id: "req-1".to_owned(),
            env: "demo".to_owned(),
            kind: "egress_host".to_owned(),
            subject: "api.example.test:443".to_owned(),
            reason: "network".to_owned(),
            age: "3s".to_owned(),
            expires_in: "27s".to_owned(),
            default_scope: "session".to_owned(),
        }]);

        let action = state.handle_key(ApprovalPaneKey::ApproveDefault);

        assert_eq!(
            action,
            Some(ApprovalPaneAction::Approve {
                request_id: "req-1".to_owned(),
                scope: "session".to_owned(),
            })
        );
    }

    #[test]
    fn deny_key_returns_deny_action() {
        let mut state = ApprovalPaneState::new(vec![ApprovalPaneRow {
            request_id: "req-1".to_owned(),
            env: "demo".to_owned(),
            kind: "mcp_tool".to_owned(),
            subject: "filesystem.write".to_owned(),
            reason: "unknown tool".to_owned(),
            age: "1s".to_owned(),
            expires_in: "59s".to_owned(),
            default_scope: "once".to_owned(),
        }]);

        let action = state.handle_key(ApprovalPaneKey::Deny);

        assert_eq!(
            action,
            Some(ApprovalPaneAction::Deny {
                request_id: "req-1".to_owned(),
            })
        );
    }

    #[test]
    fn movement_clamps_to_available_rows() {
        let mut state = ApprovalPaneState::new(vec![
            ApprovalPaneRow {
                request_id: "req-1".to_owned(),
                env: "demo".to_owned(),
                kind: "egress_host".to_owned(),
                subject: "api.example.test:443".to_owned(),
                reason: "network".to_owned(),
                age: "3s".to_owned(),
                expires_in: "27s".to_owned(),
                default_scope: "session".to_owned(),
            },
            ApprovalPaneRow {
                request_id: "req-2".to_owned(),
                env: "demo".to_owned(),
                kind: "mcp_tool".to_owned(),
                subject: "filesystem.write".to_owned(),
                reason: "unknown tool".to_owned(),
                age: "1s".to_owned(),
                expires_in: "59s".to_owned(),
                default_scope: "once".to_owned(),
            },
        ]);

        assert_eq!(state.selected_index(), Some(0));
        assert_eq!(state.handle_key(ApprovalPaneKey::Down), None);
        assert_eq!(state.selected_index(), Some(1));
        assert_eq!(state.handle_key(ApprovalPaneKey::Down), None);
        assert_eq!(state.selected_index(), Some(1));
        assert_eq!(state.handle_key(ApprovalPaneKey::Up), None);
        assert_eq!(state.selected_index(), Some(0));
        assert_eq!(state.handle_key(ApprovalPaneKey::Up), None);
        assert_eq!(state.selected_index(), Some(0));
    }

    #[test]
    fn refresh_and_close_return_actions_without_a_selection() {
        let mut state = ApprovalPaneState::new(Vec::new());

        assert_eq!(state.selected_index(), None);
        assert_eq!(
            state.handle_key(ApprovalPaneKey::Refresh),
            Some(ApprovalPaneAction::Refresh)
        );
        assert_eq!(
            state.handle_key(ApprovalPaneKey::Close),
            Some(ApprovalPaneAction::Close)
        );
    }
}
