#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandAction {
    DestroyEnv(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pane {
    Envs,
    Events,
    Approvals,
    Detail,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewMode {
    Normal,
    Logs,
    Policy,
    Help,
    Command,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvRow {
    pub name: String,
    pub agent: String,
    pub sandbox: String,
    pub context: String,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventRow {
    pub ts: String,
    pub env: String,
    pub kind: String,
    pub subject: String,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalRow {
    pub request_id: String,
    pub env: String,
    pub agent: Option<String>,
    pub subject: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetailState {
    pub env: String,
    pub lines: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpsSnapshot {
    pub envs: Vec<EnvRow>,
    pub events: Vec<EventRow>,
    pub approvals: Vec<ApprovalRow>,
    pub detail: Option<DetailState>,
    pub events_per_minute: u64,
}

impl OpsSnapshot {
    pub fn empty() -> Self {
        Self {
            envs: Vec::new(),
            events: Vec::new(),
            approvals: Vec::new(),
            detail: None,
            events_per_minute: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::OpsSnapshot;

    #[test]
    fn empty_snapshot_has_no_rows() {
        let snapshot = OpsSnapshot::empty();
        assert!(snapshot.envs.is_empty());
        assert!(snapshot.events.is_empty());
        assert!(snapshot.approvals.is_empty());
        assert!(snapshot.detail.is_none());
        assert_eq!(snapshot.events_per_minute, 0);
    }
}
