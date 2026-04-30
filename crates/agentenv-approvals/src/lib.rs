#![forbid(unsafe_code)]

pub mod config;
pub mod coordinator;
pub mod events;
pub mod local_store;
pub mod model;
pub mod policy;
pub mod signing;
pub mod slack;
pub mod store;
pub mod webhook;

pub use config::{
    ApprovalConfig, ApprovalConfigBody, ApprovalConfigError, SlackConfig, WebhookTargetConfig,
};
pub use coordinator::{ApprovalCoordinator, ApprovalCoordinatorConfig, ApprovalCoordinatorError};
pub use events::{approval_decided_event, approval_requested_event};
pub use local_store::{
    ApprovalRequestRecord, LocalApprovalStatus, LocalApprovalStore, LocalApprovalStoreError,
    LocalApprovalStoreResult,
};
pub use model::{
    format_rfc3339, ApprovalDecisionRecord, ApprovalDecisionValue, ApprovalKind, ApprovalRequest,
    ApprovalRequestFilter, ApprovalScope, ApprovalStatus,
};
pub use policy::{
    append_baseline_proposal, append_overlay_grant, read_overlay, ApprovalGrant,
    ApprovalPolicyError, ApprovalPolicyOverlay,
};
pub use signing::{sign_payload, verify_payload, PayloadSignature, SigningError};
pub use slack::{verify_slack_signature, SlackApprovalMessage, SlackSignatureError};
pub use store::{ApprovalStore, ApprovalStoreError};
pub use webhook::{
    retry_delay_for_attempt, ApprovalNotificationError, ApprovalNotifier, UrlValidator,
    WebhookPayload,
};
