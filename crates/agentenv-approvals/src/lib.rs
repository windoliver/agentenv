#![forbid(unsafe_code)]

pub mod coordinator;
pub mod events;
pub mod model;
pub mod policy;
pub mod store;

pub use coordinator::{ApprovalCoordinator, ApprovalCoordinatorConfig, ApprovalCoordinatorError};
pub use events::{approval_decided_event, approval_requested_event};
pub use model::{
    format_rfc3339, ApprovalDecisionRecord, ApprovalDecisionValue, ApprovalKind, ApprovalRequest,
    ApprovalRequestFilter, ApprovalScope, ApprovalStatus,
};
pub use policy::{
    append_baseline_proposal, append_overlay_grant, read_overlay, ApprovalGrant,
    ApprovalPolicyError, ApprovalPolicyOverlay,
};
pub use store::{ApprovalStore, ApprovalStoreError};
