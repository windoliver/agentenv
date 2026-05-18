use agentenv_policy::provenance::{
    default_tool_declaration, evaluate_capability_policy, join_tags, CapabilityPolicyDecision,
};
use agentenv_proto::{McpApprovalMode, ProvenanceTag, ToolCapability, ToolCapabilityDeclaration};

#[test]
fn joins_use_highest_taint() {
    assert_eq!(
        join_tags([ProvenanceTag::Trusted, ProvenanceTag::Tenant]),
        ProvenanceTag::Tenant
    );
    assert_eq!(
        join_tags([ProvenanceTag::Tenant, ProvenanceTag::Untrusted]),
        ProvenanceTag::Untrusted
    );
}

#[test]
fn git_commit_defaults_to_trusted_only() {
    let declaration = default_tool_declaration("git.commit");

    assert_eq!(declaration.caps, vec![ToolCapability::GitWrite]);
    assert_eq!(declaration.max_input_taint, ProvenanceTag::Trusted);
}

#[test]
fn tenant_can_reach_read_only_filesystem_tool() {
    let declaration = default_tool_declaration("filesystem.read");

    let decision = evaluate_capability_policy(&declaration, ProvenanceTag::Tenant);

    assert_eq!(decision, CapabilityPolicyDecision::Allow);
}

#[test]
fn untrusted_git_write_requires_approval_when_configured() {
    let declaration = ToolCapabilityDeclaration {
        caps: vec![ToolCapability::GitWrite],
        max_input_taint: ProvenanceTag::Trusted,
        approval: McpApprovalMode::PerCall,
        argument_policies: Vec::new(),
    };

    let decision = evaluate_capability_policy(&declaration, ProvenanceTag::Untrusted);

    assert_eq!(decision, CapabilityPolicyDecision::RequestApproval);
}

#[test]
fn untrusted_git_write_denies_when_approval_disabled() {
    let declaration = ToolCapabilityDeclaration {
        caps: vec![ToolCapability::GitWrite],
        max_input_taint: ProvenanceTag::Trusted,
        approval: McpApprovalMode::Never,
        argument_policies: Vec::new(),
    };

    let decision = evaluate_capability_policy(&declaration, ProvenanceTag::Untrusted);

    assert_eq!(decision, CapabilityPolicyDecision::Deny);
}
