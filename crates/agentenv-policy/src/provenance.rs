use agentenv_proto::{McpApprovalMode, ProvenanceTag, ToolCapability, ToolCapabilityDeclaration};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityPolicyDecision {
    Allow,
    RequestApproval,
    Deny,
}

pub fn join_tags(tags: impl IntoIterator<Item = ProvenanceTag>) -> ProvenanceTag {
    tags.into_iter().max().unwrap_or(ProvenanceTag::Untrusted)
}

pub fn evaluate_capability_policy(
    declaration: &ToolCapabilityDeclaration,
    observed_taint: ProvenanceTag,
) -> CapabilityPolicyDecision {
    if observed_taint <= declaration.max_input_taint {
        return CapabilityPolicyDecision::Allow;
    }

    match declaration.approval {
        McpApprovalMode::PerCall | McpApprovalMode::PerSession => {
            CapabilityPolicyDecision::RequestApproval
        }
        McpApprovalMode::Never => CapabilityPolicyDecision::Deny,
    }
}

pub fn default_tool_declaration(tool_name: &str) -> ToolCapabilityDeclaration {
    let lower = tool_name.to_ascii_lowercase();
    if lower.contains("commit") {
        return declaration(vec![ToolCapability::GitWrite], ProvenanceTag::Trusted);
    }
    if lower.contains("write")
        || lower.contains("create")
        || lower.contains("delete")
        || lower.contains("remove")
        || lower.contains("update")
        || lower.contains("patch")
        || lower.contains("apply")
    {
        return declaration(vec![ToolCapability::WriteFs], ProvenanceTag::Trusted);
    }
    if lower.contains("exec") || lower.contains("shell") || lower.contains("run") {
        return declaration(vec![ToolCapability::Exec], ProvenanceTag::Trusted);
    }
    if lower.contains("fetch")
        || lower.contains("http")
        || lower.contains("web")
        || lower.contains("request")
    {
        return declaration(vec![ToolCapability::Network], ProvenanceTag::Tenant);
    }
    if lower.contains("read")
        || lower.contains("list")
        || lower.contains("search")
        || lower.contains("grep")
    {
        return declaration(vec![ToolCapability::ReadFs], ProvenanceTag::Tenant);
    }

    declaration(vec![ToolCapability::McpTool], ProvenanceTag::Trusted)
}

fn declaration(
    caps: Vec<ToolCapability>,
    max_input_taint: ProvenanceTag,
) -> ToolCapabilityDeclaration {
    ToolCapabilityDeclaration {
        caps,
        max_input_taint,
        approval: McpApprovalMode::PerCall,
        argument_policies: Vec::new(),
    }
}
