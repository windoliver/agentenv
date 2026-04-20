use crate::registry::DriverKind;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuiltInDriverSpec {
    pub kind: DriverKind,
    pub names: &'static [&'static str],
}

const BUILT_IN_DRIVER_SPECS: &[BuiltInDriverSpec] = &[
    BuiltInDriverSpec {
        kind: DriverKind::Sandbox,
        names: &["openshell", "sandbox-openshell"],
    },
    BuiltInDriverSpec {
        kind: DriverKind::Agent,
        names: &["claude", "agent-claude"],
    },
    BuiltInDriverSpec {
        kind: DriverKind::Agent,
        names: &["codex", "agent-codex"],
    },
    BuiltInDriverSpec {
        kind: DriverKind::Agent,
        names: &["hermes"],
    },
    BuiltInDriverSpec {
        kind: DriverKind::Agent,
        names: &["openclaw", "agent-openclaw"],
    },
    BuiltInDriverSpec {
        kind: DriverKind::Context,
        names: &["filesystem", "context-filesystem"],
    },
    BuiltInDriverSpec {
        kind: DriverKind::Context,
        names: &["mcp-generic", "context-mcp-generic"],
    },
    BuiltInDriverSpec {
        kind: DriverKind::Context,
        names: &["nexus"],
    },
    BuiltInDriverSpec {
        kind: DriverKind::Context,
        names: &["none", "context-none"],
    },
    BuiltInDriverSpec {
        kind: DriverKind::Inference,
        names: &["passthrough", "inference-passthrough"],
    },
    BuiltInDriverSpec {
        kind: DriverKind::Inference,
        names: &["openai", "inference-openai"],
    },
    BuiltInDriverSpec {
        kind: DriverKind::Inference,
        names: &["anthropic", "inference-anthropic"],
    },
    BuiltInDriverSpec {
        kind: DriverKind::Inference,
        names: &["ollama", "inference-ollama"],
    },
];

pub fn built_in_driver_specs() -> &'static [BuiltInDriverSpec] {
    BUILT_IN_DRIVER_SPECS
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::DriverKind;

    #[test]
    fn built_in_specs_include_current_aliases() {
        let specs = built_in_driver_specs();

        assert!(specs.iter().any(|spec| {
            spec.kind == DriverKind::Sandbox && spec.names == &["openshell", "sandbox-openshell"]
        }));
        assert!(specs.iter().any(|spec| {
            spec.kind == DriverKind::Agent && spec.names == &["codex", "agent-codex"]
        }));
        assert!(specs.iter().any(|spec| {
            spec.kind == DriverKind::Context && spec.names == &["filesystem", "context-filesystem"]
        }));
        assert!(specs.iter().any(|spec| {
            spec.kind == DriverKind::Inference
                && spec.names == &["passthrough", "inference-passthrough"]
        }));
    }
}
