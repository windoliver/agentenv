use agentenv_proto::{
    FilesystemPolicy, InferencePolicy, NetworkAccessPolicy, NetworkPolicy, NetworkRule,
    NetworkTarget, PolicyReloadability, ProcessPolicy,
};

use crate::{PolicyResult, PresetRegistry, PresetSelection};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    Restricted,
    Balanced,
    Open,
}

pub fn compose_policy(
    tier: Tier,
    presets: &[PresetSelection],
    overrides: Option<NetworkPolicy>,
    registry: &PresetRegistry,
) -> PolicyResult<NetworkPolicy> {
    let mut policy = baseline_policy(tier);
    let effective_presets = resolve_effective_presets(tier, presets)?;

    for preset in &effective_presets {
        registry.merge_into(&mut policy, preset)?;
    }

    if let Some(override_policy) = overrides {
        merge_policy(&mut policy, override_policy);
    }

    normalize(&mut policy);
    Ok(policy)
}

fn resolve_effective_presets(
    tier: Tier,
    presets: &[PresetSelection],
) -> PolicyResult<Vec<PresetSelection>> {
    let mut effective = tier_default_presets(tier)?;

    for preset in presets {
        if let Some(existing) = effective.iter_mut().find(|entry| entry.name == preset.name) {
            *existing = preset.clone();
        } else {
            effective.push(preset.clone());
        }
    }

    Ok(effective)
}

fn tier_default_presets(tier: Tier) -> PolicyResult<Vec<PresetSelection>> {
    let default_slugs = match tier {
        Tier::Restricted => &[][..],
        Tier::Balanced | Tier::Open => &[
            "github_read",
            "npm_read",
            "pypi_read",
            "crates_read",
            "docker_hub_read",
        ][..],
    };

    default_slugs
        .iter()
        .map(|slug| PresetSelection::from_slug(slug))
        .collect()
}

fn baseline_policy(tier: Tier) -> NetworkPolicy {
    match tier {
        Tier::Restricted => NetworkPolicy {
            network: NetworkAccessPolicy {
                reloadability: PolicyReloadability::HotReload,
                allow: Vec::new(),
                deny: Vec::new(),
                approval_required: Vec::new(),
            },
            filesystem: FilesystemPolicy {
                reloadability: PolicyReloadability::LockedAtCreate,
                read_only: vec!["/usr".to_owned(), "/lib".to_owned(), "/etc".to_owned()],
                read_write: vec!["/sandbox".to_owned(), "/tmp".to_owned()],
            },
            process: ProcessPolicy {
                reloadability: PolicyReloadability::LockedAtCreate,
                run_as_user: "sandbox".to_owned(),
                run_as_group: "sandbox".to_owned(),
                profile: "restricted".to_owned(),
                allow_syscalls: Vec::new(),
                deny_syscalls: Vec::new(),
            },
            inference: InferencePolicy {
                reloadability: PolicyReloadability::HotReload,
                routes: Vec::new(),
            },
        },
        Tier::Balanced => {
            let mut policy = baseline_policy(Tier::Restricted);
            policy.filesystem.read_only.push("/var/log".to_owned());
            policy.process.profile = "balanced".to_owned();
            policy
        }
        Tier::Open => {
            let mut policy = baseline_policy(Tier::Balanced);
            policy.process.profile = "open".to_owned();
            policy.network.allow.push(NetworkRule {
                target: NetworkTarget::Host {
                    host: "*".to_owned(),
                    port: Some(443),
                    scheme: Some("https".to_owned()),
                },
            });
            policy
        }
    }
}

fn merge_policy(base: &mut NetworkPolicy, overrides: NetworkPolicy) {
    merge_network_rules(
        &mut base.network.allow,
        &mut base.network.approval_required,
        &mut base.network.deny,
        overrides.network.allow,
    );
    merge_network_rules(
        &mut base.network.approval_required,
        &mut base.network.allow,
        &mut base.network.deny,
        overrides.network.approval_required,
    );
    merge_network_rules(
        &mut base.network.deny,
        &mut base.network.allow,
        &mut base.network.approval_required,
        overrides.network.deny,
    );

    merge_paths(
        &mut base.filesystem.read_write,
        &mut base.filesystem.read_only,
        overrides.filesystem.read_write,
    );
    merge_paths(
        &mut base.filesystem.read_only,
        &mut base.filesystem.read_write,
        overrides.filesystem.read_only,
    );

    if !overrides.process.run_as_user.is_empty() {
        base.process.run_as_user = overrides.process.run_as_user;
    }
    if !overrides.process.run_as_group.is_empty() {
        base.process.run_as_group = overrides.process.run_as_group;
    }
    if !overrides.process.profile.is_empty() {
        base.process.profile = overrides.process.profile;
    }

    base.process
        .allow_syscalls
        .extend(overrides.process.allow_syscalls);
    base.process
        .deny_syscalls
        .extend(overrides.process.deny_syscalls);
    base.inference.routes.extend(overrides.inference.routes);
}

fn merge_network_rules(
    target: &mut Vec<NetworkRule>,
    other_a: &mut Vec<NetworkRule>,
    other_b: &mut Vec<NetworkRule>,
    incoming: Vec<NetworkRule>,
) {
    for rule in incoming {
        remove_conflicting_rule(target, &rule);
        remove_conflicting_rule(other_a, &rule);
        remove_conflicting_rule(other_b, &rule);
        target.push(rule);
    }
}

fn merge_paths(target: &mut Vec<String>, other: &mut Vec<String>, incoming: Vec<String>) {
    for path in incoming {
        target.retain(|existing| existing != &path);
        other.retain(|existing| existing != &path);
        target.push(path);
    }
}

fn remove_conflicting_rule(rules: &mut Vec<NetworkRule>, incoming: &NetworkRule) {
    let incoming_key = rule_sort_key(incoming);
    rules.retain(|rule| rule_sort_key(rule) != incoming_key);
}

fn normalize(policy: &mut NetworkPolicy) {
    sort_and_dedup_strings(&mut policy.filesystem.read_only);
    sort_and_dedup_strings(&mut policy.filesystem.read_write);
    sort_and_dedup_strings(&mut policy.process.allow_syscalls);
    sort_and_dedup_strings(&mut policy.process.deny_syscalls);

    sort_and_dedup_rules(&mut policy.network.allow);
    sort_and_dedup_rules(&mut policy.network.deny);
    sort_and_dedup_rules(&mut policy.network.approval_required);

    policy
        .inference
        .routes
        .sort_by_key(inference_route_sort_key);
    policy.inference.routes.dedup();
}

fn sort_and_dedup_strings(values: &mut Vec<String>) {
    values.sort();
    values.dedup();
}

fn sort_and_dedup_rules(rules: &mut Vec<NetworkRule>) {
    rules.sort_by_key(rule_sort_key);
    rules.dedup();
}

fn rule_sort_key(rule: &NetworkRule) -> String {
    match &rule.target {
        NetworkTarget::Host { host, port, scheme } => format!(
            "host|{}|{}|{}",
            scheme.as_deref().unwrap_or_default(),
            host,
            port.map(|value| value.to_string())
                .as_deref()
                .unwrap_or_default()
        ),
        NetworkTarget::Cidr { cidr } => format!("cidr|{cidr}"),
        NetworkTarget::Port { port, protocol } => {
            format!("port|{}|{port}", protocol.as_deref().unwrap_or_default())
        }
        NetworkTarget::UrlPattern { pattern } => format!("url_pattern|{pattern}"),
        NetworkTarget::HttpMethodPath { host, method, path } => format!(
            "http_method_path|{}|{}|{}",
            host.as_deref().unwrap_or_default(),
            method,
            path
        ),
    }
}

fn inference_route_sort_key(route: &agentenv_proto::InferenceRoute) -> String {
    format!(
        "{}|{}|{}|{}|{}",
        route.matcher,
        route.provider,
        route.model,
        route.base_url.as_deref().unwrap_or_default(),
        route
            .timeout_seconds
            .map(|value| value.to_string())
            .as_deref()
            .unwrap_or_default()
    )
}
