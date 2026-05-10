use agentenv_core::lifecycle::{create_from_blueprint_yaml, freeze_from_blueprint_yaml};
use agentenv_core::security::dns_policy::{validate_dns_policy, DnsPolicyError};
use agentenv_proto::DnsPolicy;

#[test]
fn public_resolver_ip_is_accepted() {
    let policy = DnsPolicy {
        resolvers_allowed: vec!["1.1.1.1".to_owned()],
        ..DnsPolicy::default()
    };

    validate_dns_policy(&policy).expect("public resolver should validate");
}

#[test]
fn private_resolver_ip_is_accepted_for_explicit_resolver_allowlist() {
    let policy = DnsPolicy {
        resolvers_allowed: vec!["10.0.0.10".to_owned()],
        ..DnsPolicy::default()
    };

    validate_dns_policy(&policy).expect("private resolver should validate");
}

#[test]
fn resolver_error_sanitizes_scheme_less_credentials() {
    let policy = DnsPolicy {
        resolvers_allowed: vec!["alice:secret@1.1.1.1".to_owned()],
        ..DnsPolicy::default()
    };

    let err = validate_dns_policy(&policy).expect_err("credential-bearing resolver should reject");
    let message = err.to_string();

    assert!(
        matches!(err, DnsPolicyError::ResolverBlocked { ref path, .. } if path == "policy.dns.resolvers_allowed[0]")
    );
    assert!(!message.contains("alice"), "{message}");
    assert!(!message.contains("secret"), "{message}");
}

#[test]
fn malformed_resolver_error_sanitizes_scheme_less_credentials() {
    let policy = DnsPolicy {
        resolvers_allowed: vec!["alice:secret@[]".to_owned()],
        ..DnsPolicy::default()
    };

    let err = validate_dns_policy(&policy).expect_err("malformed resolver should reject");
    let message = err.to_string();

    assert!(
        matches!(err, DnsPolicyError::ResolverBlocked { ref path, .. } if path == "policy.dns.resolvers_allowed[0]")
    );
    assert!(!message.contains("alice"), "{message}");
    assert!(!message.contains("secret"), "{message}");
}

#[test]
fn resolver_with_query_is_rejected_and_sanitized() {
    let policy = DnsPolicy {
        resolvers_allowed: vec!["1.1.1.1?token=query-secret".to_owned()],
        ..DnsPolicy::default()
    };

    let err = validate_dns_policy(&policy).expect_err("query-bearing resolver should reject");
    let message = err.to_string();

    assert!(
        matches!(err, DnsPolicyError::ResolverBlocked { ref path, .. } if path == "policy.dns.resolvers_allowed[0]")
    );
    assert!(!message.contains("query-secret"), "{message}");
}

#[test]
fn wildcard_resolver_is_rejected() {
    let policy = DnsPolicy {
        resolvers_allowed: vec!["*".to_owned()],
        ..DnsPolicy::default()
    };

    let err = validate_dns_policy(&policy).expect_err("wildcard resolver should reject");

    assert!(
        matches!(err, DnsPolicyError::ResolverBlocked { ref path, .. } if path == "policy.dns.resolvers_allowed[0]")
    );
}

#[test]
fn doh_endpoint_with_query_is_rejected() {
    let policy = DnsPolicy {
        doh_upstreams_allowed: vec!["https://dns.google/dns-query?name=secret.example".to_owned()],
        ..DnsPolicy::default()
    };

    let err = validate_dns_policy(&policy).expect_err("query-bearing DoH endpoint should reject");
    assert!(
        matches!(err, DnsPolicyError::InvalidDohEndpoint { ref path, .. } if path == "policy.dns.doh_upstreams_allowed[0]")
    );
}

#[test]
fn doh_endpoint_error_sanitizes_credentials_query_and_fragment() {
    let policy = DnsPolicy {
        doh_upstreams_allowed: vec![
            "https://alice:p@ssword@dns.google/dns-query?token=query-secret#fragment-secret"
                .to_owned(),
        ],
        ..DnsPolicy::default()
    };

    let err = validate_dns_policy(&policy).expect_err("secret-bearing DoH endpoint should reject");
    let message = err.to_string();

    assert!(
        matches!(err, DnsPolicyError::InvalidDohEndpoint { ref path, .. } if path == "policy.dns.doh_upstreams_allowed[0]")
    );
    assert!(!message.contains("alice"), "{message}");
    assert!(!message.contains("p@ssword"), "{message}");
    assert!(!message.contains("query-secret"), "{message}");
    assert!(!message.contains("fragment-secret"), "{message}");
}

#[test]
fn valid_doh_endpoint_is_accepted() {
    let policy = DnsPolicy {
        doh_upstreams_allowed: vec!["https://dns.google/dns-query".to_owned()],
        ..DnsPolicy::default()
    };

    validate_dns_policy(&policy).expect("valid DoH endpoint should validate");
}

#[test]
fn dot_endpoint_with_invalid_port_is_rejected() {
    let policy = DnsPolicy {
        dot_upstreams_allowed: vec!["1.1.1.1:99999".to_owned()],
        ..DnsPolicy::default()
    };

    let err = validate_dns_policy(&policy).expect_err("invalid DoT port should reject");
    assert!(
        matches!(err, DnsPolicyError::InvalidDotEndpoint { ref path, .. } if path == "policy.dns.dot_upstreams_allowed[0]")
    );
}

#[test]
fn dot_endpoint_error_sanitizes_scheme_less_credentials() {
    let policy = DnsPolicy {
        dot_upstreams_allowed: vec!["alice:secret@dns.example:99999".to_owned()],
        ..DnsPolicy::default()
    };

    let err =
        validate_dns_policy(&policy).expect_err("credential-bearing DoT endpoint should reject");
    let message = err.to_string();

    assert!(
        matches!(err, DnsPolicyError::InvalidDotEndpoint { ref path, .. } if path == "policy.dns.dot_upstreams_allowed[0]")
    );
    assert!(!message.contains("alice"), "{message}");
    assert!(!message.contains("secret"), "{message}");
}

#[test]
fn valid_dot_endpoint_is_accepted() {
    let policy = DnsPolicy {
        dot_upstreams_allowed: vec!["[2606:4700:4700::1111]:853".to_owned()],
        ..DnsPolicy::default()
    };

    validate_dns_policy(&policy).expect("valid DoT endpoint should validate");
}

#[test]
fn active_dns_policy_without_upstream_is_rejected() {
    let policy = DnsPolicy {
        log_all_queries: true,
        pin_resolved_ips: true,
        ..DnsPolicy::default()
    };

    let err = validate_dns_policy(&policy).expect_err("active DNS policy needs an upstream");

    assert!(matches!(err, DnsPolicyError::MissingUpstream));
}

#[test]
fn lifecycle_accepts_declared_private_dns_resolver() {
    let yaml = r#"
version: 0.1.0
min_agentenv_version: 0.0.1-alpha0
sandbox:
  driver: openshell
agent:
  driver: codex
context:
  driver: context-none
policy:
  tier: balanced
  presets: []
  dns:
    resolvers_allowed:
      - 10.0.0.10
"#;

    freeze_from_blueprint_yaml(yaml).expect("freeze should accept private resolver");
    create_from_blueprint_yaml("dns-policy", yaml).expect("create should accept private resolver");
}
