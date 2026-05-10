use std::net::IpAddr;

use thiserror::Error;
use url::Url;

use crate::security::ssrf::{
    sanitize_untrusted_url_text, validate_outbound, SsrfBlockReason, SsrfBlocked, SsrfOptions,
};

#[derive(Debug, Error)]
pub enum DnsPolicyError {
    #[error("active DNS policy requires at least one DNS upstream")]
    MissingUpstream,
    #[error("DNS resolver `{value}` at `{path}` failed SSRF validation: {source}")]
    ResolverBlocked {
        path: String,
        value: String,
        #[source]
        source: Box<SsrfBlocked>,
    },
    #[error(
        "DoH endpoint `{value}` at `{path}` must be an https URL without credentials, query, or fragment"
    )]
    InvalidDohEndpoint { path: String, value: String },
    #[error("DoH endpoint `{value}` at `{path}` failed SSRF validation: {source}")]
    DohBlocked {
        path: String,
        value: String,
        #[source]
        source: Box<SsrfBlocked>,
    },
    #[error("DoT endpoint `{value}` at `{path}` must be host:port with port 1-65535")]
    InvalidDotEndpoint { path: String, value: String },
    #[error("DoT endpoint `{value}` at `{path}` failed SSRF validation: {source}")]
    DotBlocked {
        path: String,
        value: String,
        #[source]
        source: Box<SsrfBlocked>,
    },
}

pub fn validate_dns_policy(policy: &agentenv_proto::DnsPolicy) -> Result<(), DnsPolicyError> {
    if policy.is_active()
        && policy.resolvers_allowed.is_empty()
        && policy.doh_upstreams_allowed.is_empty()
        && policy.dot_upstreams_allowed.is_empty()
    {
        return Err(DnsPolicyError::MissingUpstream);
    }

    for (index, resolver) in policy.resolvers_allowed.iter().enumerate() {
        validate_resolver(resolver, &format!("policy.dns.resolvers_allowed[{index}]"))?;
    }

    for (index, endpoint) in policy.doh_upstreams_allowed.iter().enumerate() {
        validate_doh_endpoint(
            endpoint,
            &format!("policy.dns.doh_upstreams_allowed[{index}]"),
        )?;
    }

    for (index, endpoint) in policy.dot_upstreams_allowed.iter().enumerate() {
        validate_dot_endpoint(
            endpoint,
            &format!("policy.dns.dot_upstreams_allowed[{index}]"),
        )?;
    }

    Ok(())
}

fn validate_resolver(value: &str, path: &str) -> Result<(), DnsPolicyError> {
    validate_resolver_host(value).map_err(|source| DnsPolicyError::ResolverBlocked {
        path: path.to_owned(),
        value: sanitized_policy_value(value),
        source: Box::new(source),
    })?;

    let url = url_for_host(value, None).map_err(|source| DnsPolicyError::ResolverBlocked {
        path: path.to_owned(),
        value: sanitized_policy_value(value),
        source: Box::new(source),
    })?;

    validate_outbound(&url, dns_resolver_ssrf_options()).map_err(|source| {
        DnsPolicyError::ResolverBlocked {
            path: path.to_owned(),
            value: sanitized_policy_value(value),
            source: Box::new(source),
        }
    })?;

    Ok(())
}

fn dns_resolver_ssrf_options() -> SsrfOptions {
    SsrfOptions {
        allow_private: true,
        ..SsrfOptions::default()
    }
}

fn validate_resolver_host(value: &str) -> Result<(), SsrfBlocked> {
    if value.is_empty()
        || value == "*"
        || has_url_authority_prefix(value)
        || value.contains(['@', '/', '?', '#'])
    {
        return Err(invalid_resolver_block(value));
    }

    if value.parse::<IpAddr>().is_ok() {
        return Ok(());
    }

    if value.contains(':') || !is_valid_hostname(value) {
        return Err(invalid_resolver_block(value));
    }

    Ok(())
}

fn is_valid_hostname(value: &str) -> bool {
    let hostname = value.strip_suffix('.').unwrap_or(value);

    !hostname.is_empty()
        && hostname.len() <= 253
        && hostname.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

fn invalid_resolver_block(value: &str) -> SsrfBlocked {
    SsrfBlocked {
        url: sanitized_policy_value(value),
        host: None,
        resolved_ip: None,
        reason: SsrfBlockReason::MissingHost,
    }
}

fn validate_doh_endpoint(value: &str, path: &str) -> Result<(), DnsPolicyError> {
    let url = Url::parse(value).map_err(|_| DnsPolicyError::InvalidDohEndpoint {
        path: path.to_owned(),
        value: sanitized_policy_value(value),
    })?;

    if url.scheme() != "https"
        || url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(DnsPolicyError::InvalidDohEndpoint {
            path: path.to_owned(),
            value: sanitized_policy_value(value),
        });
    }

    validate_outbound(&url, SsrfOptions::default()).map_err(|source| {
        DnsPolicyError::DohBlocked {
            path: path.to_owned(),
            value: sanitized_policy_value(value),
            source: Box::new(source),
        }
    })?;

    Ok(())
}

fn validate_dot_endpoint(value: &str, path: &str) -> Result<(), DnsPolicyError> {
    let parsed =
        Url::parse(&format!("dot://{value}")).map_err(|_| DnsPolicyError::InvalidDotEndpoint {
            path: path.to_owned(),
            value: sanitized_policy_value(value),
        })?;

    let Some(host) = parsed.host_str() else {
        return Err(DnsPolicyError::InvalidDotEndpoint {
            path: path.to_owned(),
            value: sanitized_policy_value(value),
        });
    };
    let Some(port) = parsed.port() else {
        return Err(DnsPolicyError::InvalidDotEndpoint {
            path: path.to_owned(),
            value: sanitized_policy_value(value),
        });
    };

    if port == 0
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || !parsed.path().is_empty()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(DnsPolicyError::InvalidDotEndpoint {
            path: path.to_owned(),
            value: sanitized_policy_value(value),
        });
    }

    let url = url_for_host(host, Some(port)).map_err(|_| DnsPolicyError::InvalidDotEndpoint {
        path: path.to_owned(),
        value: sanitized_policy_value(value),
    })?;
    validate_outbound(&url, SsrfOptions::default()).map_err(|source| {
        DnsPolicyError::DotBlocked {
            path: path.to_owned(),
            value: sanitized_policy_value(value),
            source: Box::new(source),
        }
    })?;

    Ok(())
}

fn sanitized_policy_value(value: &str) -> String {
    let sanitized = sanitize_untrusted_url_text(value);

    if has_url_authority_prefix(value) || has_url_authority_prefix(&sanitized) {
        return sanitized;
    }

    sanitize_untrusted_url_text(&format!("//{sanitized}"))
        .strip_prefix("//")
        .unwrap_or(&sanitized)
        .to_owned()
}

fn url_for_host(host: &str, port: Option<u16>) -> Result<Url, SsrfBlocked> {
    let authority = match host.parse::<IpAddr>() {
        Ok(IpAddr::V6(_)) => format!("[{host}]"),
        _ => host.to_owned(),
    };
    let port_suffix = port.map(|port| format!(":{port}")).unwrap_or_default();
    let raw = format!("http://{authority}{port_suffix}/");

    Url::parse(&raw).map_err(|_| SsrfBlocked {
        url: sanitized_policy_value(host),
        host: None,
        resolved_ip: None,
        reason: SsrfBlockReason::MissingHost,
    })
}

fn has_url_authority_prefix(value: &str) -> bool {
    value.contains("://") || value.starts_with("//")
}
