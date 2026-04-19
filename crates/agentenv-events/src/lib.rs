#![forbid(unsafe_code)]

use agentenv_core::security::ssrf::{SsrfBlockReason, SsrfBlocked};
use agentenv_proto::{ActivityEventParams, ActivityKind};

pub fn ssrf_blocked_event(
    blocked: &SsrfBlocked,
    ts: impl Into<String>,
    handle: Option<String>,
) -> ActivityEventParams {
    ActivityEventParams {
        kind: ActivityKind::EgressDenied,
        subject: match blocked.host.as_deref() {
            Some(host) => host.to_owned(),
            None => sanitize_fallback_subject(&blocked.url),
        },
        reason: Some(ssrf_block_reason_label(&blocked.reason).to_owned()),
        ts: ts.into(),
        handle,
    }
}

fn sanitize_fallback_subject(subject: &str) -> String {
    let mut sanitized = match subject.find(['?', '#']) {
        Some(index) => subject[..index].to_owned(),
        None => subject.to_owned(),
    };

    let authority_start = if let Some(scheme_end) = sanitized.find("://") {
        Some(scheme_end + "://".len())
    } else if sanitized.starts_with("//") {
        Some("//".len())
    } else {
        None
    };

    if let Some(authority_start) = authority_start {
        let authority_end = match sanitized[authority_start..].find('/') {
            Some(index) => authority_start + index,
            None => sanitized.len(),
        };

        if let Some(at_offset) = sanitized[authority_start..authority_end].rfind('@') {
            let credential_end = authority_start + at_offset + 1;
            sanitized.replace_range(authority_start..credential_end, "");
        }
    }

    sanitized
}

fn ssrf_block_reason_label(reason: &SsrfBlockReason) -> &'static str {
    match reason {
        SsrfBlockReason::UnsupportedScheme { .. } => "unsupported_scheme",
        SsrfBlockReason::MissingHost => "missing_host",
        SsrfBlockReason::CredentialsInUrl => "credentials_in_url",
        SsrfBlockReason::DnsResolutionFailed { .. } => "dns_resolution_failed",
        SsrfBlockReason::DeniedIp { .. } => "denied_ip",
        SsrfBlockReason::DeniedCloudMetadata => "denied_cloud_metadata",
        SsrfBlockReason::DeniedExtraCidr { .. } => "denied_extra_cidr",
        SsrfBlockReason::RedirectLimitExceeded { .. } => "redirect_limit_exceeded",
        SsrfBlockReason::MalformedRedirect { .. } => "malformed_redirect",
        SsrfBlockReason::UnsupportedDnsResolver { .. } => "unsupported_dns_resolver",
    }
}

#[cfg(test)]
mod tests {
    use agentenv_core::security::ssrf::{SsrfBlockReason, SsrfBlocked};
    use agentenv_proto::ActivityKind;

    use super::ssrf_blocked_event;

    #[test]
    fn denied_cloud_metadata_block_becomes_egress_denied_event() {
        let blocked = SsrfBlocked {
            url: "http://169.254.169.254/latest/meta-data".to_owned(),
            host: Some("169.254.169.254".to_owned()),
            resolved_ip: None,
            reason: SsrfBlockReason::DeniedCloudMetadata,
        };

        let event = ssrf_blocked_event(
            &blocked,
            "2026-04-19T12:34:56Z",
            Some("sandbox-123".to_owned()),
        );

        assert_eq!(event.kind, ActivityKind::EgressDenied);
        assert_eq!(event.subject, "169.254.169.254");
        assert_eq!(event.reason, Some("denied_cloud_metadata".to_owned()));
        assert_eq!(event.ts, "2026-04-19T12:34:56Z");
        assert_eq!(event.handle, Some("sandbox-123".to_owned()));
    }

    #[test]
    fn missing_host_block_falls_back_to_sanitized_url_subject() {
        let blocked = SsrfBlocked {
            url: "http:///path".to_owned(),
            host: None,
            resolved_ip: None,
            reason: SsrfBlockReason::MissingHost,
        };

        let event = ssrf_blocked_event(&blocked, "2026-04-19T12:34:57Z", None);

        assert_eq!(event.kind, ActivityKind::EgressDenied);
        assert_eq!(event.subject, "http:///path");
        assert_eq!(event.reason, Some("missing_host".to_owned()));
        assert_eq!(event.ts, "2026-04-19T12:34:57Z");
        assert_eq!(event.handle, None);
    }

    #[test]
    fn credentials_in_url_reason_uses_stable_label() {
        let blocked = SsrfBlocked {
            url: "https://example.test/private".to_owned(),
            host: None,
            resolved_ip: None,
            reason: SsrfBlockReason::CredentialsInUrl,
        };

        let event = ssrf_blocked_event(&blocked, "2026-04-19T12:34:58Z", None);

        assert_eq!(event.subject, "https://example.test/private");
        assert_eq!(event.reason, Some("credentials_in_url".to_owned()));
    }

    #[test]
    fn fallback_subject_redacts_credentials_query_and_fragment() {
        let blocked = SsrfBlocked {
            url: "https://user:pass@example.test/private?token=secret#frag".to_owned(),
            host: None,
            resolved_ip: None,
            reason: SsrfBlockReason::CredentialsInUrl,
        };

        let event = ssrf_blocked_event(&blocked, "2026-04-19T12:34:59Z", None);

        assert_eq!(event.subject, "https://example.test/private");
        for redacted in ["user", "pass", "token", "secret", "?", "#"] {
            assert!(
                !event.subject.contains(redacted),
                "fallback subject leaked `{redacted}` in `{}`",
                event.subject
            );
        }
    }

    #[test]
    fn fallback_subject_redacts_scheme_relative_credentials() {
        let blocked = SsrfBlocked {
            url: "//user:pass@example.test/private?token=secret#frag".to_owned(),
            host: None,
            resolved_ip: None,
            reason: SsrfBlockReason::CredentialsInUrl,
        };

        let event = ssrf_blocked_event(&blocked, "2026-04-19T12:35:00Z", None);

        assert_eq!(event.subject, "//example.test/private");
        for redacted in ["user", "pass", "token", "secret", "?", "#"] {
            assert!(
                !event.subject.contains(redacted),
                "fallback subject leaked `{redacted}` in `{}`",
                event.subject
            );
        }
    }
}
