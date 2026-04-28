#![forbid(unsafe_code)]

mod store;

use agentenv_core::security::ssrf::{sanitize_untrusted_url_text, SsrfBlockReason, SsrfBlocked};
use agentenv_proto::{ActivityEventParams, ActivityKind};

pub use store::{
    default_store_path, EventImportReport, EventStoreError, EventStoreResult, LocalEventStore,
    StoredEvent, StoredEventKind,
};

pub fn ssrf_blocked_event(
    blocked: &SsrfBlocked,
    ts: impl Into<String>,
    handle: Option<String>,
) -> ActivityEventParams {
    ActivityEventParams {
        kind: ActivityKind::EgressDenied,
        subject: match blocked.host.as_deref() {
            Some(host) => host.to_owned(),
            None => sanitize_untrusted_url_text(&blocked.url),
        },
        reason: Some(ssrf_block_reason_label(&blocked.reason).to_owned()),
        ts: ts.into(),
        handle,
    }
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
    use std::{fs, io::Write};

    use super::ssrf_blocked_event;
    use super::{default_store_path, LocalEventStore, StoredEvent, StoredEventKind};

    #[test]
    fn local_store_initializes_ops_database() {
        let root = tempfile::tempdir().expect("tempdir");

        let store = LocalEventStore::open(root.path()).expect("open event store");

        assert_eq!(store.path(), default_store_path(root.path()));
        assert!(store
            .list_recent(None, 10)
            .expect("list recent events")
            .is_empty());
    }

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

    #[test]
    fn local_store_appends_and_filters_recent_events() {
        let root = tempfile::tempdir().expect("tempdir");
        let store = LocalEventStore::open(root.path()).expect("open event store");

        store
            .append(&StoredEvent::new(
                "alpha",
                "2026-04-27T12:00:00Z",
                StoredEventKind::Log,
                "alpha ready",
            ))
            .expect("append alpha");
        store
            .append(&StoredEvent::new(
                "beta",
                "2026-04-27T12:00:01Z",
                StoredEventKind::EgressDenied,
                "169.254.169.254",
            ))
            .expect("append beta");

        let alpha = store
            .list_recent(Some("alpha"), 10)
            .expect("list alpha events");
        assert_eq!(alpha.len(), 1);
        assert_eq!(alpha[0].subject, "alpha ready");

        let all = store.list_recent(None, 10).expect("list all events");
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].env, "beta");
    }

    #[test]
    fn jsonl_import_skips_bad_lines_and_tracks_offset() {
        let root = tempfile::tempdir().expect("tempdir");
        let store = LocalEventStore::open(root.path()).expect("open event store");
        let env_dir = root.path().join("envs").join("demo");
        fs::create_dir_all(&env_dir).expect("create env dir");
        let events_path = env_dir.join("events.jsonl");
        fs::write(
            &events_path,
            concat!(
                "{\"ts\":\"2026-04-27T12:00:00Z\",\"driver\":\"context\",\"level\":\"info\",\"msg\":\"context ready\"}\n",
                "not json\n",
                "{\"ts\":\"2026-04-27T12:00:01Z\",\"kind\":\"egress_denied\",\"subject\":\"metadata\"}\n",
            ),
        )
        .expect("write jsonl");

        let first = store
            .import_env_jsonl("demo", &events_path)
            .expect("first import");
        assert_eq!(first.imported, 2);
        assert_eq!(first.skipped, 1);

        let second = store
            .import_env_jsonl("demo", &events_path)
            .expect("second import");
        assert_eq!(second.imported, 0);
        assert_eq!(second.skipped, 0);

        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(&events_path)
            .expect("open append");
        file.write_all(
            b"{\"ts\":\"2026-04-27T12:00:02Z\",\"driver\":\"agent\",\"msg\":\"agent ready\"}\n",
        )
        .expect("append jsonl");

        let third = store
            .import_env_jsonl("demo", &events_path)
            .expect("third import");
        assert_eq!(third.imported, 1);
        assert_eq!(third.skipped, 0);
        assert_eq!(
            store
                .list_recent(Some("demo"), 10)
                .expect("list imported")
                .len(),
            3
        );
    }
}
