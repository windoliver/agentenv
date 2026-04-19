use std::net::IpAddr;

use agentenv_core::security::ssrf::{
    validate_outbound_with_resolver, SsrfBlockReason, SsrfOptions, StaticDnsResolver,
};
use url::Url;

#[test]
fn validator_accepts_public_https_and_pins_resolved_ip() {
    let resolver =
        StaticDnsResolver::try_from_pairs([("api.example.com", ["93.184.216.34"])]).unwrap();
    let url = Url::parse("https://api.example.com/v1/models").unwrap();

    let validated =
        validate_outbound_with_resolver(&url, SsrfOptions::default(), &resolver).unwrap();

    assert_eq!(validated.host, "api.example.com");
    assert_eq!(
        validated.pinned_ips,
        vec!["93.184.216.34".parse::<IpAddr>().unwrap()]
    );
    assert_eq!(validated.url.as_str(), "https://api.example.com/v1/models");
}

#[test]
fn validator_rejects_unsupported_scheme() {
    let resolver =
        StaticDnsResolver::try_from_pairs([("api.example.com", ["93.184.216.34"])]).unwrap();
    let url = Url::parse("file:///etc/passwd").unwrap();

    let error =
        validate_outbound_with_resolver(&url, SsrfOptions::default(), &resolver).unwrap_err();

    assert!(matches!(
        error.reason,
        SsrfBlockReason::UnsupportedScheme { ref scheme } if scheme == "file"
    ));
}

#[test]
fn validator_hostless_blocked_url_sanitizes_query_and_fragment() {
    let resolver =
        StaticDnsResolver::try_from_pairs([("api.example.com", ["93.184.216.34"])]).unwrap();
    let url = Url::parse("file:///etc/passwd?token=secret#frag").unwrap();

    let error =
        validate_outbound_with_resolver(&url, SsrfOptions::default(), &resolver).unwrap_err();

    assert!(matches!(
        error.reason,
        SsrfBlockReason::UnsupportedScheme { ref scheme } if scheme == "file"
    ));
    assert_eq!(error.url, "file:///etc/passwd");
}

#[test]
fn validator_sanitizes_credentials_in_blocked_url() {
    let resolver =
        StaticDnsResolver::try_from_pairs([("api.example.com", ["93.184.216.34"])]).unwrap();
    let url = Url::parse("https://token:secret@example.com/v1/models?x=1#frag").unwrap();

    let error =
        validate_outbound_with_resolver(&url, SsrfOptions::default(), &resolver).unwrap_err();

    assert!(matches!(error.reason, SsrfBlockReason::CredentialsInUrl));
    assert_eq!(error.url, "https://example.com/v1/models");
}

#[test]
fn validator_drops_query_fragment_on_blocked_metadata_url() {
    let resolver =
        StaticDnsResolver::try_from_pairs([("metadata.azure", ["168.63.129.16"])]).unwrap();
    let url = Url::parse("https://metadata.azure/latest/meta-data/metadata?x=1#frag").unwrap();

    let error =
        validate_outbound_with_resolver(&url, SsrfOptions::default(), &resolver).unwrap_err();

    assert!(matches!(error.reason, SsrfBlockReason::DeniedCloudMetadata));
    assert_eq!(error.url, "https://metadata.azure/latest/meta-data/metadata");
}

#[test]
fn validator_rejects_non_legacy_cloud_metadata_ip() {
    let resolver =
        StaticDnsResolver::try_from_pairs([("metadata.azure", ["168.63.129.16"])]).unwrap();
    let url = Url::parse("https://metadata.azure/").unwrap();

    let error =
        validate_outbound_with_resolver(&url, SsrfOptions::default(), &resolver).unwrap_err();

    assert!(matches!(error.reason, SsrfBlockReason::DeniedCloudMetadata));
}

#[test]
fn validator_rejects_aws_ipv6_metadata_even_with_private_allowed() {
    let resolver =
        StaticDnsResolver::try_from_pairs([("metadata.aws", ["fd00:ec2:0:0:0:0:0:254"])]).unwrap();
    let url = Url::parse("http://metadata.aws/latest/meta-data/").unwrap();
    let options = SsrfOptions {
        allow_private: true,
        ..SsrfOptions::default()
    };

    let error = validate_outbound_with_resolver(&url, options, &resolver).unwrap_err();

    assert!(matches!(error.reason, SsrfBlockReason::DeniedCloudMetadata));
}
