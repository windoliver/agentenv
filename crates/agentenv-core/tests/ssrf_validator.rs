use std::net::IpAddr;

use agentenv_core::security::ssrf::{
    validate_outbound_with_resolver, SsrfBlockReason, SsrfOptions, StaticDnsResolver,
};
use url::Url;

#[test]
fn validator_accepts_public_https_and_pins_resolved_ip() {
    let resolver = StaticDnsResolver::from_pairs([("api.example.com", ["93.184.216.34"])]);
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
    let resolver = StaticDnsResolver::from_pairs([("api.example.com", ["93.184.216.34"])]);
    let url = Url::parse("file:///etc/passwd").unwrap();

    let error =
        validate_outbound_with_resolver(&url, SsrfOptions::default(), &resolver).unwrap_err();

    assert!(matches!(
        error.reason,
        SsrfBlockReason::UnsupportedScheme { ref scheme } if scheme == "file"
    ));
}
