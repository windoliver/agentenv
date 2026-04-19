use std::net::IpAddr;

use agentenv_core::security::ssrf::{
    validate_outbound_with_resolver, validate_redirect_chain_with_resolver, IpCategory,
    SsrfBlockReason, SsrfOptions, StaticDnsResolver,
};
use ipnet::IpNet;
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
    assert_eq!(
        error.url,
        "https://metadata.azure/latest/meta-data/metadata"
    );
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

#[test]
fn validator_rejects_credentials_in_url() {
    let resolver =
        StaticDnsResolver::try_from_pairs([("api.example.com", ["93.184.216.34"])]).unwrap();
    let url = Url::parse("https://user:pass@api.example.com/v1/models").unwrap();

    let error =
        validate_outbound_with_resolver(&url, SsrfOptions::default(), &resolver).unwrap_err();

    assert!(matches!(error.reason, SsrfBlockReason::CredentialsInUrl));
}

#[test]
fn validator_rejects_denied_ip_categories_by_default() {
    let cases = vec![
        ("loopback.example.com", "127.0.0.1", IpCategory::Loopback),
        (
            "link_local.example.com",
            "169.254.10.20",
            IpCategory::LinkLocal,
        ),
        ("private.example.com", "10.1.2.3", IpCategory::Private),
        ("reserved.example.com", "100.64.0.1", IpCategory::Reserved),
        ("multicast.example.com", "224.0.0.1", IpCategory::Multicast),
        (
            "broadcast.example.com",
            "255.255.255.255",
            IpCategory::Broadcast,
        ),
        (
            "documentation.example.com",
            "192.0.2.10",
            IpCategory::Documentation,
        ),
        (
            "unspecified.example.com",
            "0.0.0.0",
            IpCategory::Unspecified,
        ),
    ];

    for (name, ip, expected_category) in cases {
        let resolver = StaticDnsResolver::try_from_pairs([(name, [ip])]).unwrap();
        let url = Url::parse(&format!("http://{name}/")).unwrap();

        let error =
            validate_outbound_with_resolver(&url, SsrfOptions::default(), &resolver).unwrap_err();

        assert!(
            matches!(error.reason, SsrfBlockReason::DeniedIp { category } if category == expected_category)
        );
        assert_eq!(error.resolved_ip, Some(ip.parse::<IpAddr>().unwrap()));
    }
}

#[test]
fn validator_blocks_cloud_metadata_even_if_private_allowed() {
    let url = Url::parse("http://169.254.169.254/latest/meta-data/").unwrap();
    let options = SsrfOptions {
        allow_private: true,
        ..SsrfOptions::default()
    };

    let resolver = StaticDnsResolver::default();
    let error = validate_outbound_with_resolver(&url, options, &resolver).unwrap_err();

    assert!(matches!(error.reason, SsrfBlockReason::DeniedCloudMetadata));
}

#[test]
fn validator_accepts_private_ips_when_allowed() {
    let url = Url::parse("http://10.1.2.3/health").unwrap();
    let options = SsrfOptions {
        allow_private: true,
        ..SsrfOptions::default()
    };

    let validated =
        validate_outbound_with_resolver(&url, options, &StaticDnsResolver::default()).unwrap();

    assert_eq!(validated.host, "10.1.2.3");
    assert_eq!(
        validated.pinned_ips,
        vec!["10.1.2.3".parse::<IpAddr>().unwrap()]
    );
}

#[test]
fn validator_normalizes_mapped_ipv6_and_denies_cloud_metadata() {
    let resolver =
        StaticDnsResolver::try_from_pairs([("metadata.example.com", ["::ffff:169.254.169.254"])])
            .unwrap();
    let url = Url::parse("http://metadata.example.com/latest/meta-data/").unwrap();

    let error =
        validate_outbound_with_resolver(&url, SsrfOptions::default(), &resolver).unwrap_err();

    assert!(matches!(error.reason, SsrfBlockReason::DeniedCloudMetadata));
    assert_eq!(error.resolved_ip, Some("169.254.169.254".parse().unwrap()));
}

#[test]
fn validator_blocks_extra_cidr_denylist() {
    let resolver =
        StaticDnsResolver::try_from_pairs([("api.example.com", ["93.184.216.34"])]).unwrap();
    let url = Url::parse("https://api.example.com/v1/models").unwrap();
    let options = SsrfOptions {
        extra_deny_cidrs: vec!["93.184.216.0/24".parse::<IpNet>().unwrap()],
        ..SsrfOptions::default()
    };

    let error = validate_outbound_with_resolver(&url, options, &resolver).unwrap_err();

    assert!(
        matches!(error.reason, SsrfBlockReason::DeniedExtraCidr { cidr } if cidr == "93.184.216.0/24")
    );
}

#[test]
fn validator_blocks_mixed_allowed_and_denied_resolutions() {
    let resolver =
        StaticDnsResolver::try_from_pairs([("mixed.example.com", ["93.184.216.34", "127.0.0.1"])])
            .unwrap();
    let url = Url::parse("https://mixed.example.com/").unwrap();

    let error =
        validate_outbound_with_resolver(&url, SsrfOptions::default(), &resolver).unwrap_err();

    assert!(matches!(
        error.reason,
        SsrfBlockReason::DeniedIp {
            category: IpCategory::Loopback
        }
    ));
}

#[test]
fn redirect_chain_revalidates_each_location() {
    let resolver = StaticDnsResolver::try_from_pairs([
        ("start.example.com", ["93.184.216.34"]),
        ("next.example.com", ["93.184.216.35"]),
    ])
    .unwrap();
    let start = Url::parse("https://start.example.com/download").unwrap();

    let chain = validate_redirect_chain_with_resolver(
        &start,
        &["https://next.example.com/artifact"],
        SsrfOptions::default(),
        &resolver,
    )
    .unwrap();

    assert_eq!(chain.len(), 2);
    assert_eq!(chain[0].host, "start.example.com");
    assert_eq!(chain[1].host, "next.example.com");
    assert_eq!(
        chain[1].pinned_ips,
        vec!["93.184.216.35".parse::<IpAddr>().unwrap()]
    );
}

#[test]
fn redirect_chain_blocks_metadata_location() {
    let resolver =
        StaticDnsResolver::try_from_pairs([("start.example.com", ["93.184.216.34"])]).unwrap();
    let start = Url::parse("https://start.example.com/download").unwrap();

    let error = validate_redirect_chain_with_resolver(
        &start,
        &["http://169.254.169.254/latest/meta-data/"],
        SsrfOptions::default(),
        &resolver,
    )
    .unwrap_err();

    assert!(matches!(error.reason, SsrfBlockReason::DeniedCloudMetadata));
}

#[test]
fn redirect_chain_enforces_default_limit() {
    let resolver =
        StaticDnsResolver::try_from_pairs([("start.example.com", ["93.184.216.34"])]).unwrap();
    let start = Url::parse("https://start.example.com/download").unwrap();

    let error = validate_redirect_chain_with_resolver(
        &start,
        &["/one", "/two", "/three", "/four"],
        SsrfOptions::default(),
        &resolver,
    )
    .unwrap_err();

    assert!(matches!(
        error.reason,
        SsrfBlockReason::RedirectLimitExceeded { max_redirects: 3 }
    ));
}

#[test]
fn redirect_chain_resolves_relative_locations_against_current_url() {
    let resolver = StaticDnsResolver::try_from_pairs([
        ("start.example.com", ["93.184.216.34"]),
        ("next.example.com", ["93.184.216.35"]),
    ])
    .unwrap();
    let start = Url::parse("https://start.example.com/releases/latest").unwrap();

    let chain = validate_redirect_chain_with_resolver(
        &start,
        &["../assets/pkg.tar.gz", "https://next.example.com/final"],
        SsrfOptions::default(),
        &resolver,
    )
    .unwrap();

    assert_eq!(chain.len(), 3);
    assert_eq!(
        chain[1].url.as_str(),
        "https://start.example.com/assets/pkg.tar.gz"
    );
    assert_eq!(chain[2].host, "next.example.com");
}

#[test]
fn redirect_chain_rejects_malformed_location() {
    let resolver =
        StaticDnsResolver::try_from_pairs([("start.example.com", ["93.184.216.34"])]).unwrap();
    let start = Url::parse("https://start.example.com/download").unwrap();

    let error = validate_redirect_chain_with_resolver(
        &start,
        &["http://["],
        SsrfOptions::default(),
        &resolver,
    )
    .unwrap_err();

    assert!(matches!(
        error.reason,
        SsrfBlockReason::MalformedRedirect { ref location } if location == "http://["
    ));
}
