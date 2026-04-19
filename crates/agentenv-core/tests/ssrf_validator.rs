use std::net::IpAddr;

use agentenv_core::security::ssrf::{
    validate_outbound_with_resolver, IpCategory, SsrfBlockReason, SsrfOptions, StaticDnsResolver,
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
