#![forbid(unsafe_code)]

use agentenv_core::security::ssrf::{
    sanitize_untrusted_url_text, validate_outbound_with_resolver, DnsResolver, SsrfBlockReason,
    SsrfBlocked, SsrfOptions, ValidatedUrl,
};
use agentenv_proto::{McpEndpoint, McpTransport};
use url::Url;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedMcpEndpoint {
    pub endpoint: McpEndpoint,
    pub validated_url: Option<ValidatedUrl>,
}

pub fn validate_mcp_endpoint(
    endpoint: &McpEndpoint,
    opts: SsrfOptions,
    resolver: &dyn DnsResolver,
) -> Result<ValidatedMcpEndpoint, SsrfBlocked> {
    if matches!(endpoint.transport, McpTransport::SshHttp) && !opts.allow_ssh_http {
        return Err(SsrfBlocked {
            url: sanitize_untrusted_url_text(&endpoint.url),
            host: None,
            resolved_ip: None,
            reason: SsrfBlockReason::UnsupportedScheme {
                scheme: "ssh+http".to_owned(),
            },
        });
    }

    match &endpoint.transport {
        McpTransport::Stdio => Ok(ValidatedMcpEndpoint {
            endpoint: endpoint.clone(),
            validated_url: None,
        }),
        McpTransport::Http | McpTransport::HttpSse | McpTransport::SshHttp => {
            let url = Url::parse(&endpoint.url).map_err(|_| {
                let sanitized = sanitize_untrusted_url_text(&endpoint.url);
                SsrfBlocked {
                    url: sanitized.clone(),
                    host: None,
                    resolved_ip: None,
                    reason: SsrfBlockReason::MalformedRedirect {
                        location: sanitized,
                    },
                }
            })?;
            let validated_url = validate_outbound_with_resolver(&url, opts, resolver)?;

            Ok(ValidatedMcpEndpoint {
                endpoint: endpoint.clone(),
                validated_url: Some(validated_url),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use agentenv_core::security::ssrf::{SsrfBlockReason, SsrfOptions, StaticDnsResolver};
    use agentenv_proto::{McpEndpoint, McpTransport};

    use super::validate_mcp_endpoint;

    fn endpoint(url: &str, transport: McpTransport) -> McpEndpoint {
        McpEndpoint {
            url: url.to_owned(),
            transport,
            headers: BTreeMap::from([("authorization".to_owned(), "Bearer test".to_owned())]),
        }
    }

    #[test]
    fn stdio_endpoint_skips_validation() {
        let endpoint = endpoint("not a url", McpTransport::Stdio);
        let resolver = StaticDnsResolver::default();

        let validated =
            validate_mcp_endpoint(&endpoint, SsrfOptions::default(), &resolver).unwrap();

        assert_eq!(validated.endpoint, endpoint);
        assert!(validated.validated_url.is_none());
    }

    #[test]
    fn http_sse_endpoint_validates_and_exposes_pinned_ips() {
        let endpoint = endpoint("https://mcp.example.com/sse", McpTransport::HttpSse);
        let resolver =
            StaticDnsResolver::try_from_pairs([("mcp.example.com", ["93.184.216.34"])]).unwrap();

        let validated =
            validate_mcp_endpoint(&endpoint, SsrfOptions::default(), &resolver).unwrap();
        let validated_url = validated.validated_url.unwrap();

        assert_eq!(validated.endpoint, endpoint);
        assert_eq!(validated_url.host, "mcp.example.com");
        assert_eq!(
            validated_url.pinned_ips,
            vec!["93.184.216.34".parse::<std::net::IpAddr>().unwrap()]
        );
    }

    #[test]
    fn ssh_http_requires_opt_in() {
        let endpoint = endpoint("ssh+http://mcp.example.com/sse", McpTransport::SshHttp);
        let resolver =
            StaticDnsResolver::try_from_pairs([("mcp.example.com", ["93.184.216.34"])]).unwrap();

        let blocked =
            validate_mcp_endpoint(&endpoint, SsrfOptions::default(), &resolver).unwrap_err();

        assert!(matches!(
            blocked.reason,
            SsrfBlockReason::UnsupportedScheme { ref scheme } if scheme == "ssh+http"
        ));
    }

    #[test]
    fn ssh_http_transport_requires_opt_in_for_https_url() {
        let endpoint = endpoint("https://mcp.example.com/sse", McpTransport::SshHttp);
        let resolver =
            StaticDnsResolver::try_from_pairs([("mcp.example.com", ["93.184.216.34"])]).unwrap();

        let blocked =
            validate_mcp_endpoint(&endpoint, SsrfOptions::default(), &resolver).unwrap_err();

        assert!(matches!(
            blocked.reason,
            SsrfBlockReason::UnsupportedScheme { ref scheme } if scheme == "ssh+http"
        ));
    }

    #[test]
    fn ssh_http_validates_when_opted_in() {
        let endpoint = endpoint("ssh+http://mcp.example.com/sse", McpTransport::SshHttp);
        let resolver =
            StaticDnsResolver::try_from_pairs([("mcp.example.com", ["93.184.216.34"])]).unwrap();
        let options = SsrfOptions {
            allow_ssh_http: true,
            ..SsrfOptions::default()
        };

        let validated = validate_mcp_endpoint(&endpoint, options, &resolver).unwrap();
        let validated_url = validated.validated_url.unwrap();

        assert_eq!(validated_url.host, "mcp.example.com");
        assert_eq!(
            validated_url.pinned_ips,
            vec!["93.184.216.34".parse::<std::net::IpAddr>().unwrap()]
        );
    }

    #[test]
    fn unsafe_metadata_url_is_blocked() {
        let endpoint = endpoint("https://mcp.example.com/sse", McpTransport::Http);
        let resolver =
            StaticDnsResolver::try_from_pairs([("mcp.example.com", ["169.254.169.254"])]).unwrap();

        let blocked =
            validate_mcp_endpoint(&endpoint, SsrfOptions::default(), &resolver).unwrap_err();

        assert!(matches!(
            blocked.reason,
            SsrfBlockReason::DeniedCloudMetadata
        ));
    }

    #[test]
    fn malformed_url_is_blocked() {
        let endpoint = endpoint("http://[", McpTransport::Http);
        let resolver = StaticDnsResolver::default();

        let blocked =
            validate_mcp_endpoint(&endpoint, SsrfOptions::default(), &resolver).unwrap_err();

        assert!(matches!(
            blocked.reason,
            SsrfBlockReason::MalformedRedirect { ref location } if location == "http://["
        ));
    }

    #[test]
    fn malformed_url_error_is_sanitized() {
        let endpoint = endpoint("http://user:pass@[?token=secret#frag", McpTransport::Http);
        let resolver = StaticDnsResolver::default();

        let blocked =
            validate_mcp_endpoint(&endpoint, SsrfOptions::default(), &resolver).unwrap_err();

        assert_eq!(blocked.url, "http://[");
        let SsrfBlockReason::MalformedRedirect { location } = blocked.reason else {
            panic!("expected malformed redirect");
        };
        assert_eq!(location, "http://[");
    }
}
