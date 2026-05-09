use std::{
    fs,
    future::Future,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use anyhow::{anyhow, Context, Result};
use hickory_proto::{
    op::{Message, ResponseCode},
    rr::{RData, RecordType},
};
use sandbox_openshell::dns_guard::{
    classify_answer, classify_query, is_denied_answer_ip, DnsAnswerSet, DnsGuardConfig,
    DnsGuardRuntimeError, DnsQueryAction,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    time::timeout,
};
use tokio_rustls::{
    rustls::{ClientConfig, OwnedTrustAnchor, RootCertStore, ServerName},
    TlsConnector,
};
use url::Url;

const DNS_MESSAGE_CONTENT_TYPE: &str = "application/dns-message";
const MAX_DNS_UDP_PACKET_SIZE: usize = 4096;
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_DOT_PORT: u16 = 853;

#[tokio::main]
async fn main() -> Result<()> {
    let config = load_config()?;
    run_guard(config).await
}

fn load_config() -> Result<DnsGuardConfig> {
    let path = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("AGENTENV_DNS_GUARD_CONFIG").map(PathBuf::from))
        .ok_or_else(|| {
            anyhow!("DNS guard config path must be passed as argv[1] or AGENTENV_DNS_GUARD_CONFIG")
        })?;
    let config = fs::read_to_string(&path)
        .with_context(|| format!("failed to read DNS guard config at {}", path.display()))?;
    serde_json::from_str(&config)
        .with_context(|| format!("failed to parse DNS guard config at {}", path.display()))
}

async fn run_guard(config: DnsGuardConfig) -> Result<()> {
    let socket = UdpSocket::bind(&config.listen_addr)
        .await
        .with_context(|| format!("failed to bind DNS guard at {}", config.listen_addr))?;
    let mut buf = vec![0_u8; MAX_DNS_UDP_PACKET_SIZE];

    loop {
        let (len, peer) = socket.recv_from(&mut buf).await?;
        let response = handle_packet(&config, &buf[..len]).await;
        let bytes = match response {
            Ok(bytes) => bytes,
            Err(err) => {
                eprintln!("DNS guard request failed: {err:#}");
                continue;
            }
        };
        socket.send_to(&bytes, peer).await?;
    }
}

async fn handle_packet(config: &DnsGuardConfig, packet: &[u8]) -> Result<Vec<u8>> {
    let request = Message::from_vec(packet).context("failed to parse DNS request")?;
    if request.queries.len() != 1 {
        return refused_response(&request).context("failed to encode non-single-query refusal");
    }
    let query = &request.queries[0];
    let query_name = normalize_dns_name(&query.name().to_utf8());
    let qtype = query.query_type().to_string();

    let query_decision = classify_query(config, &query_name, &qtype);
    if query_decision.action == DnsQueryAction::Deny {
        log_dns_decision(
            config,
            DnsLogEvent {
                sandbox_handle: config.sandbox_handle.clone(),
                query_name,
                qtype,
                upstream: configured_upstream(config),
                cname_chain: Vec::new(),
                ips: Vec::new(),
                ttl_seconds: None,
                action: query_decision.action,
                reason: query_decision.reason_code,
            },
        );
        return refused_response(&request).context("failed to encode denied-query refusal");
    }

    let response_bytes = match resolve_via_configured_upstream(config, packet).await {
        Ok(bytes) => bytes,
        Err(err) => {
            eprintln!("DNS guard upstream request failed: {err:#}");
            return refused_response(&request).context("failed to encode upstream-error refusal");
        }
    };
    let response = match Message::from_vec(&response_bytes) {
        Ok(response) => response,
        Err(err) => {
            eprintln!("DNS guard upstream response parse failed: {err:#}");
            return refused_response(&request)
                .context("failed to encode malformed-response refusal");
        }
    };
    if let Err(err) = validate_upstream_response(&request, &response) {
        eprintln!("DNS guard upstream response validation failed: {err:#}");
        return refused_response(&request).context("failed to encode mismatched-response refusal");
    }
    let answer = answer_set_from_message(&query_name, &qtype, &response);
    let answer_decision = classify_answer(config, answer.clone());
    log_dns_decision(
        config,
        DnsLogEvent {
            sandbox_handle: config.sandbox_handle.clone(),
            query_name,
            qtype,
            upstream: configured_upstream(config),
            cname_chain: answer.cname_chain,
            ips: answer.ips,
            ttl_seconds: Some(answer.ttl_seconds),
            action: answer_decision.action,
            reason: answer_decision.reason_code,
        },
    );
    if answer_decision.action == DnsQueryAction::Deny {
        return refused_response(&request).context("failed to encode denied-answer refusal");
    }

    Ok(response_bytes)
}

async fn resolve_via_configured_upstream(
    config: &DnsGuardConfig,
    packet: &[u8],
) -> Result<Vec<u8>, DnsGuardRuntimeError> {
    if let Some(resolver) = config.resolvers_allowed.first() {
        return with_upstream_timeout(resolve_via_classic_dns(resolver, packet)).await;
    }
    if let Some(upstream) = config.doh_upstreams_allowed.first() {
        return with_upstream_timeout(resolve_via_doh(upstream, packet)).await;
    }
    if let Some(upstream) = config.dot_upstreams_allowed.first() {
        return with_upstream_timeout(resolve_via_dot(upstream, packet)).await;
    }
    Err(DnsGuardRuntimeError::Upstream {
        message: "no DNS upstream configured".to_owned(),
    })
}

async fn with_upstream_timeout<F>(operation: F) -> Result<Vec<u8>, DnsGuardRuntimeError>
where
    F: Future<Output = Result<Vec<u8>, DnsGuardRuntimeError>>,
{
    with_timeout(operation, UPSTREAM_TIMEOUT).await
}

async fn with_timeout<F>(operation: F, duration: Duration) -> Result<Vec<u8>, DnsGuardRuntimeError>
where
    F: Future<Output = Result<Vec<u8>, DnsGuardRuntimeError>>,
{
    match timeout(duration, operation).await {
        Ok(result) => result,
        Err(_) => Err(DnsGuardRuntimeError::Upstream {
            message: format!("DNS upstream timed out after {}s", duration.as_secs()),
        }),
    }
}

async fn resolve_via_classic_dns(
    resolver: &str,
    packet: &[u8],
) -> Result<Vec<u8>, DnsGuardRuntimeError> {
    let upstream = classic_resolver_endpoint(resolver)?;
    let bind_addr = if upstream
        .parse::<SocketAddr>()
        .is_ok_and(|addr| addr.is_ipv6())
    {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = UdpSocket::bind(bind_addr).await.map_err(upstream_error)?;
    socket.connect(&upstream).await.map_err(upstream_error)?;
    socket.send(packet).await.map_err(upstream_error)?;

    let mut buf = vec![0_u8; MAX_DNS_UDP_PACKET_SIZE];
    let len = socket.recv(&mut buf).await.map_err(upstream_error)?;
    buf.truncate(len);
    Ok(buf)
}

async fn resolve_via_doh(upstream: &str, packet: &[u8]) -> Result<Vec<u8>, DnsGuardRuntimeError> {
    let upstream_url = parse_doh_upstream(upstream)?;
    let response = reqwest::Client::new()
        .post(upstream_url)
        .header(reqwest::header::ACCEPT, DNS_MESSAGE_CONTENT_TYPE)
        .header(reqwest::header::CONTENT_TYPE, DNS_MESSAGE_CONTENT_TYPE)
        .body(packet.to_vec())
        .send()
        .await
        .map_err(upstream_error)?
        .error_for_status()
        .map_err(upstream_error)?;
    let bytes = response.bytes().await.map_err(upstream_error)?;
    Ok(bytes.to_vec())
}

async fn resolve_via_dot(upstream: &str, packet: &[u8]) -> Result<Vec<u8>, DnsGuardRuntimeError> {
    let (host, port) = parse_dot_upstream(upstream)?;
    let server_name = ServerName::try_from(host.as_str()).map_err(upstream_error)?;
    let stream = TcpStream::connect((host.as_str(), port))
        .await
        .map_err(upstream_error)?;
    let connector = TlsConnector::from(Arc::new(dot_client_config()));
    let mut tls = connector
        .connect(server_name, stream)
        .await
        .map_err(upstream_error)?;
    let query_len = u16::try_from(packet.len()).map_err(|_| DnsGuardRuntimeError::Upstream {
        message: format!("DNS-over-TLS query too large: {} bytes", packet.len()),
    })?;

    tls.write_all(&query_len.to_be_bytes())
        .await
        .map_err(upstream_error)?;
    tls.write_all(packet).await.map_err(upstream_error)?;
    tls.flush().await.map_err(upstream_error)?;

    let mut len_buf = [0_u8; 2];
    tls.read_exact(&mut len_buf).await.map_err(upstream_error)?;
    let response_len = usize::from(u16::from_be_bytes(len_buf));
    let mut response = vec![0_u8; response_len];
    tls.read_exact(&mut response)
        .await
        .map_err(upstream_error)?;
    Ok(response)
}

fn validate_upstream_response(
    request: &Message,
    response: &Message,
) -> Result<(), DnsGuardRuntimeError> {
    if response.metadata.id != request.metadata.id {
        return Err(DnsGuardRuntimeError::Upstream {
            message: format!(
                "upstream DNS response ID {} did not match request ID {}",
                response.metadata.id, request.metadata.id
            ),
        });
    }
    if response.queries != request.queries {
        return Err(DnsGuardRuntimeError::Upstream {
            message: "upstream DNS response question did not match request question".to_owned(),
        });
    }
    Ok(())
}

fn classic_resolver_endpoint(resolver: &str) -> Result<String, DnsGuardRuntimeError> {
    if resolver.parse::<SocketAddr>().is_ok() {
        return Ok(resolver.to_owned());
    }
    if let Ok(ip) = resolver.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, 53).to_string());
    }
    if let Some((host, port)) = resolver.rsplit_once(':') {
        if !host.contains(':') {
            validate_port(port, "classic DNS resolver", resolver)?;
            return Ok(resolver.to_owned());
        }
    }
    Ok(format!("{resolver}:53"))
}

fn parse_doh_upstream(upstream: &str) -> Result<Url, DnsGuardRuntimeError> {
    let parsed = Url::parse(upstream).map_err(upstream_error)?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(DnsGuardRuntimeError::Upstream {
            message: format!("invalid DNS-over-HTTPS upstream `{upstream}`"),
        });
    }
    if let Some(host) = parsed.host_str() {
        let host_literal = host
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .unwrap_or(host);
        if let Ok(ip) = host_literal.parse::<IpAddr>() {
            if is_denied_answer_ip(ip) {
                return Err(DnsGuardRuntimeError::Upstream {
                    message: format!(
                        "invalid DNS-over-HTTPS upstream `{upstream}`: denied host IP"
                    ),
                });
            }
        }
    }
    Ok(parsed)
}

fn parse_dot_upstream(upstream: &str) -> Result<(String, u16), DnsGuardRuntimeError> {
    let parsed = Url::parse(&format!("dot://{upstream}")).map_err(upstream_error)?;
    let host = parsed
        .host_str()
        .ok_or_else(|| DnsGuardRuntimeError::Upstream {
            message: format!("invalid DNS-over-TLS upstream `{upstream}`: missing host"),
        })?
        .to_owned();
    let port = parsed.port().unwrap_or(DEFAULT_DOT_PORT);

    if port == 0
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || !parsed.path().is_empty()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(DnsGuardRuntimeError::Upstream {
            message: format!("invalid DNS-over-TLS upstream `{upstream}`"),
        });
    }

    Ok((host, port))
}

fn validate_port(port_text: &str, kind: &str, upstream: &str) -> Result<u16, DnsGuardRuntimeError> {
    let port = port_text.parse::<u16>().map_err(upstream_error)?;
    if port == 0 {
        return Err(DnsGuardRuntimeError::Upstream {
            message: format!("invalid {kind} upstream `{upstream}`: port must be non-zero"),
        });
    }
    Ok(port)
}

fn dot_client_config() -> ClientConfig {
    let mut root_store = RootCertStore::empty();
    root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|anchor| {
        OwnedTrustAnchor::from_subject_spki_name_constraints(
            anchor.subject,
            anchor.spki,
            anchor.name_constraints,
        )
    }));
    ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth()
}

fn answer_set_from_message(query_name: &str, qtype: &str, message: &Message) -> DnsAnswerSet {
    let mut cname_chain = Vec::new();
    let mut ips = Vec::new();
    let ttl_seconds = message
        .answers
        .iter()
        .map(|record| record.ttl)
        .min()
        .unwrap_or_default();

    for record in &message.answers {
        match &record.data {
            RData::A(ip) => ips.push(IpAddr::V4(ip.0)),
            RData::AAAA(ip) => ips.push(IpAddr::V6(ip.0)),
            RData::CNAME(name) => cname_chain.push(normalize_dns_name(&name.to_utf8())),
            _ => {}
        }
    }

    DnsAnswerSet {
        query_name: query_name.to_owned(),
        qtype: qtype.to_owned(),
        cname_chain,
        ips,
        ttl_seconds,
    }
}

fn refused_response(request: &Message) -> Result<Vec<u8>> {
    let mut response = Message::error_msg(
        request.metadata.id,
        request.metadata.op_code,
        ResponseCode::Refused,
    );
    response.add_queries(request.queries.iter().cloned());
    response.to_vec().context("failed to encode DNS refusal")
}

fn normalize_dns_name(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

fn upstream_error(error: impl std::error::Error) -> DnsGuardRuntimeError {
    DnsGuardRuntimeError::Upstream {
        message: error.to_string(),
    }
}

#[derive(Debug)]
struct DnsLogEvent {
    sandbox_handle: String,
    query_name: String,
    qtype: String,
    upstream: Option<String>,
    cname_chain: Vec<String>,
    ips: Vec<IpAddr>,
    ttl_seconds: Option<u32>,
    action: DnsQueryAction,
    reason: Option<&'static str>,
}

impl DnsLogEvent {
    fn to_stderr_line(&self) -> String {
        let cname_chain = join_or_dash(self.cname_chain.iter().map(String::as_str));
        let answers = join_or_dash(self.ips.iter().map(IpAddr::to_string));
        let ttl = self
            .ttl_seconds
            .map(|ttl| ttl.to_string())
            .unwrap_or_else(|| "-".to_owned());
        let action = match self.action {
            DnsQueryAction::Allow => "allow",
            DnsQueryAction::Deny => "deny",
        };
        let reason = self.reason.unwrap_or("-");
        format!(
            "dns_guard sandbox_handle={} query_name={} qtype={} upstream={} cname_chain={} answers={} ttl={} action={} reason={}",
            self.sandbox_handle,
            self.query_name,
            self.qtype,
            self.upstream.as_deref().unwrap_or("-"),
            cname_chain,
            answers,
            ttl,
            action,
            reason
        )
    }
}

fn log_dns_decision(config: &DnsGuardConfig, event: DnsLogEvent) {
    if config.log_all_queries {
        eprintln!("{}", event.to_stderr_line());
    }
}

fn configured_upstream(config: &DnsGuardConfig) -> Option<String> {
    if let Some(resolver) = config.resolvers_allowed.first() {
        return Some(match classic_resolver_endpoint(resolver) {
            Ok(endpoint) => endpoint,
            Err(_) => resolver.clone(),
        });
    }
    if let Some(upstream) = config.doh_upstreams_allowed.first() {
        return Some(upstream.clone());
    }
    config.dot_upstreams_allowed.first().cloned()
}

fn join_or_dash(items: impl Iterator<Item = impl ToString>) -> String {
    let joined = items
        .map(|item| item.to_string())
        .collect::<Vec<_>>()
        .join(",");
    if joined.is_empty() {
        "-".to_owned()
    } else {
        joined
    }
}

#[allow(dead_code)]
fn qtype_from_str(qtype: &str) -> Result<RecordType> {
    qtype
        .parse()
        .with_context(|| format!("unsupported DNS record type {qtype}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::{
        op::{MessageType, OpCode, Query},
        rr::Name,
    };
    use std::future::pending;

    #[test]
    fn classic_resolver_endpoint_defaults_ipv6_literal_to_port_53() {
        assert_eq!(
            classic_resolver_endpoint("2606:4700:4700::1111").expect("resolver"),
            "[2606:4700:4700::1111]:53"
        );
    }

    #[test]
    fn upstream_response_validation_rejects_mismatched_id_and_question() {
        let request = query_message(42, "api.github.com.", RecordType::A);
        let response_with_bad_id = query_message(43, "api.github.com.", RecordType::A);
        let response_with_bad_question = query_message(42, "example.com.", RecordType::A);

        assert!(validate_upstream_response(&request, &response_with_bad_id).is_err());
        assert!(validate_upstream_response(&request, &response_with_bad_question).is_err());
    }

    #[test]
    fn doh_upstream_validation_rejects_malformed_and_denied_ip_hosts() {
        assert!(parse_doh_upstream("https://dns.google/dns-query").is_ok());

        for upstream in [
            "http://dns.google/dns-query",
            "https://user@dns.google/dns-query",
            "https://dns.google/dns-query?name=example.com",
            "https://dns.google/dns-query#frag",
            "https://10.0.0.1/dns-query",
            "https://[fd00::1]/dns-query",
        ] {
            assert!(
                parse_doh_upstream(upstream).is_err(),
                "{upstream} should be rejected"
            );
        }
    }

    #[tokio::test]
    async fn upstream_timeout_returns_deterministic_error() {
        let result = with_timeout(
            async { pending::<Result<Vec<u8>, DnsGuardRuntimeError>>().await },
            Duration::from_millis(1),
        )
        .await;

        let err = result.expect_err("pending upstream should time out");

        assert!(err.to_string().contains("timed out"));
    }

    #[tokio::test]
    async fn multi_question_request_is_refused_without_upstream_forwarding() {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.expect("upstream bind");
        let mut request = query_message(42, "api.github.com.", RecordType::A);
        request.add_query(Query::query(
            Name::from_ascii("blocked.example.").expect("query name"),
            RecordType::A,
        ));
        let config = DnsGuardConfig {
            sandbox_handle: "devbox".to_owned(),
            listen_addr: "127.0.0.1:1053".to_owned(),
            resolvers_allowed: vec![upstream.local_addr().expect("upstream addr").to_string()],
            doh_upstreams_allowed: Vec::new(),
            dot_upstreams_allowed: Vec::new(),
            allowed_query_names: ["api.github.com".to_owned()].into_iter().collect(),
            log_all_queries: false,
            pin_resolved_ips: false,
        };
        let packet = request.to_vec().expect("request bytes");
        let mut upstream_buf = [0_u8; MAX_DNS_UDP_PACKET_SIZE];

        tokio::select! {
            result = handle_packet(&config, &packet) => {
                let response_bytes = result.expect("handle packet");
                let response = Message::from_vec(&response_bytes).expect("response message");
                assert_eq!(response.metadata.response_code, ResponseCode::Refused);
            }
            received = upstream.recv_from(&mut upstream_buf) => {
                let (len, peer) = received.expect("upstream receive");
                panic!("multi-question request was forwarded upstream to {peer}: {len} bytes");
            }
        }
    }

    #[test]
    fn dns_log_event_includes_decision_context() {
        let decision = DnsLogEvent {
            sandbox_handle: "devbox".to_owned(),
            query_name: "api.github.com".to_owned(),
            qtype: "AAAA".to_owned(),
            upstream: Some("1.1.1.1".to_owned()),
            cname_chain: vec!["github.map.fastly.net".to_owned()],
            ips: vec!["::ffff:10.0.0.1".parse().expect("ip")],
            ttl_seconds: Some(60),
            action: DnsQueryAction::Deny,
            reason: Some("dns_answer_denied"),
        };

        let line = decision.to_stderr_line();

        assert!(line.contains("sandbox_handle=devbox"));
        assert!(line.contains("query_name=api.github.com"));
        assert!(line.contains("qtype=AAAA"));
        assert!(line.contains("upstream=1.1.1.1"));
        assert!(line.contains("cname_chain=github.map.fastly.net"));
        assert!(line.contains("answers=::ffff:10.0.0.1"));
        assert!(line.contains("ttl=60"));
        assert!(line.contains("action=deny"));
        assert!(line.contains("reason=dns_answer_denied"));
    }

    fn query_message(id: u16, name: &str, record_type: RecordType) -> Message {
        let mut message = Message::new(id, MessageType::Query, OpCode::Query);
        message.add_query(Query::query(
            Name::from_ascii(name).expect("query name"),
            record_type,
        ));
        message
    }
}
