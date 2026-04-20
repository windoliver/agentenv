# M2-4 Built-In Inference Drivers Design

Date: 2026-04-19
Issue: [#10](https://github.com/windoliver/agentenv/issues/10)
Milestone: M2 - Built-in drivers

## Summary

Implement the built-in inference driver crates as a scaffold-compatible MVP. The
drivers will satisfy the existing `InferenceDriver` trait, expose provider-specific
configuration and credential requirements, and provide deterministic native-routing
and proxy-sidecar planning helpers for the future create lifecycle.

The current repository has the driver protocol, blueprint parsing, registry entries,
policy inference routes, and placeholder inference crates, but it does not yet have a
runtime create/apply pipeline that can start sidecars or call OpenShell native routing.
This design therefore makes the inference drivers real and testable without inventing
runtime lifecycle plumbing ahead of M4.

## Affected Crates

- `crates/agentenv-core`
- `crates/drivers/inference-passthrough`
- `crates/drivers/inference-openai`
- `crates/drivers/inference-anthropic`
- `crates/drivers/inference-ollama`

## Scope

In scope:

- Implement concrete built-in inference driver types for passthrough, OpenAI,
  Anthropic, and Ollama.
- Implement the existing `agentenv_core::driver::InferenceDriver` trait for each
  driver.
- Parse provider configuration from `agentenv_proto::InferenceSpec.config`.
- Return correct driver metadata and inference capabilities from `initialize`.
- Return provider credential requirements from `credential_requirements`.
- Return deterministic handles and in-sandbox endpoint URLs from `provision` and
  `endpoint_in_sandbox`.
- Provide pure, testable planning helpers for native sandbox delegation and proxy
  sidecar routing.
- Add focused unit tests for behavior and configuration validation.

Out of scope:

- Starting real proxy processes inside a sandbox.
- Calling `openshell inference set` or any other sandbox runtime command.
- Adding a new protocol method or changing the existing `InferenceDriver` schema.
- Performing real upstream OpenAI, Anthropic, or Ollama network requests.
- Implementing runtime model switching. The MVP exposes model-switching capability
  metadata and plan fields; runtime switching belongs with lifecycle orchestration.
- Verifying credential stripping with tcpdump or live proxy inspection. The MVP tests
  the sidecar plan shape that enables stripping; live inspection belongs with the
  runtime proxy implementation.

## Goals

1. Turn the inference driver crates from placeholders into real built-in drivers.
2. Preserve the existing four-axis architecture and JSON-RPC-compatible trait shape.
3. Keep credentials out of handles, endpoint URLs, logs, and serialized plan output.
4. Make future native-routing and sidecar execution straightforward for lifecycle code.
5. Keep the MVP deterministic and unit-testable without depending on external services.

## Architecture

The MVP centers on the existing `InferenceDriver` trait:

- `initialize` reports driver identity and inference capabilities.
- `preflight` succeeds without host checks for the MVP.
- `provision` validates config and returns a deterministic `InferenceHandle`.
- `endpoint_in_sandbox` returns the endpoint encoded by that handle.
- `credential_requirements` declares provider credentials.
- `teardown` and `shutdown` are no-ops.

`inference-passthrough` is a true no-op driver. It does not strip caller credentials,
does not support model switching, and returns an empty endpoint so agents continue
using their own provider credentials directly.

`inference-openai`, `inference-anthropic`, and `inference-ollama` are routed drivers.
They parse provider config and expose deterministic plan helpers for the two runtime
paths described by issue #10:

- Native routing: when a sandbox later reports
  `supports_native_inference_routing = true`, lifecycle code can build a native
  routing plan from provider, model, and base URL fields.
- Proxy sidecar: when native routing is unavailable, lifecycle code can build a
  proxy plan with a loopback listen endpoint, upstream base URL, model, and credential
  env var name.

The driver itself does not decide between native and proxy modes because the current
`InferenceDriver::provision` signature receives only `InferenceSpec`, not sandbox
capabilities. That decision belongs in future lifecycle orchestration, where both the
sandbox capabilities and inference driver behavior are visible.

## Component Design

### `inference-passthrough`

Exports `PassthroughInferenceDriver`.

Behavior:

- Driver name: `passthrough`.
- Capabilities: `strips_caller_credentials = false`,
  `supports_model_switching = false`.
- `credential_requirements` returns an empty list.
- `provision` returns a stable passthrough handle.
- `endpoint_in_sandbox` returns `url = ""`.

### Routed Provider Drivers

Each routed crate exports one concrete driver:

- `OpenAiInferenceDriver`
- `AnthropicInferenceDriver`
- `OllamaInferenceDriver`

Each driver uses the same conceptual flow:

1. Parse `InferenceSpec.config`.
2. Apply provider defaults.
3. Validate optional `base_url`.
4. Produce a stable handle.
5. Resolve that handle to a deterministic in-sandbox endpoint.

Provider defaults:

| Driver | Default Model | Default Base URL | Credential |
| --- | --- | --- | --- |
| OpenAI | `gpt-4o` | `https://api.openai.com/v1` | `OPENAI_API_KEY` |
| Anthropic | `claude-3-5-sonnet-latest` | `https://api.anthropic.com` | `ANTHROPIC_API_KEY` |
| Ollama | `llama3.1` | `http://127.0.0.1:11434` | none |

Routed driver capabilities:

- `strips_caller_credentials = true`
- `supports_model_switching = true`

Ollama has no default credential requirement because local Ollama-style endpoints
normally do not need an API key. If a future remote Ollama-compatible provider needs
credentials, that should be added as an explicit config extension instead of inventing
an implicit credential now.

## Config Model

The blueprint surface remains:

```yaml
inference:
  driver: openai
  model: gpt-4o
  base_url: ${OPENAI_BASE_URL}
  credentials:
    OPENAI_API_KEY:
      source: env
```

Core already stores component-specific extra fields in `ComponentSection.extra`; the
future create path can pass those fields into `InferenceSpec.config`.

Supported config keys:

- `model`: optional string; uses provider default when absent.
- `base_url`: optional string; uses provider default when absent.

Unknown config keys are tolerated by blueprint parsing and ignored by the MVP driver
helpers. This follows the current flattened component model and preserves forwards
compatibility for provider-specific additions.

## Planning Helpers

Routed drivers expose pure helper types:

- `ProviderConfig`
- `NativeRoutingPlan`
- `ProxySidecarPlan`

`ProviderConfig` contains:

- provider name
- model
- base URL
- credential env var name, when required

`NativeRoutingPlan` contains:

- provider name
- model
- base URL
- endpoint exposed by the sandbox, defaulting to `http://inference.local`

`ProxySidecarPlan` contains:

- listen URL, defaulting to a deterministic loopback URL
- upstream base URL
- provider name
- model
- credential env var name, when required

Plans contain credential names only, never credential values.

## Data Flow

1. A blueprint declares an optional `inference` component.
2. Blueprint resolution pins the selected inference driver through the existing
   registry.
3. Future lifecycle code converts the component's flattened extra fields into
   `InferenceSpec.config`.
4. The selected driver validates config through `provision`.
5. `endpoint_in_sandbox` returns either an empty endpoint for passthrough or the
   routed endpoint encoded by the driver handle.
6. Future lifecycle code combines sandbox capabilities with routed-driver planning
   helpers to execute native routing or sidecar proxy setup.

## Error Handling

`agentenv-core` should add a narrow driver error for invalid configuration if one does
not already exist. The error should include the field name and a clear message. Driver
implementations should use this error for:

- non-string `model`
- empty `model`
- non-string `base_url`
- empty `base_url`
- malformed `base_url`
- handle strings not produced by the driver

Driver code must not use `.unwrap()` outside tests. Invalid user input must produce
structured errors rather than panics.

## Credential Handling

Drivers declare credential requirements but never resolve or store credential values.

OpenAI requirement:

- name: `OPENAI_API_KEY`
- kind: `api_key`
- required: `true`

Anthropic requirement:

- name: `ANTHROPIC_API_KEY`
- kind: `api_key`
- required: `true`

Passthrough and Ollama return no requirements.

Handles, endpoints, and plan structs must not include credential values. Proxy plans
may include only the credential environment variable name that future lifecycle code
will use when launching the proxy.

## Testing Strategy

Tests should avoid network calls and external runtimes.

`inference-passthrough` tests:

- `initialize` returns inference driver metadata and passthrough capabilities.
- `credential_requirements` returns an empty list.
- `provision` returns a stable handle.
- `endpoint_in_sandbox` returns an empty URL.

Routed driver tests for each provider:

- `initialize` returns provider metadata and routed capabilities.
- default config yields the provider's default model and base URL.
- custom `model` is accepted.
- custom `base_url` is accepted when it is a valid URL.
- invalid config values produce driver config errors.
- credential requirements match provider expectations.
- native routing plan contains provider, model, base URL, and `http://inference.local`.
- proxy sidecar plan contains listen URL, upstream base URL, provider, model, and
  credential env var name when required.
- `endpoint_in_sandbox` returns the planned routed endpoint.
- handles from other providers or malformed handles are rejected.

Workspace verification:

- `cargo fmt`
- `cargo clippy --workspace -- -D warnings`
- `cargo test --workspace`

## Acceptance Mapping

Issue acceptance criteria mapped to the MVP:

- Passthrough is a no-op that composes cleanly: implemented directly by
  `PassthroughInferenceDriver`.
- Routed drivers delegate when sandbox supports native routing: represented by
  deterministic `NativeRoutingPlan` helpers because runtime sandbox execution is not
  present yet.
- Routed drivers run an in-sandbox proxy when sandbox does not support native routing:
  represented by deterministic `ProxySidecarPlan` helpers because runtime sidecar
  execution is not present yet.
- Credential stripping verified by inspection: MVP verifies plans contain credential
  env var names but no values; live stripping inspection is deferred to the runtime
  proxy phase.
- Model switching works where upstream supports it: MVP exposes model fields and
  routed driver capability metadata; runtime switching is deferred until the lifecycle
  layer can reapply inference routing.

## Trade-Offs

This design deliberately prioritizes protocol-compatible driver behavior over runtime
execution. The trade-off is that issue #10 will have a clear MVP boundary: the crates
become real and future-ready, but full proxy launch and OpenShell integration remain
deferred until lifecycle execution exists.

The alternative would be to add a sandbox-capability parameter to the inference
protocol now. That would force a schema change and contradict the existing protocol
document, so this design avoids it.
