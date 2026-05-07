# agentenv-policy

M1 scaffold crate for the `agentenv` workspace.

## Image Hardening Profiles

Image hardening profiles live under `hardening/` and are loaded by the policy
crate alongside network policy presets.

- `baseline.yaml` is the default production profile for sandbox images.
- `strict.yaml` is the sensitive-work profile with tighter package, capability,
  tmpfs, and runtime recommendations.
- `open.yaml` is the minimal profile for exploratory environments.

The crate owns typed parsing, normalization, and validation for built-in and
custom profiles. It also merges supported filesystem settings into
`NetworkPolicy` and serializes image/runtime recommendations into stable
`hardening_*` metadata for sandbox drivers. Validation rejects malformed profile
YAML, empty names or descriptions, invalid filesystem paths, invalid package or
capability entries, missing Dockerfile fragments, and non-positive ulimits.
