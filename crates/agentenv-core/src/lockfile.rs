use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_yaml::{Mapping, Value};
use thiserror::Error;

use crate::blueprint::{PolicyOverride, PolicySection, StateSection};
use crate::digest::{parse_sha256_digest, parse_sha256_hex, DigestError};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lockfile {
    pub version: String,
    pub protocol_version: String,
    pub blueprint_hash: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub drivers: BTreeMap<String, DriverPin>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub artifacts: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub credentials: BTreeMap<String, CredentialRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_blueprint: Option<LockedBlueprint>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriverPin {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialRef {
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(flatten, default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockedBlueprint {
    pub version: String,
    pub min_agentenv_version: String,
    pub sandbox: LockedComponent,
    pub agent: LockedComponent,
    pub context: LockedComponent,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inference: Option<LockedComponent>,
    pub policy: PolicySection,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<StateSection>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockedComponent {
    pub driver: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub credentials: BTreeMap<String, CredentialRef>,
    #[serde(flatten, default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Error)]
pub enum LockfileError {
    #[error("failed to parse lockfile YAML: {0}")]
    ParseYaml(serde_yaml::Error),
    #[error("failed to deserialize lockfile data: {0}")]
    Deserialize(serde_yaml::Error),
    #[error("failed to serialize lockfile data: {0}")]
    Serialize(serde_yaml::Error),
    #[error("invalid blueprint hash: {source}")]
    InvalidBlueprintHash {
        #[source]
        source: DigestError,
    },
    #[error("invalid artifact digest for `{name}`: {source}")]
    InvalidArtifactDigest {
        name: String,
        #[source]
        source: DigestError,
    },
    #[error("lockfile credential values are not allowed for `{name}`")]
    CredentialValueNotAllowed { name: String },
    #[error("lockfile credential field `{field}` for `{name}` appears to contain an inline secret; credential values are not allowed")]
    CredentialFieldNotAllowed { name: String, field: String },
    #[error("lockfile credential field `{field}` for `{name}` uses a complex YAML key; credential extra keys must be strings")]
    InvalidCredentialExtraKey { name: String, field: String },
}

impl Lockfile {
    pub fn from_yaml(yaml: &str) -> Result<Self, LockfileError> {
        let value: Value = serde_yaml::from_str(yaml).map_err(LockfileError::ParseYaml)?;
        let lockfile: Self = serde_yaml::from_value(value).map_err(LockfileError::Deserialize)?;
        lockfile.validate()?;
        Ok(lockfile)
    }

    pub fn to_yaml_deterministic(&self) -> Result<String, LockfileError> {
        self.validate()?;
        let canonical = self.canonicalized();
        serde_yaml::to_string(&canonical).map_err(LockfileError::Serialize)
    }

    pub fn validate_no_secret_values(&self) -> Result<(), LockfileError> {
        validate_credentials(&self.credentials)?;

        if let Some(resolved_blueprint) = self.resolved_blueprint.as_ref() {
            validate_credentials(&resolved_blueprint.sandbox.credentials)?;
            validate_credentials(&resolved_blueprint.agent.credentials)?;
            validate_credentials(&resolved_blueprint.context.credentials)?;
            if let Some(inference) = resolved_blueprint.inference.as_ref() {
                validate_credentials(&inference.credentials)?;
            }
        }

        Ok(())
    }

    fn validate(&self) -> Result<(), LockfileError> {
        parse_sha256_hex(&self.blueprint_hash)
            .map_err(|source| LockfileError::InvalidBlueprintHash { source })?;

        for (name, digest) in &self.artifacts {
            parse_sha256_digest(digest).map_err(|source| LockfileError::InvalidArtifactDigest {
                name: name.clone(),
                source,
            })?;
        }

        self.validate_no_secret_values()
    }

    fn canonicalized(&self) -> Self {
        let mut lockfile = self.clone();

        canonicalize_credentials(&mut lockfile.credentials);
        if let Some(resolved_blueprint) = lockfile.resolved_blueprint.as_mut() {
            canonicalize_component(&mut resolved_blueprint.sandbox);
            canonicalize_component(&mut resolved_blueprint.agent);
            canonicalize_component(&mut resolved_blueprint.context);
            if let Some(inference) = resolved_blueprint.inference.as_mut() {
                canonicalize_component(inference);
            }
            canonicalize_policy(&mut resolved_blueprint.policy);
            if let Some(state) = resolved_blueprint.state.as_mut() {
                canonicalize_state(state);
            }
        }

        lockfile
    }
}

fn validate_credentials(
    credentials: &BTreeMap<String, CredentialRef>,
) -> Result<(), LockfileError> {
    for (name, credential) in credentials {
        if credential.value.is_some() {
            return Err(LockfileError::CredentialValueNotAllowed { name: name.clone() });
        }

        for (field, value) in &credential.extra {
            if let Some(field_path) =
                find_secret_like_field(field, value, field).map_err(|field_path| {
                    LockfileError::InvalidCredentialExtraKey {
                        name: name.clone(),
                        field: field_path,
                    }
                })?
            {
                return Err(LockfileError::CredentialFieldNotAllowed {
                    name: name.clone(),
                    field: field_path,
                });
            }
        }
    }

    Ok(())
}

fn canonicalize_credentials(credentials: &mut BTreeMap<String, CredentialRef>) {
    for credential in credentials.values_mut() {
        for value in credential.extra.values_mut() {
            *value = canonicalize_yaml_value(value.clone());
        }
    }
}

fn canonicalize_component(component: &mut LockedComponent) {
    canonicalize_credentials(&mut component.credentials);
    for value in component.extra.values_mut() {
        *value = canonicalize_yaml_value(value.clone());
    }
}

fn canonicalize_policy(policy: &mut PolicySection) {
    for value in policy.extra.values_mut() {
        *value = canonicalize_yaml_value(value.clone());
    }

    for override_rule in &mut policy.overrides {
        canonicalize_policy_override(override_rule);
    }
}

fn canonicalize_policy_override(override_rule: &mut PolicyOverride) {
    for value in override_rule.extra.values_mut() {
        *value = canonicalize_yaml_value(value.clone());
    }
}

fn canonicalize_state(state: &mut StateSection) {
    for value in state.extra.values_mut() {
        *value = canonicalize_yaml_value(value.clone());
    }
}

fn is_inline_secret_field(field: &str) -> bool {
    let normalized = normalize_secret_field(field);

    matches!(
        normalized.as_str(),
        "value"
            | "secret"
            | "token"
            | "password"
            | "apikey"
            | "clientsecret"
            | "accesstoken"
            | "refreshtoken"
    )
}

fn normalize_secret_field(field: &str) -> String {
    field
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(|ch| ch.to_lowercase())
        .collect()
}

fn find_secret_like_field(
    field: &str,
    value: &Value,
    path: &str,
) -> Result<Option<String>, String> {
    if is_inline_secret_field(field) {
        return Ok(Some(path.to_string()));
    }

    find_secret_like_field_in_value(value, path)
}

fn find_secret_like_field_in_value(value: &Value, path: &str) -> Result<Option<String>, String> {
    match value {
        Value::Sequence(items) => {
            items
                .iter()
                .enumerate()
                .try_fold(None, |found, (index, item)| {
                    if found.is_some() {
                        return Ok(found);
                    }

                    let item_path = format!("{path}[{index}]");
                    find_secret_like_field_in_value(item, &item_path)
                })
        }
        Value::Mapping(map) => map.iter().try_fold(None, |found, (key, value)| {
            if found.is_some() {
                return Ok(found);
            }

            let key_name = yaml_key_name(key).ok_or_else(|| format!("{path}.<complex-key>"))?;
            let key_path = format!("{path}.{key_name}");

            if is_inline_secret_field(&key_name) {
                return Ok(Some(key_path));
            }

            find_secret_like_field_in_value(value, &key_path)
        }),
        Value::Tagged(tagged) => find_secret_like_field_in_value(&tagged.value, path),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => Ok(None),
    }
}

fn yaml_key_name(key: &Value) -> Option<String> {
    match key {
        Value::String(string) => Some(string.clone()),
        Value::Tagged(tagged) => match &tagged.value {
            Value::String(string) => Some(string.clone()),
            _ => None,
        },
        _ => None,
    }
}

fn canonicalize_yaml_value(value: Value) -> Value {
    match value {
        Value::Sequence(items) => Value::Sequence(
            items
                .into_iter()
                .map(canonicalize_yaml_value)
                .collect::<Vec<_>>(),
        ),
        Value::Mapping(map) => {
            let mut entries = map
                .into_iter()
                .map(|(key, value)| {
                    let canonical_key = canonicalize_yaml_value(key);
                    let canonical_value = canonicalize_yaml_value(value);
                    (canonical_key, canonical_value)
                })
                .collect::<Vec<_>>();
            entries.sort_by(|(left_key, _), (right_key, _)| {
                canonical_yaml_sort_key(left_key).cmp(&canonical_yaml_sort_key(right_key))
            });

            let mut canonical = Mapping::new();
            for (key, value) in entries {
                canonical.insert(key, value);
            }

            Value::Mapping(canonical)
        }
        Value::Tagged(tagged) => Value::Tagged(Box::new(serde_yaml::value::TaggedValue {
            tag: tagged.tag,
            value: canonicalize_yaml_value(tagged.value),
        })),
        other => other,
    }
}

fn canonical_yaml_sort_key(value: &Value) -> String {
    match value {
        Value::Null => "n:null".to_string(),
        Value::Bool(boolean) => format!("b:{boolean}"),
        Value::Number(number) => format!("d:{number}"),
        Value::String(string) => format!("s:{string}"),
        Value::Sequence(items) => {
            let mut rendered = String::from("q:[");
            for item in items {
                rendered.push_str(&canonical_yaml_sort_key(item));
                rendered.push(',');
            }
            rendered.push(']');
            rendered
        }
        Value::Mapping(map) => {
            let mut rendered = String::from("m:{");
            for (key, value) in map {
                rendered.push_str(&canonical_yaml_sort_key(key));
                rendered.push('=');
                rendered.push_str(&canonical_yaml_sort_key(value));
                rendered.push(',');
            }
            rendered.push('}');
            rendered
        }
        Value::Tagged(tagged) => {
            format!(
                "t:{}:{}",
                tagged.tag,
                canonical_yaml_sort_key(&tagged.value)
            )
        }
    }
}
