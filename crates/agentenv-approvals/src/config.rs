use std::collections::BTreeMap;
use std::path::Path;

use serde::{de, Deserialize, Deserializer};

use crate::model::ApprovalKind;

#[derive(Debug, thiserror::Error)]
pub enum ApprovalConfigError {
    #[error("approval config IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("approval config YAML error: {0}")]
    Yaml(#[from] serde_yaml::Error),
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ApprovalConfig {
    #[serde(default)]
    pub approvals: ApprovalConfigBody,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ApprovalConfigBody {
    #[serde(default)]
    pub webhooks: Vec<WebhookTargetConfig>,
    #[serde(default)]
    pub slack: Option<SlackConfig>,
    #[serde(default, deserialize_with = "deserialize_auto_deny_after")]
    pub auto_deny_after: BTreeMap<ApprovalKind, humantime::Duration>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct WebhookTargetConfig {
    pub url: String,
    #[serde(default)]
    pub secret: Option<String>,
    #[serde(default)]
    pub secret_ref: Option<String>,
    #[serde(default)]
    pub kinds: Vec<ApprovalKind>,
    #[serde(default)]
    pub callback_url: Option<String>,
    #[serde(default)]
    pub max_attempts: Option<u32>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct SlackConfig {
    pub webhook_url: String,
    #[serde(default)]
    pub channel: Option<String>,
    #[serde(default)]
    pub signing_secret: Option<String>,
    #[serde(default)]
    pub callback_url: Option<String>,
}

impl ApprovalConfig {
    pub fn load(path: &Path) -> Result<Self, ApprovalConfigError> {
        match std::fs::read_to_string(path) {
            Ok(contents) => Ok(serde_yaml::from_str(&contents)?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(error.into()),
        }
    }
}

fn deserialize_auto_deny_after<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<ApprovalKind, humantime::Duration>, D::Error>
where
    D: Deserializer<'de>,
{
    let raw = BTreeMap::<ApprovalKind, String>::deserialize(deserializer)?;
    raw.into_iter()
        .map(|(kind, value)| {
            humantime::parse_duration(&value)
                .map(humantime::Duration::from)
                .map(|duration| (kind, duration))
                .map_err(de::Error::custom)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn missing_config_loads_default() {
        let temp = tempfile::tempdir().unwrap();
        let config = ApprovalConfig::load(&temp.path().join("missing.yaml")).unwrap();

        assert!(config.approvals.webhooks.is_empty());
        assert!(config.approvals.slack.is_none());
        assert!(config.approvals.auto_deny_after.is_empty());
    }

    #[test]
    fn parses_webhooks_slack_and_auto_deny_timeouts() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("config.yaml");
        std::fs::write(
            &path,
            r##"
approvals:
  webhooks:
    - url: https://approvals.company.com/agentenv
      secret: ${WEBHOOK_SECRET}
      kinds: [egress_host, zone_access]
  slack:
    webhook_url: https://hooks.slack.com/services/test
    channel: "#agentenv-approvals"
    signing_secret: ${SLACK_SIGNING_SECRET}
    callback_url: https://approvals.example.com/slack/interactions
  auto_deny_after:
    egress_host: 30s
    package_install: 120s
"##,
        )
        .unwrap();

        let config = ApprovalConfig::load(&path).unwrap();

        assert_eq!(
            config.approvals.webhooks[0].url,
            "https://approvals.company.com/agentenv"
        );
        assert_eq!(
            config.approvals.webhooks[0].secret.as_deref(),
            Some("${WEBHOOK_SECRET}")
        );
        assert_eq!(
            config.approvals.webhooks[0].kinds,
            vec![ApprovalKind::EgressHost, ApprovalKind::ZoneAccess]
        );
        assert_eq!(
            config
                .approvals
                .slack
                .as_ref()
                .unwrap()
                .callback_url
                .as_deref(),
            Some("https://approvals.example.com/slack/interactions")
        );
        assert_eq!(
            config.approvals.auto_deny_after[&ApprovalKind::EgressHost],
            humantime::Duration::from(Duration::from_secs(30))
        );
        assert_eq!(
            config.approvals.auto_deny_after[&ApprovalKind::PackageInstall],
            humantime::Duration::from(Duration::from_secs(120))
        );
    }
}
