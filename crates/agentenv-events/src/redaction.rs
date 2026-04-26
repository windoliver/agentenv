use serde_json::{Map, Value};
use url::Url;

pub fn redact_string(raw: &str) -> String {
    if let Ok(url) = Url::parse(raw) {
        return redact_url(url).to_string();
    }

    if raw.starts_with("//") {
        if let Ok(url) = Url::parse(&format!("https:{raw}")) {
            let redacted = redact_url(url).to_string();
            return redacted
                .strip_prefix("https:")
                .map_or(redacted.clone(), str::to_owned);
        }
    }

    redact_url_like_text(raw)
}

pub fn redact_json_value(value: Value) -> Value {
    match value {
        Value::Object(object) => Value::Object(redact_json_object(object)),
        Value::Array(values) => Value::Array(values.into_iter().map(redact_json_value).collect()),
        Value::String(raw) => Value::String(redact_string(&raw)),
        other => other,
    }
}

fn redact_json_object(object: Map<String, Value>) -> Map<String, Value> {
    object
        .into_iter()
        .map(|(key, value)| {
            let redacted = if is_secret_key(&key) {
                Value::String("[redacted]".to_owned())
            } else {
                redact_json_value(value)
            };
            (key, redacted)
        })
        .collect()
}

fn is_secret_key(key: &str) -> bool {
    let lowercase = key.to_lowercase();
    SECRET_KEY_MARKERS
        .iter()
        .any(|marker| lowercase.contains(marker))
}

fn redact_url(mut url: Url) -> Url {
    if url.set_username("").is_err() {
        // Hostless and non-hierarchical URLs may reject username changes.
    }
    let _ = url.set_password(None);
    url.set_query(None);
    url.set_fragment(None);
    url
}

fn redact_url_like_text(raw: &str) -> String {
    let mut redacted = match raw.find(['?', '#']) {
        Some(index) => raw[..index].to_owned(),
        None => raw.to_owned(),
    };

    let authority_start = if let Some(scheme_end) = redacted.find("://") {
        Some(scheme_end + "://".len())
    } else if redacted.starts_with("//") {
        Some("//".len())
    } else {
        None
    };

    if let Some(authority_start) = authority_start {
        let authority_end = redacted[authority_start..]
            .find('/')
            .map(|index| authority_start + index)
            .unwrap_or(redacted.len());
        if let Some(at_offset) = redacted[authority_start..authority_end].rfind('@') {
            let credential_end = authority_start + at_offset + 1;
            redacted.replace_range(authority_start..credential_end, "");
        }
    }

    redacted
}

const SECRET_KEY_MARKERS: &[&str] = &[
    "token",
    "secret",
    "password",
    "api_key",
    "apikey",
    "authorization",
    "credential",
];

#[cfg(test)]
mod tests {
    use super::{redact_json_value, redact_string};

    #[test]
    fn redacts_url_credentials_query_and_fragment() {
        let redacted = redact_string("https://user:pass@example.test/path?token=secret#frag");
        assert_eq!(redacted, "https://example.test/path");
    }

    #[test]
    fn redacts_secret_like_json_keys() {
        let value = serde_json::json!({
            "token": "sk-value",
            "nested": {"api_key": "very-secret"},
            "safe": "OPENAI_API_KEY"
        });

        let redacted = redact_json_value(value);

        assert_eq!(redacted["token"], serde_json::json!("[redacted]"));
        assert_eq!(
            redacted["nested"]["api_key"],
            serde_json::json!("[redacted]")
        );
        assert_eq!(redacted["safe"], serde_json::json!("OPENAI_API_KEY"));
    }
}
