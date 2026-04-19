use agentenv_proto::{CredentialKind, CredentialRequirement, ValidatorSpec};

#[test]
fn credential_requirement_round_trips_kind_and_validator() {
    let requirement = CredentialRequirement {
        name: "OPENAI_API_KEY".to_owned(),
        kind: CredentialKind::ApiKey,
        required: true,
        description: "Used for inference tests".to_owned(),
        validator: Some(ValidatorSpec::Regex {
            pattern: "^sk-".to_owned(),
        }),
    };

    let json = serde_json::to_value(&requirement).expect("serialize credential requirement");
    assert_eq!(json["kind"], "api_key");
    assert_eq!(json["validator"]["kind"], "regex");
    assert_eq!(json["validator"]["pattern"], "^sk-");

    let round_trip: CredentialRequirement =
        serde_json::from_value(json).expect("deserialize credential requirement");
    assert_eq!(round_trip, requirement);
}
