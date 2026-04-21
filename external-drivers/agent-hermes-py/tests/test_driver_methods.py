from agentenv_agent_hermes.protocol import (
    ERROR_SCHEMA_VERSION_INCOMPATIBLE,
    SCHEMA_VERSION,
    assert_schema_compatible,
)


def test_schema_version_accepts_matching_major_versions():
    assert_schema_compatible(SCHEMA_VERSION)
    assert_schema_compatible("1.9")


def test_schema_version_rejects_mismatched_major_versions():
    try:
        assert_schema_compatible("2.0")
    except ValueError as exc:
        assert "major schema versions match" in str(exc)
    else:
        raise AssertionError("schema mismatch should fail")


def test_protocol_error_codes_match_agentenv_proto():
    assert ERROR_SCHEMA_VERSION_INCOMPATIBLE == -32002
