"""
Property-based tests for audit model masking and JSONL serialization.

These tests verify:
- Credential masking consistency
- Sensitive query parameter masking
- JSONL format validity (round-trip)
"""

import json
from datetime import datetime, timezone

import pytest
from hypothesis import given, settings, strategies as st

from registry.audit.models import (
    SENSITIVE_QUERY_PARAMS,
    Action,
    Authorization,
    Identity,
    RegistryApiAccessRecord,
    Request,
    Response,
    mask_credential,
)


class TestCredentialMaskingProperty:
    """Tests for credential masking consistency."""

    @given(st.text(min_size=0, max_size=6))
    @settings(max_examples=100)
    def test_short_credentials_masked_completely(self, credential: str):
        """Short credentials (<=6 chars) return '***'."""
        result = mask_credential(credential)
        assert result == "***"

    @given(st.text(min_size=7, max_size=1000))
    @settings(max_examples=100)
    def test_long_credentials_show_last_six(self, credential: str):
        """Long credentials return '***' + last 6 characters."""
        result = mask_credential(credential)
        expected = "***" + credential[-6:]
        assert result == expected

    @given(st.text(min_size=0, max_size=1000))
    @settings(max_examples=100)
    def test_masking_never_reveals_more_than_six_chars(self, credential: str):
        """Masked output never reveals more than 6 characters."""
        result = mask_credential(credential)
        assert result.startswith("***")
        revealed = result[3:]
        assert len(revealed) <= 6

    def test_empty_string_masked(self):
        """Empty strings are masked to '***'."""
        assert mask_credential("") == "***"

    def test_none_value_masked(self):
        """None values are masked to '***'."""
        assert mask_credential(None) == "***"


class TestSensitiveQueryParamMaskingProperty:
    """Tests for sensitive query parameter masking."""

    @given(
        st.dictionaries(
            keys=st.sampled_from(list(SENSITIVE_QUERY_PARAMS)),
            values=st.text(min_size=1, max_size=100),
            min_size=1,
            max_size=5,
        )
    )
    @settings(max_examples=100)
    def test_all_sensitive_params_are_masked(self, sensitive_params: dict):
        """All query parameters with sensitive keys have their values masked."""
        request = Request(
            method="GET",
            path="/api/test",
            query_params=sensitive_params,
            client_ip="127.0.0.1",
        )
        for key, original_value in sensitive_params.items():
            masked_value = request.query_params[key]
            expected_masked = mask_credential(str(original_value))
            assert masked_value == expected_masked

    @given(
        st.dictionaries(
            keys=st.text(min_size=1, max_size=20).filter(
                lambda k: k.lower() not in SENSITIVE_QUERY_PARAMS
            ),
            values=st.text(min_size=1, max_size=100),
            min_size=1,
            max_size=5,
        )
    )
    @settings(max_examples=100)
    def test_non_sensitive_params_unchanged(self, non_sensitive_params: dict):
        """Query parameters with non-sensitive keys are not masked."""
        request = Request(
            method="GET",
            path="/api/test",
            query_params=non_sensitive_params,
            client_ip="127.0.0.1",
        )
        for key, original_value in non_sensitive_params.items():
            assert request.query_params[key] == original_value

    @given(
        st.fixed_dictionaries({
            "token": st.text(min_size=10, max_size=50),
            "page": st.integers(min_value=1, max_value=100),
            "limit": st.integers(min_value=1, max_value=100),
        })
    )
    @settings(max_examples=100)
    def test_mixed_params_selective_masking(self, mixed_params: dict):
        """Only sensitive params are masked in mixed dictionaries."""
        request = Request(
            method="GET",
            path="/api/test",
            query_params=mixed_params,
            client_ip="127.0.0.1",
        )
        assert request.query_params["token"] == mask_credential(str(mixed_params["token"]))
        assert request.query_params["page"] == mixed_params["page"]
        assert request.query_params["limit"] == mixed_params["limit"]

    def test_case_insensitive_sensitive_detection(self):
        """Sensitive key detection is case-insensitive."""
        params = {
            "TOKEN": "secret123456789",
            "Password": "mypassword123",
            "API_KEY": "key123456789abc",
        }
        request = Request(
            method="GET",
            path="/api/test",
            query_params=params,
            client_ip="127.0.0.1",
        )
        assert request.query_params["TOKEN"] == "***456789"
        assert request.query_params["Password"] == "***ord123"
        assert request.query_params["API_KEY"] == "***789abc"


# Strategies for generating valid audit record components
identity_strategy = st.builds(
    Identity,
    username=st.text(min_size=1, max_size=50).filter(lambda x: x.strip()),
    auth_method=st.sampled_from(["oauth2", "traditional", "jwt_bearer", "anonymous"]),
    provider=st.one_of(st.none(), st.sampled_from(["cognito", "entra_id", "keycloak"])),
    groups=st.lists(st.text(min_size=1, max_size=20), max_size=5),
    scopes=st.lists(st.text(min_size=1, max_size=30), max_size=5),
    is_admin=st.booleans(),
    credential_type=st.sampled_from(["session_cookie", "bearer_token", "none"]),
    credential_hint=st.one_of(st.none(), st.text(min_size=1, max_size=100)),
)

request_strategy = st.builds(
    Request,
    method=st.sampled_from(["GET", "POST", "PUT", "DELETE", "PATCH"]),
    path=st.text(min_size=1, max_size=200).map(lambda x: "/" + x.lstrip("/")),
    query_params=st.dictionaries(
        keys=st.text(min_size=1, max_size=20).filter(lambda x: x.strip()),
        values=st.one_of(st.text(max_size=50), st.integers()),
        max_size=5,
    ),
    client_ip=st.ip_addresses().map(str),
    forwarded_for=st.one_of(st.none(), st.ip_addresses().map(str)),
    user_agent=st.one_of(st.none(), st.text(min_size=1, max_size=100)),
    content_length=st.one_of(st.none(), st.integers(min_value=0, max_value=10000000)),
)

response_strategy = st.builds(
    Response,
    status_code=st.integers(min_value=100, max_value=599),
    duration_ms=st.floats(min_value=0.0, max_value=60000.0, allow_nan=False, allow_infinity=False),
    content_length=st.one_of(st.none(), st.integers(min_value=0, max_value=10000000)),
)

action_strategy = st.one_of(
    st.none(),
    st.builds(
        Action,
        operation=st.sampled_from([
            "create", "read", "update", "delete", "list", "toggle", "rate", "login", "logout", "search"
        ]),
        resource_type=st.sampled_from(["server", "agent", "auth", "federation", "health", "search"]),
        resource_id=st.one_of(st.none(), st.text(min_size=1, max_size=50)),
        description=st.one_of(st.none(), st.text(min_size=1, max_size=200)),
    ),
)

authorization_strategy = st.one_of(
    st.none(),
    st.builds(
        Authorization,
        decision=st.sampled_from(["ALLOW", "DENY", "NOT_REQUIRED"]),
        required_permission=st.one_of(st.none(), st.text(min_size=1, max_size=50)),
        evaluated_scopes=st.lists(st.text(min_size=1, max_size=30), max_size=5),
    ),
)

audit_record_strategy = st.builds(
    RegistryApiAccessRecord,
    timestamp=st.datetimes(
        min_value=datetime(2020, 1, 1),
        max_value=datetime(2030, 12, 31),
        timezones=st.just(timezone.utc),
    ),
    request_id=st.uuids().map(str),
    correlation_id=st.one_of(st.none(), st.uuids().map(str)),
    identity=identity_strategy,
    request=request_strategy,
    response=response_strategy,
    action=action_strategy,
    authorization=authorization_strategy,
)


class TestJSONLFormatValidityProperty:
    """Tests for JSONL format validity."""

    @given(audit_record_strategy)
    @settings(max_examples=100)
    def test_audit_record_serializes_to_valid_json(self, record: RegistryApiAccessRecord):
        """Any audit record serializes to valid JSON."""
        json_str = record.model_dump_json()
        parsed = json.loads(json_str)
        assert isinstance(parsed, dict)

    @given(audit_record_strategy)
    @settings(max_examples=100)
    def test_audit_record_round_trip(self, record: RegistryApiAccessRecord):
        """Serializing and deserializing produces an equivalent object."""
        json_str = record.model_dump_json()
        parsed_dict = json.loads(json_str)
        reconstructed = RegistryApiAccessRecord.model_validate(parsed_dict)
        assert reconstructed.request_id == record.request_id
        assert reconstructed.log_type == record.log_type
        assert reconstructed.version == record.version
        assert reconstructed.identity.username == record.identity.username
        assert reconstructed.identity.auth_method == record.identity.auth_method
        assert reconstructed.identity.is_admin == record.identity.is_admin
        assert reconstructed.request.method == record.request.method
        assert reconstructed.request.path == record.request.path
        assert reconstructed.request.client_ip == record.request.client_ip
        assert reconstructed.response.status_code == record.response.status_code

    @given(audit_record_strategy)
    @settings(max_examples=100)
    def test_jsonl_single_line_format(self, record: RegistryApiAccessRecord):
        """Serialized audit records are single-line JSON."""
        json_str = record.model_dump_json()
        assert "\n" not in json_str
        assert "\r" not in json_str

    @given(st.lists(audit_record_strategy, min_size=1, max_size=10))
    @settings(max_examples=50)
    def test_multiple_records_form_valid_jsonl(self, records: list):
        """Multiple audit records form valid JSONL when joined with newlines."""
        jsonl_content = "\n".join(r.model_dump_json() for r in records)
        lines = jsonl_content.strip().split("\n")
        assert len(lines) == len(records)
        for i, line in enumerate(lines):
            parsed = json.loads(line)
            assert parsed["request_id"] == records[i].request_id


class TestIdentityCredentialHintMasking:
    """Tests for Identity model credential_hint masking."""

    @given(st.text(min_size=10, max_size=200))
    @settings(max_examples=100)
    def test_identity_credential_hint_masked_on_creation(self, raw_credential: str):
        """credential_hint is automatically masked by the validator."""
        identity = Identity(
            username="testuser",
            auth_method="oauth2",
            credential_type="bearer_token",
            credential_hint=raw_credential,
        )
        expected_masked = mask_credential(raw_credential)
        assert identity.credential_hint == expected_masked

    def test_identity_none_credential_hint_unchanged(self):
        """None credential_hint remains None."""
        identity = Identity(
            username="testuser",
            auth_method="anonymous",
            credential_type="none",
            credential_hint=None,
        )
        assert identity.credential_hint is None
