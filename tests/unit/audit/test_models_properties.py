"""
Property-based tests for audit model masking and JSONL serialization.

Validates: Requirements 2.1, 2.2, 2.3, 2.4, 3.1
"""

import json
from datetime import datetime, timezone

from hypothesis import given, settings, strategies as st

from registry.audit.models import (
    SENSITIVE_QUERY_PARAMS,
    Identity,
    RegistryApiAccessRecord,
    Request,
    Response,
    mask_credential,
)


class TestCredentialMasking:
    """Property 3: Credential masking consistency."""

    @given(st.text(min_size=0, max_size=6))
    @settings(max_examples=50)
    def test_short_credentials_masked_completely(self, credential: str):
        """Short credentials (<=6 chars) return '***'."""
        assert mask_credential(credential) == "***"

    @given(st.text(min_size=7, max_size=100))
    @settings(max_examples=50)
    def test_long_credentials_show_last_six(self, credential: str):
        """Long credentials return '***' + last 6 characters."""
        result = mask_credential(credential)
        assert result == "***" + credential[-6:]
        assert len(result[3:]) <= 6


class TestSensitiveQueryParamMasking:
    """Property 4: Sensitive query parameter masking."""

    @given(
        st.dictionaries(
            keys=st.sampled_from(list(SENSITIVE_QUERY_PARAMS)),
            values=st.text(min_size=1, max_size=50),
            min_size=1,
            max_size=3,
        )
    )
    @settings(max_examples=50)
    def test_sensitive_params_are_masked(self, sensitive_params: dict):
        """Query parameters with sensitive keys have their values masked."""
        request = Request(
            method="GET",
            path="/api/test",
            query_params=sensitive_params,
            client_ip="127.0.0.1",
        )
        for key, original_value in sensitive_params.items():
            assert request.query_params[key] == mask_credential(str(original_value))


class TestJSONLFormatValidity:
    """Property 5: JSONL format validity."""

    @given(
        st.builds(
            RegistryApiAccessRecord,
            timestamp=st.datetimes(timezones=st.just(timezone.utc)),
            request_id=st.uuids().map(str),
            identity=st.builds(
                Identity,
                username=st.text(min_size=1, max_size=20).filter(lambda x: x.strip()),
                auth_method=st.sampled_from(["oauth2", "anonymous"]),
                credential_type=st.sampled_from(["bearer_token", "none"]),
            ),
            request=st.builds(
                Request,
                method=st.sampled_from(["GET", "POST"]),
                path=st.just("/api/test"),
                client_ip=st.just("127.0.0.1"),
            ),
            response=st.builds(
                Response,
                status_code=st.integers(min_value=200, max_value=500),
                duration_ms=st.floats(min_value=0.0, max_value=1000.0, allow_nan=False),
            ),
        )
    )
    @settings(max_examples=50)
    def test_audit_record_round_trip(self, record: RegistryApiAccessRecord):
        """Serializing and deserializing produces an equivalent object."""
        json_str = record.model_dump_json()
        assert "\n" not in json_str  # Single line
        parsed = json.loads(json_str)
        reconstructed = RegistryApiAccessRecord.model_validate(parsed)
        assert reconstructed.request_id == record.request_id
