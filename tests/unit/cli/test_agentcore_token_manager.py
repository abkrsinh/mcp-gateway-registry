"""Unit tests for cli.agentcore.token_manager — TokenManager.

Tests token generation for OAuth2 (CUSTOM_JWT) gateways, token file
verification, refresh setup verification, and negative cases for IAM
and NONE gateways.
"""

from __future__ import annotations

import os
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from cli.agentcore.token_manager import TokenManager


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SAMPLE_GATEWAY_ARN = "arn:aws:bedrock:us-east-1:111122223333:gateway/gw-123"
SAMPLE_GATEWAY_ARN_2 = "arn:aws:bedrock:us-east-1:111122223333:gateway/gw-456"
SAMPLE_GATEWAY_ARN_3 = "arn:aws:bedrock:us-east-1:111122223333:gateway/gw-789"


def _make_gateway_config(arn: str, server_name: str = "my-gateway") -> dict:
    """Create a minimal gateway config dict."""
    return {"gateway_arn": arn, "server_name": server_name}


@pytest.fixture()
def mock_generate_access_token():
    """Install a fake agentcore_auth package in sys.modules and return the mock function."""
    mock_fn = MagicMock()

    # Create fake module hierarchy: agentcore_auth.generate_access_token
    agentcore_auth = types.ModuleType("agentcore_auth")
    gen_mod = types.ModuleType("agentcore_auth.generate_access_token")
    gen_mod.generate_access_token = mock_fn
    agentcore_auth.generate_access_token = gen_mod

    saved = {
        k: sys.modules.get(k)
        for k in ("agentcore_auth", "agentcore_auth.generate_access_token")
    }
    sys.modules["agentcore_auth"] = agentcore_auth
    sys.modules["agentcore_auth.generate_access_token"] = gen_mod

    yield mock_fn

    # Restore original state
    for k, v in saved.items():
        if v is None:
            sys.modules.pop(k, None)
        else:
            sys.modules[k] = v


# ---------------------------------------------------------------------------
# Task 6.1 — Token generation for OAuth2 (CUSTOM_JWT) gateways
# ---------------------------------------------------------------------------


class TestTokenGenerationCustomJWT:
    """Validates: Requirements 13.1 — token generation for CUSTOM_JWT gateways."""

    def test_generate_tokens_calls_generate_access_token(self, mock_generate_access_token):
        """Token generation calls generate_access_token with correct index."""
        tm = TokenManager(oauth_domain="https://auth.example.com")
        configs = [_make_gateway_config(SAMPLE_GATEWAY_ARN, "svc-one")]
        arn_to_index = {SAMPLE_GATEWAY_ARN: 1}

        result = tm.generate_tokens_for_gateways(configs, arn_to_index)

        mock_generate_access_token.assert_called_once_with(
            gateway_index=1, oauth_tokens_dir=".oauth-tokens"
        )
        assert SAMPLE_GATEWAY_ARN in result
        assert "svc-one" in result[SAMPLE_GATEWAY_ARN]

    def test_generate_tokens_returns_expected_paths(self, mock_generate_access_token):
        """Returned dict maps ARN → expected token file path."""
        tm = TokenManager()
        configs = [_make_gateway_config(SAMPLE_GATEWAY_ARN, "customer-support")]
        arn_to_index = {SAMPLE_GATEWAY_ARN: 2}

        result = tm.generate_tokens_for_gateways(configs, arn_to_index)

        expected = ".oauth-tokens/bedrock-agentcore-customer-support-egress.json"
        assert result[SAMPLE_GATEWAY_ARN] == expected

    def test_generate_tokens_multiple_gateways(self, mock_generate_access_token):
        """Multiple CUSTOM_JWT gateways each get a token generated."""
        tm = TokenManager()
        configs = [
            _make_gateway_config(SAMPLE_GATEWAY_ARN, "svc-a"),
            _make_gateway_config(SAMPLE_GATEWAY_ARN_2, "svc-b"),
        ]
        arn_to_index = {SAMPLE_GATEWAY_ARN: 1, SAMPLE_GATEWAY_ARN_2: 2}

        result = tm.generate_tokens_for_gateways(configs, arn_to_index)

        assert mock_generate_access_token.call_count == 2
        assert len(result) == 2

    def test_generate_tokens_error_handling(self, mock_generate_access_token):
        """Failed token generation logs error and skips that gateway."""
        mock_generate_access_token.side_effect = Exception("auth server unreachable")
        tm = TokenManager()
        configs = [_make_gateway_config(SAMPLE_GATEWAY_ARN, "svc-fail")]
        arn_to_index = {SAMPLE_GATEWAY_ARN: 1}

        result = tm.generate_tokens_for_gateways(configs, arn_to_index)

        assert SAMPLE_GATEWAY_ARN not in result
        assert len(result) == 0

    def test_generate_tokens_skips_gateway_without_index(self, mock_generate_access_token):
        """Gateways not in arn_to_index are skipped."""
        tm = TokenManager()
        configs = [_make_gateway_config(SAMPLE_GATEWAY_ARN, "svc-x")]
        arn_to_index = {}  # no mapping

        result = tm.generate_tokens_for_gateways(configs, arn_to_index)

        mock_generate_access_token.assert_not_called()
        assert len(result) == 0


# ---------------------------------------------------------------------------
# Task 6.1 (continued) — verify_token_files
# ---------------------------------------------------------------------------


class TestVerifyTokenFiles:
    """Validates: Requirements 13.2 — token file verification."""

    def test_existing_files_return_empty_missing(self, tmp_path):
        """When all expected token files exist, missing list is empty."""
        tokens_dir = tmp_path / ".oauth-tokens"
        tokens_dir.mkdir()
        (tokens_dir / "bedrock-agentcore-svc-a-egress.json").write_text("{}")
        (tokens_dir / "bedrock-agentcore-svc-b-egress.json").write_text("{}")

        tm = TokenManager()
        missing = tm.verify_token_files(
            ["svc-a", "svc-b"], tokens_dir=str(tokens_dir)
        )

        assert missing == []

    def test_missing_files_are_reported(self, tmp_path):
        """Missing token files are returned in the missing list."""
        tokens_dir = tmp_path / ".oauth-tokens"
        tokens_dir.mkdir()
        # Only create one of two expected files
        (tokens_dir / "bedrock-agentcore-svc-a-egress.json").write_text("{}")

        tm = TokenManager()
        missing = tm.verify_token_files(
            ["svc-a", "svc-b"], tokens_dir=str(tokens_dir)
        )

        assert len(missing) == 1
        assert "svc-b" in missing[0]

    def test_all_missing_when_dir_empty(self, tmp_path):
        """All files reported missing when tokens dir is empty."""
        tokens_dir = tmp_path / ".oauth-tokens"
        tokens_dir.mkdir()

        tm = TokenManager()
        missing = tm.verify_token_files(
            ["svc-a", "svc-b"], tokens_dir=str(tokens_dir)
        )

        assert len(missing) == 2


# ---------------------------------------------------------------------------
# Task 6.2 — Token refresh — verify_refresh_setup reads .env
# ---------------------------------------------------------------------------


class TestVerifyRefreshSetup:
    """Validates: Requirements 13.3 — token_refresher.py reads credentials from .env."""

    def test_env_with_oauth_client_id_returns_true(self, tmp_path):
        """verify_refresh_setup returns True when .env has OAUTH_CLIENT_ID_ entries."""
        env_file = tmp_path / ".env"
        env_file.write_text(
            "OAUTH_CLIENT_ID_1=my-client-id\n"
            "OAUTH_CLIENT_SECRET_1=my-secret\n"
        )

        tm = TokenManager()
        assert tm.verify_refresh_setup(env_file=str(env_file)) is True

    def test_env_with_legacy_agentcore_client_id_returns_true(self, tmp_path):
        """verify_refresh_setup returns True with legacy AGENTCORE_CLIENT_ID_ entries."""
        env_file = tmp_path / ".env"
        env_file.write_text(
            "AGENTCORE_CLIENT_ID_1=legacy-id\n"
            "AGENTCORE_CLIENT_SECRET_1=legacy-secret\n"
        )

        tm = TokenManager()
        assert tm.verify_refresh_setup(env_file=str(env_file)) is True

    def test_empty_env_returns_false(self, tmp_path):
        """verify_refresh_setup returns False when .env is empty."""
        env_file = tmp_path / ".env"
        env_file.write_text("")

        tm = TokenManager()
        assert tm.verify_refresh_setup(env_file=str(env_file)) is False

    def test_missing_env_returns_false(self, tmp_path):
        """verify_refresh_setup returns False when .env does not exist."""
        env_file = tmp_path / ".env"  # not created

        tm = TokenManager()
        assert tm.verify_refresh_setup(env_file=str(env_file)) is False

    def test_env_without_credential_entries_returns_false(self, tmp_path):
        """verify_refresh_setup returns False when .env has no credential entries."""
        env_file = tmp_path / ".env"
        env_file.write_text("SOME_OTHER_VAR=value\nANOTHER_VAR=123\n")

        tm = TokenManager()
        assert tm.verify_refresh_setup(env_file=str(env_file)) is False


# ---------------------------------------------------------------------------
# Task 6.3 — IAM gateways do NOT trigger token generation
# ---------------------------------------------------------------------------


class TestIAMGatewaysSkipTokenGeneration:
    """Validates: Requirements 13.1 (negative case) — IAM gateways skip token gen."""

    def test_iam_gateway_not_in_arn_to_index_skips_generation(self, mock_generate_access_token):
        """IAM gateways should NOT have entries in arn_to_index, so they are skipped."""
        tm = TokenManager()
        # IAM gateway is in configs but NOT in arn_to_index (no OAuth2 creds)
        iam_config = _make_gateway_config(SAMPLE_GATEWAY_ARN, "iam-gateway")
        configs = [iam_config]
        arn_to_index = {}  # IAM gateways have no credential index

        result = tm.generate_tokens_for_gateways(configs, arn_to_index)

        mock_generate_access_token.assert_not_called()
        assert len(result) == 0

    def test_mixed_iam_and_custom_jwt_only_generates_for_custom_jwt(self, mock_generate_access_token):
        """When both IAM and CUSTOM_JWT gateways exist, only CUSTOM_JWT gets tokens."""
        tm = TokenManager()
        configs = [
            _make_gateway_config(SAMPLE_GATEWAY_ARN, "oauth-gw"),
            _make_gateway_config(SAMPLE_GATEWAY_ARN_2, "iam-gw"),
        ]
        # Only the CUSTOM_JWT gateway has an index
        arn_to_index = {SAMPLE_GATEWAY_ARN: 1}

        result = tm.generate_tokens_for_gateways(configs, arn_to_index)

        mock_generate_access_token.assert_called_once_with(
            gateway_index=1, oauth_tokens_dir=".oauth-tokens"
        )
        assert SAMPLE_GATEWAY_ARN in result
        assert SAMPLE_GATEWAY_ARN_2 not in result


# ---------------------------------------------------------------------------
# Task 6.4 — NONE gateways skip credential collection and token generation
# ---------------------------------------------------------------------------


class TestNoneGatewaysSkipTokenGeneration:
    """Validates: Requirements 11.7, 13.1 (negative case) — NONE gateways skip entirely."""

    def test_none_gateway_not_in_arn_to_index_skips_generation(self, mock_generate_access_token):
        """NONE gateways should NOT have entries in arn_to_index, so they are skipped."""
        tm = TokenManager()
        none_config = _make_gateway_config(SAMPLE_GATEWAY_ARN, "none-gateway")
        configs = [none_config]
        arn_to_index = {}  # NONE gateways have no credential index

        result = tm.generate_tokens_for_gateways(configs, arn_to_index)

        mock_generate_access_token.assert_not_called()
        assert len(result) == 0

    def test_mixed_none_iam_custom_jwt_only_generates_for_custom_jwt(self, mock_generate_access_token):
        """With NONE, IAM, and CUSTOM_JWT gateways, only CUSTOM_JWT gets tokens."""
        tm = TokenManager()
        configs = [
            _make_gateway_config(SAMPLE_GATEWAY_ARN, "oauth-gw"),
            _make_gateway_config(SAMPLE_GATEWAY_ARN_2, "iam-gw"),
            _make_gateway_config(SAMPLE_GATEWAY_ARN_3, "none-gw"),
        ]
        # Only the CUSTOM_JWT gateway has an index
        arn_to_index = {SAMPLE_GATEWAY_ARN: 1}

        result = tm.generate_tokens_for_gateways(configs, arn_to_index)

        mock_generate_access_token.assert_called_once()
        assert len(result) == 1
        assert SAMPLE_GATEWAY_ARN in result
        assert SAMPLE_GATEWAY_ARN_2 not in result
        assert SAMPLE_GATEWAY_ARN_3 not in result

    def test_all_none_gateways_produce_empty_result(self, mock_generate_access_token):
        """When all gateways are NONE type, no tokens are generated at all."""
        tm = TokenManager()
        configs = [
            _make_gateway_config(SAMPLE_GATEWAY_ARN, "none-a"),
            _make_gateway_config(SAMPLE_GATEWAY_ARN_2, "none-b"),
        ]
        arn_to_index = {}  # No NONE gateways have credential indices

        result = tm.generate_tokens_for_gateways(configs, arn_to_index)

        mock_generate_access_token.assert_not_called()
        assert result == {}


# ---------------------------------------------------------------------------
# TokenManager __init__ configuration
# ---------------------------------------------------------------------------


class TestTokenManagerInit:
    """Test TokenManager initialization and env var configuration."""

    def test_default_timeout(self):
        """Default timeout is 30 seconds."""
        tm = TokenManager()
        assert tm.timeout == 30

    def test_custom_timeout(self):
        """Custom timeout is respected."""
        tm = TokenManager(timeout=60)
        assert tm.timeout == 60

    @patch.dict(os.environ, {"TOKEN_GENERATION_TIMEOUT": "45"})
    def test_timeout_from_env_var(self):
        """TOKEN_GENERATION_TIMEOUT env var overrides default."""
        tm = TokenManager()
        assert tm.timeout == 45

    def test_oauth_domain_from_param(self):
        """oauth_domain parameter is stored."""
        tm = TokenManager(oauth_domain="https://auth.example.com")
        assert tm.oauth_domain == "https://auth.example.com"

    @patch.dict(os.environ, {"OAUTH_DOMAIN": "https://env.example.com"})
    def test_oauth_domain_from_env_var(self):
        """OAUTH_DOMAIN env var is used when no param provided."""
        tm = TokenManager()
        assert tm.oauth_domain == "https://env.example.com"
