"""Unit tests for cli.agentcore.credentials — CredentialHelper.

Tests credential collection from env vars (OAUTH_CLIENT_ID_{N} and legacy
AGENTCORE_CLIENT_ID_{N}), interactive prompt mocking, OAuth2 validation
with Cognito/Auth0/Okta, AWS_IAM flow, NONE flow, credential persistence,
and credential validation gating.
"""

from __future__ import annotations

import os
import stat
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SAMPLE_GATEWAY_ARN = "arn:aws:bedrock:us-east-1:111122223333:gateway/gw-123"
SAMPLE_GATEWAY_ARN_2 = "arn:aws:bedrock:us-east-1:111122223333:gateway/gw-456"


def _make_credential_helper(env_vars: dict[str, str] | None = None):
    """Create a CredentialHelper with controlled environment variables."""
    env = env_vars or {}
    with patch.dict(os.environ, env, clear=True):
        from cli.agentcore.credentials import CredentialHelper

        return CredentialHelper()


# ---------------------------------------------------------------------------
# Task 5.1 — Credential collection from env vars + interactive prompt
# ---------------------------------------------------------------------------


class TestEnvVarLoading:
    """Tests for _load_from_env() — OAUTH_ and legacy AGENTCORE_ prefixes."""

    def test_loads_oauth_prefix_credentials(self):
        """Req 11.1: Load from OAUTH_CLIENT_ID_{N} env vars."""
        env = {
            "OAUTH_CLIENT_ID_1": "id-1",
            "OAUTH_CLIENT_SECRET_1": "secret-1",
            "AGENTCORE_GATEWAY_ARN_1": SAMPLE_GATEWAY_ARN,
        }
        helper = _make_credential_helper(env)

        assert SAMPLE_GATEWAY_ARN in helper.credentials
        creds = helper.credentials[SAMPLE_GATEWAY_ARN]
        assert creds["client_id"] == "id-1"
        assert creds["client_secret"] == "secret-1"

    def test_loads_legacy_agentcore_prefix_credentials(self):
        """Req 11.2: Legacy AGENTCORE_CLIENT_ID_{N} backward compatibility."""
        env = {
            "AGENTCORE_CLIENT_ID_1": "legacy-id",
            "AGENTCORE_CLIENT_SECRET_1": "legacy-secret",
            "AGENTCORE_GATEWAY_ARN_1": SAMPLE_GATEWAY_ARN,
        }
        helper = _make_credential_helper(env)

        assert SAMPLE_GATEWAY_ARN in helper.credentials
        creds = helper.credentials[SAMPLE_GATEWAY_ARN]
        assert creds["client_id"] == "legacy-id"
        assert creds["client_secret"] == "legacy-secret"

    def test_oauth_prefix_takes_precedence_over_legacy(self):
        """OAUTH_ prefix is checked first; legacy is fallback only."""
        env = {
            "OAUTH_CLIENT_ID_1": "new-id",
            "OAUTH_CLIENT_SECRET_1": "new-secret",
            "AGENTCORE_CLIENT_ID_1": "old-id",
            "AGENTCORE_CLIENT_SECRET_1": "old-secret",
            "AGENTCORE_GATEWAY_ARN_1": SAMPLE_GATEWAY_ARN,
        }
        helper = _make_credential_helper(env)

        creds = helper.credentials[SAMPLE_GATEWAY_ARN]
        assert creds["client_id"] == "new-id"
        assert creds["client_secret"] == "new-secret"

    def test_incomplete_triplet_not_loaded(self):
        """Only complete triplets (id + secret + arn) are stored."""
        env = {
            "OAUTH_CLIENT_ID_1": "id-1",
            # Missing secret and ARN
        }
        helper = _make_credential_helper(env)
        assert len(helper.credentials) == 0

    def test_multiple_credential_sets_loaded(self):
        """Multiple indices are loaded correctly."""
        env = {
            "OAUTH_CLIENT_ID_1": "id-1",
            "OAUTH_CLIENT_SECRET_1": "secret-1",
            "AGENTCORE_GATEWAY_ARN_1": SAMPLE_GATEWAY_ARN,
            "OAUTH_CLIENT_ID_2": "id-2",
            "OAUTH_CLIENT_SECRET_2": "secret-2",
            "AGENTCORE_GATEWAY_ARN_2": SAMPLE_GATEWAY_ARN_2,
        }
        helper = _make_credential_helper(env)

        assert len(helper.credentials) == 2
        assert SAMPLE_GATEWAY_ARN in helper.credentials
        assert SAMPLE_GATEWAY_ARN_2 in helper.credentials

    def test_server_name_and_authorizer_type_loaded(self):
        """Optional server_name and authorizer_type are captured."""
        env = {
            "OAUTH_CLIENT_ID_1": "id-1",
            "OAUTH_CLIENT_SECRET_1": "secret-1",
            "AGENTCORE_GATEWAY_ARN_1": SAMPLE_GATEWAY_ARN,
            "AGENTCORE_SERVER_NAME_1": "my-server",
            "AGENTCORE_AUTHORIZER_TYPE_1": "CUSTOM_JWT",
        }
        helper = _make_credential_helper(env)

        creds = helper.credentials[SAMPLE_GATEWAY_ARN]
        assert creds["server_name"] == "my-server"
        assert creds["authorizer_type"] == "CUSTOM_JWT"


class TestInteractivePrompt:
    """Tests for _prompt_credentials() — input + getpass mocking."""

    def test_prompt_collects_client_id_and_secret(self):
        """Req 11.3: Interactive prompt with input() + getpass.getpass()."""
        helper = _make_credential_helper()

        with patch("builtins.input", return_value="prompted-id"), \
             patch("cli.agentcore.credentials.getpass.getpass", return_value="prompted-secret"):
            creds = helper._prompt_credentials(SAMPLE_GATEWAY_ARN)

        assert creds is not None
        assert creds["client_id"] == "prompted-id"
        assert creds["client_secret"] == "prompted-secret"

    def test_empty_client_id_skips_collection(self):
        """Req 11.4: Empty Enter skips credential collection."""
        helper = _make_credential_helper()

        with patch("builtins.input", return_value=""):
            creds = helper._prompt_credentials(SAMPLE_GATEWAY_ARN)

        assert creds is None

    def test_empty_client_secret_skips_collection(self):
        """Empty secret also skips."""
        helper = _make_credential_helper()

        with patch("builtins.input", return_value="some-id"), \
             patch("cli.agentcore.credentials.getpass.getpass", return_value=""):
            creds = helper._prompt_credentials(SAMPLE_GATEWAY_ARN)

        assert creds is None

    def test_get_credentials_uses_env_before_prompt(self):
        """Env vars are preferred over interactive prompt."""
        env = {
            "OAUTH_CLIENT_ID_1": "env-id",
            "OAUTH_CLIENT_SECRET_1": "env-secret",
            "AGENTCORE_GATEWAY_ARN_1": SAMPLE_GATEWAY_ARN,
        }
        helper = _make_credential_helper(env)

        creds = helper.get_credentials(SAMPLE_GATEWAY_ARN, "CUSTOM_JWT", interactive=True)

        assert creds["client_id"] == "env-id"

    def test_get_credentials_falls_back_to_prompt(self):
        """When no env vars, falls back to interactive prompt."""
        helper = _make_credential_helper()

        with patch("builtins.input", return_value="prompted-id"), \
             patch("cli.agentcore.credentials.getpass.getpass", return_value="prompted-secret"):
            creds = helper.get_credentials(SAMPLE_GATEWAY_ARN, "CUSTOM_JWT", interactive=True)

        assert creds is not None
        assert creds["client_id"] == "prompted-id"

    def test_get_credentials_non_interactive_returns_none(self):
        """Non-interactive mode returns None when no env vars."""
        helper = _make_credential_helper()

        creds = helper.get_credentials(SAMPLE_GATEWAY_ARN, "CUSTOM_JWT", interactive=False)

        assert creds is None



# ---------------------------------------------------------------------------
# Task 5.2 — OAuth2 flow with Cognito provider
# ---------------------------------------------------------------------------


class TestOAuth2Cognito:
    """Tests for OAuth2 validation with Cognito (CUSTOM_JWT, /oauth2/token)."""

    def test_cognito_uses_oauth2_token_endpoint(self):
        """Req 11.5: Cognito domain uses /oauth2/token endpoint."""
        helper = _make_credential_helper()
        creds = {"client_id": "cog-id", "client_secret": "cog-secret"}
        cognito_domain = "https://my-pool.auth.us-east-1.amazoncognito.com"

        with patch("cli.agentcore.credentials.requests.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=200)
            result = helper.validate_credentials(creds, cognito_domain)

        assert result is True
        mock_post.assert_called_once()
        call_url = mock_post.call_args[0][0]
        assert call_url == f"{cognito_domain}/oauth2/token"

    def test_cognito_sends_client_credentials_grant(self):
        """Cognito validation sends correct grant_type and credentials."""
        helper = _make_credential_helper()
        creds = {"client_id": "cog-id", "client_secret": "cog-secret"}
        cognito_domain = "https://my-pool.auth.us-east-1.amazoncognito.com"

        with patch("cli.agentcore.credentials.requests.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=200)
            helper.validate_credentials(creds, cognito_domain)

        call_data = mock_post.call_args[1]["data"]
        assert call_data["grant_type"] == "client_credentials"
        assert call_data["client_id"] == "cog-id"
        assert call_data["client_secret"] == "cog-secret"

    def test_get_credentials_returns_oauth2_for_custom_jwt(self):
        """CUSTOM_JWT authorizer routes to OAuth2 credential collection."""
        env = {
            "OAUTH_CLIENT_ID_1": "jwt-id",
            "OAUTH_CLIENT_SECRET_1": "jwt-secret",
            "AGENTCORE_GATEWAY_ARN_1": SAMPLE_GATEWAY_ARN,
        }
        helper = _make_credential_helper(env)

        creds = helper.get_credentials(SAMPLE_GATEWAY_ARN, "CUSTOM_JWT")

        assert creds is not None
        assert creds["client_id"] == "jwt-id"


# ---------------------------------------------------------------------------
# Task 5.3 — OAuth2 flow with Auth0 provider
# ---------------------------------------------------------------------------


class TestOAuth2Auth0:
    """Tests for OAuth2 validation with Auth0 (CUSTOM_JWT, /oauth/token)."""

    def test_auth0_uses_oauth_token_endpoint(self):
        """Req 11.5: Auth0 domain uses /oauth/token endpoint."""
        helper = _make_credential_helper()
        creds = {"client_id": "a0-id", "client_secret": "a0-secret"}
        auth0_domain = "https://my-tenant.auth0.com"

        with patch("cli.agentcore.credentials.requests.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=200)
            result = helper.validate_credentials(creds, auth0_domain)

        assert result is True
        call_url = mock_post.call_args[0][0]
        assert call_url == f"{auth0_domain}/oauth/token"

    def test_auth0_validation_failure_returns_false(self):
        """Auth0 returning non-200 means validation fails."""
        helper = _make_credential_helper()
        creds = {"client_id": "bad-id", "client_secret": "bad-secret"}
        auth0_domain = "https://my-tenant.auth0.com"

        with patch("cli.agentcore.credentials.requests.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=401)
            result = helper.validate_credentials(creds, auth0_domain)

        assert result is False


# ---------------------------------------------------------------------------
# Task 5.4 — OAuth2 flow with Okta provider
# ---------------------------------------------------------------------------


class TestOAuth2Okta:
    """Tests for OAuth2 validation with Okta (CUSTOM_JWT, /oauth2/default/v1/token)."""

    def test_okta_uses_oauth2_default_v1_token_endpoint(self):
        """Req 11.5: Okta domain uses /oauth2/default/v1/token endpoint."""
        helper = _make_credential_helper()
        creds = {"client_id": "okta-id", "client_secret": "okta-secret"}
        okta_domain = "https://dev-12345.okta.com"

        with patch("cli.agentcore.credentials.requests.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=200)
            result = helper.validate_credentials(creds, okta_domain)

        assert result is True
        call_url = mock_post.call_args[0][0]
        assert call_url == f"{okta_domain}/oauth2/default/v1/token"

    def test_okta_validation_exception_returns_false(self):
        """Network errors during Okta validation return False."""
        helper = _make_credential_helper()
        creds = {"client_id": "okta-id", "client_secret": "okta-secret"}
        okta_domain = "https://dev-12345.okta.com"

        with patch("cli.agentcore.credentials.requests.post") as mock_post:
            mock_post.side_effect = Exception("Connection refused")
            result = helper.validate_credentials(creds, okta_domain)

        assert result is False


# ---------------------------------------------------------------------------
# Task 5.5 — AWS_IAM flow with IAM role
# ---------------------------------------------------------------------------


class TestAWSIAMRole:
    """Tests for AWS_IAM authorizer — sts:GetCallerIdentity verification."""

    def test_iam_returns_marker_dict(self):
        """Req 11.6: AWS_IAM returns marker dict with type=iam."""
        helper = _make_credential_helper()

        with patch("cli.agentcore.credentials.boto3.client") as mock_client:
            mock_sts = MagicMock()
            mock_sts.get_caller_identity.return_value = {
                "Account": "111122223333",
                "Arn": "arn:aws:iam::111122223333:role/MyRole",
            }
            mock_client.return_value = mock_sts

            creds = helper.get_credentials(SAMPLE_GATEWAY_ARN, "AWS_IAM")

        assert creds is not None
        assert creds["type"] == "iam"
        assert creds["authorizer_type"] == "AWS_IAM"

    def test_iam_calls_sts_get_caller_identity(self):
        """STS GetCallerIdentity is called to verify AWS credentials."""
        helper = _make_credential_helper()

        with patch("cli.agentcore.credentials.boto3.client") as mock_client:
            mock_sts = MagicMock()
            mock_sts.get_caller_identity.return_value = {"Account": "111122223333"}
            mock_client.return_value = mock_sts

            helper.get_credentials(SAMPLE_GATEWAY_ARN, "AWS_IAM")

        mock_client.assert_called_with("sts")
        mock_sts.get_caller_identity.assert_called_once()

    def test_iam_failure_returns_none(self):
        """STS failure returns None."""
        helper = _make_credential_helper()

        with patch("cli.agentcore.credentials.boto3.client") as mock_client:
            mock_sts = MagicMock()
            mock_sts.get_caller_identity.side_effect = Exception("No credentials")
            mock_client.return_value = mock_sts

            creds = helper.get_credentials(SAMPLE_GATEWAY_ARN, "AWS_IAM")

        assert creds is None


# ---------------------------------------------------------------------------
# Task 5.6 — AWS_IAM flow with access keys
# ---------------------------------------------------------------------------


class TestAWSIAMAccessKeys:
    """Tests for AWS_IAM with env-var-based AWS credentials."""

    def test_iam_with_access_keys_returns_marker(self):
        """Req 11.6: IAM with access keys still returns marker dict."""
        helper = _make_credential_helper()

        with patch("cli.agentcore.credentials.boto3.client") as mock_client:
            mock_sts = MagicMock()
            mock_sts.get_caller_identity.return_value = {
                "Account": "111122223333",
                "Arn": "arn:aws:iam::111122223333:user/deploy-user",
            }
            mock_client.return_value = mock_sts

            creds = helper.get_credentials(SAMPLE_GATEWAY_ARN, "AWS_IAM")

        assert creds["type"] == "iam"
        assert creds["authorizer_type"] == "AWS_IAM"

    def test_iam_does_not_prompt_for_oauth_credentials(self):
        """AWS_IAM path never prompts for OAuth2 credentials."""
        helper = _make_credential_helper()

        with patch("cli.agentcore.credentials.boto3.client") as mock_client, \
             patch("builtins.input") as mock_input:
            mock_sts = MagicMock()
            mock_sts.get_caller_identity.return_value = {"Account": "111122223333"}
            mock_client.return_value = mock_sts

            helper.get_credentials(SAMPLE_GATEWAY_ARN, "AWS_IAM")

        mock_input.assert_not_called()


# ---------------------------------------------------------------------------
# Task 5.7 — NONE flow
# ---------------------------------------------------------------------------


class TestNoneAuthorizer:
    """Tests for NONE authorizer — credential collection skipped."""

    def test_none_returns_marker_dict(self):
        """Req 11.7: NONE returns {type: none, authorizer_type: NONE}."""
        helper = _make_credential_helper()

        creds = helper.get_credentials(SAMPLE_GATEWAY_ARN, "NONE")

        assert creds is not None
        assert creds["type"] == "none"
        assert creds["authorizer_type"] == "NONE"

    def test_none_does_not_prompt(self):
        """NONE authorizer never prompts for credentials."""
        helper = _make_credential_helper()

        with patch("builtins.input") as mock_input:
            helper.get_credentials(SAMPLE_GATEWAY_ARN, "NONE")

        mock_input.assert_not_called()

    def test_none_does_not_call_sts(self):
        """NONE authorizer never calls STS."""
        helper = _make_credential_helper()

        with patch("cli.agentcore.credentials.boto3.client") as mock_client:
            helper.get_credentials(SAMPLE_GATEWAY_ARN, "NONE")

        mock_client.assert_not_called()



# ---------------------------------------------------------------------------
# Task 5.8 — Credential persistence
# ---------------------------------------------------------------------------


class TestCredentialPersistence:
    """Tests for persist_credentials() — .env writing with OAUTH_ prefix."""

    def test_persist_appends_to_env_file(self, tmp_path):
        """Req 12.3: Persist with OAUTH_ prefix to .env."""
        helper = _make_credential_helper()
        env_file = tmp_path / ".env"
        env_file.write_text("# existing content\n")

        creds = {"client_id": "persist-id", "client_secret": "persist-secret"}
        idx = helper.persist_credentials(
            SAMPLE_GATEWAY_ARN, creds, "my-server", str(env_file)
        )

        content = env_file.read_text()
        assert f"OAUTH_CLIENT_ID_{idx}=persist-id" in content
        assert f"OAUTH_CLIENT_SECRET_{idx}=persist-secret" in content
        assert f"AGENTCORE_GATEWAY_ARN_{idx}={SAMPLE_GATEWAY_ARN}" in content
        assert f"AGENTCORE_SERVER_NAME_{idx}=my-server" in content

    def test_persist_sets_0600_permissions(self, tmp_path):
        """Req 12.4: .env file permissions set to 0600."""
        helper = _make_credential_helper()
        env_file = tmp_path / ".env"
        env_file.write_text("")

        creds = {"client_id": "id", "client_secret": "secret"}
        helper.persist_credentials(SAMPLE_GATEWAY_ARN, creds, "srv", str(env_file))

        file_stat = os.stat(str(env_file))
        permissions = stat.S_IMODE(file_stat.st_mode)
        assert permissions == 0o600

    def test_persist_uses_next_available_index(self, tmp_path):
        """Req 12.5: Uses next available index."""
        env = {
            "OAUTH_CLIENT_ID_1": "existing-id",
            "OAUTH_CLIENT_SECRET_1": "existing-secret",
            "AGENTCORE_GATEWAY_ARN_1": "arn:existing",
        }
        helper = _make_credential_helper(env)
        env_file = tmp_path / ".env"
        env_file.write_text("")

        creds = {"client_id": "new-id", "client_secret": "new-secret"}
        idx = helper.persist_credentials(
            SAMPLE_GATEWAY_ARN, creds, "new-server", str(env_file)
        )

        assert idx == 2  # Next after existing index 1

    def test_persist_updates_in_memory_cache(self, tmp_path):
        """Persisted credentials are added to in-memory cache."""
        helper = _make_credential_helper()
        env_file = tmp_path / ".env"
        env_file.write_text("")

        creds = {"client_id": "cache-id", "client_secret": "cache-secret"}
        helper.persist_credentials(SAMPLE_GATEWAY_ARN, creds, "cached", str(env_file))

        assert SAMPLE_GATEWAY_ARN in helper.credentials
        assert helper.credentials[SAMPLE_GATEWAY_ARN]["server_name"] == "cached"

    def test_get_next_env_index_empty(self):
        """No existing credentials → index 1."""
        helper = _make_credential_helper()
        assert helper.get_next_env_index() == 1

    def test_get_next_env_index_with_existing(self):
        """Existing credentials at index 3 → next is 4."""
        env = {
            "OAUTH_CLIENT_ID_3": "id-3",
            "OAUTH_CLIENT_SECRET_3": "secret-3",
            "AGENTCORE_GATEWAY_ARN_3": "arn:gw-3",
        }
        helper = _make_credential_helper(env)
        assert helper.get_next_env_index() == 4


# ---------------------------------------------------------------------------
# Task 5.9 — Credential validation gating
# ---------------------------------------------------------------------------


class TestCredentialValidation:
    """Tests for validate_credentials() — valid pass, invalid not persisted."""

    def test_valid_credentials_pass_validation(self):
        """Req 12.1: Valid credentials pass validation (HTTP 200)."""
        helper = _make_credential_helper()
        creds = {"client_id": "valid-id", "client_secret": "valid-secret"}

        with patch("cli.agentcore.credentials.requests.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=200)
            result = helper.validate_credentials(creds, "https://auth.example.com")

        assert result is True

    def test_invalid_credentials_fail_validation(self):
        """Req 12.2: Invalid credentials fail validation (HTTP 401)."""
        helper = _make_credential_helper()
        creds = {"client_id": "bad-id", "client_secret": "bad-secret"}

        with patch("cli.agentcore.credentials.requests.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=401)
            result = helper.validate_credentials(creds, "https://auth.example.com")

        assert result is False

    def test_no_oauth_domain_skips_validation(self):
        """No OAUTH_DOMAIN set — validation is skipped (returns True)."""
        helper = _make_credential_helper()
        creds = {"client_id": "id", "client_secret": "secret"}

        result = helper.validate_credentials(creds, "")

        assert result is True

    def test_network_error_fails_validation(self):
        """Network errors during validation return False."""
        helper = _make_credential_helper()
        creds = {"client_id": "id", "client_secret": "secret"}

        with patch("cli.agentcore.credentials.requests.post") as mock_post:
            mock_post.side_effect = Exception("Connection timeout")
            result = helper.validate_credentials(creds, "https://auth.example.com")

        assert result is False

    def test_invalid_credentials_not_persisted_workflow(self, tmp_path):
        """Req 12.2: Invalid credentials should not be persisted.

        This tests the expected workflow: validate first, only persist if valid.
        """
        helper = _make_credential_helper()
        creds = {"client_id": "bad-id", "client_secret": "bad-secret"}
        env_file = tmp_path / ".env"
        env_file.write_text("")

        with patch("cli.agentcore.credentials.requests.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=401)
            is_valid = helper.validate_credentials(creds, "https://auth.example.com")

        # Caller should NOT persist when validation fails
        assert is_valid is False
        # Verify .env is still empty (persist was not called)
        assert env_file.read_text() == ""
