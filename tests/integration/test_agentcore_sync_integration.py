"""Integration tests for AgentCore auto-registration sync flow.

Tests the SyncOrchestrator end-to-end with mocked external dependencies
(boto3 AWS calls and registry HTTP calls). Validates discovery → registration
→ credential save → token generation pipeline.

Traces to: Requirements 1-16
"""

from __future__ import annotations

import json
import os
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Sample data
# ---------------------------------------------------------------------------

ACCOUNT_ID = "111122223333"
REGION = "us-east-1"

GATEWAY_CUSTOM_JWT = {
    "gatewayId": "gw-jwt-1",
    "gatewayArn": "arn:aws:bedrock:us-east-1:111122223333:gateway/gw-jwt-1",
    "gatewayUrl": "https://gateway-jwt.example.com",
    "name": "jwt-gateway",
    "description": "OAuth2 gateway",
    "status": "READY",
    "authorizerType": "CUSTOM_JWT",
    "targets": [],
}

GATEWAY_IAM = {
    "gatewayId": "gw-iam-1",
    "gatewayArn": "arn:aws:bedrock:us-east-1:111122223333:gateway/gw-iam-1",
    "gatewayUrl": "https://gateway-iam.example.com",
    "name": "iam-gateway",
    "description": "IAM gateway",
    "status": "READY",
    "authorizerType": "AWS_IAM",
    "targets": [],
}

GATEWAY_NONE = {
    "gatewayId": "gw-none-1",
    "gatewayArn": "arn:aws:bedrock:us-east-1:111122223333:gateway/gw-none-1",
    "gatewayUrl": "https://gateway-none.example.com",
    "name": "none-gateway",
    "description": "No-auth gateway",
    "status": "READY",
    "authorizerType": "NONE",
    "targets": [],
}

MCP_RUNTIME = {
    "agentRuntimeId": "rt-mcp-1",
    "agentRuntimeArn": "arn:aws:bedrock:us-east-1:111122223333:runtime/rt-mcp-1",
    "agentRuntimeName": "test-mcp-runtime",
    "description": "Test MCP runtime",
    "status": "READY",
    "protocolConfiguration": {"serverProtocol": "MCP"},
    "endpoints": [],
}

HTTP_RUNTIME = {
    "agentRuntimeId": "rt-http-1",
    "agentRuntimeArn": "arn:aws:bedrock:us-east-1:111122223333:runtime/rt-http-1",
    "agentRuntimeName": "test-http-runtime",
    "description": "Test HTTP runtime",
    "status": "READY",
    "protocolConfiguration": {"serverProtocol": "HTTP"},
    "endpoints": [],
}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _mock_sts():
    """Create a mock STS client that returns a fixed account ID."""
    mock = MagicMock()
    mock.get_caller_identity.return_value = {"Account": ACCOUNT_ID}
    return mock


def _mock_agentcore_client(gateways=None, runtimes=None):
    """Create a mock bedrock-agentcore-control client."""
    client = MagicMock()

    # list_gateways
    gw_items = []
    for gw in (gateways or []):
        gw_items.append({"gatewayId": gw["gatewayId"], "status": gw["status"]})
    client.list_gateways.return_value = {"items": gw_items}

    # get_gateway — return the full gateway dict for each ID
    def _get_gateway(gatewayIdentifier):
        for gw in (gateways or []):
            if gw["gatewayId"] == gatewayIdentifier:
                return dict(gw)
        return {}

    client.get_gateway.side_effect = _get_gateway

    # list_gateway_targets — return empty by default
    client.list_gateway_targets.return_value = {"items": []}
    client.get_gateway_target.return_value = {}

    # list_agent_runtimes
    rt_items = []
    for rt in (runtimes or []):
        rt_items.append({"agentRuntimeId": rt["agentRuntimeId"], "status": rt["status"]})
    client.list_agent_runtimes.return_value = {"agentRuntimes": rt_items}

    # get_agent_runtime
    def _get_runtime(agentRuntimeId):
        for rt in (runtimes or []):
            if rt["agentRuntimeId"] == agentRuntimeId:
                return dict(rt)
        return {}

    client.get_agent_runtime.side_effect = _get_runtime

    # list_agent_runtime_endpoints
    client.list_agent_runtime_endpoints.return_value = {"runtimeEndpoints": []}

    return client


def _build_orchestrator(
    gateways=None,
    runtimes=None,
    dry_run=False,
    overwrite=False,
    include_mcp_targets=False,
    skip_token_generation=False,
    cred_helper=None,
    token_manager=None,
    registry_client=None,
):
    """Build a SyncOrchestrator with mocked AWS and registry dependencies."""
    mock_ac_client = _mock_agentcore_client(gateways=gateways, runtimes=runtimes)
    mock_sts = _mock_sts()

    def _boto3_client(service, **kwargs):
        if service == "sts":
            return mock_sts
        if service == "bedrock-agentcore-control":
            return mock_ac_client
        return MagicMock()

    with patch("cli.agentcore.registration.boto3") as reg_boto3, \
         patch("cli.agentcore.discovery.boto3") as disc_boto3:
        reg_boto3.client.side_effect = _boto3_client
        disc_boto3.client.side_effect = _boto3_client

        from cli.agentcore.discovery import AgentCoreScanner
        from cli.agentcore.registration import RegistrationBuilder, SyncOrchestrator

        scanner = AgentCoreScanner(region=REGION)
        # Replace the client with our mock (the constructor already called boto3.client)
        scanner.client = mock_ac_client

        builder = RegistrationBuilder(region=REGION)

    if registry_client is None:
        registry_client = MagicMock()

    if cred_helper is None:
        cred_helper = MagicMock()
        cred_helper.get_credentials.return_value = None

    if token_manager is None:
        token_manager = MagicMock()
        token_manager.generate_tokens_for_gateways.return_value = {}

    orch = SyncOrchestrator(
        scanner=scanner,
        builder=builder,
        registry_client=registry_client,
        credential_helper=cred_helper,
        token_manager=token_manager,
        dry_run=dry_run,
        overwrite=overwrite,
        include_mcp_targets=include_mcp_targets,
        skip_token_generation=skip_token_generation,
    )
    return orch, registry_client, cred_helper, token_manager


# ---------------------------------------------------------------------------
# 8.2 — End-to-end flow: discovery → registration → credential save → token gen
# Traces to: Req 1-4, 11-13
# ---------------------------------------------------------------------------


class TestEndToEndFlow:
    """Full sync pipeline with CUSTOM_JWT gateway, MCP runtime, and HTTP runtime."""

    def test_gateway_discovery_registration_credentials_tokens(self):
        """CUSTOM_JWT gateway: register → persist creds → generate token."""
        cred_helper = MagicMock()
        # Return fresh credentials (no index → needs persistence)
        cred_helper.get_credentials.return_value = {
            "client_id": "test-id",
            "client_secret": "test-secret",
        }
        cred_helper.validate_credentials.return_value = True
        cred_helper.persist_credentials.return_value = 1  # assigned index

        token_mgr = MagicMock()
        token_mgr.generate_tokens_for_gateways.return_value = {
            GATEWAY_CUSTOM_JWT["gatewayArn"]: ".oauth-tokens/bedrock-agentcore-jwt-gateway-egress.json"
        }

        orch, registry, _, _ = _build_orchestrator(
            gateways=[GATEWAY_CUSTOM_JWT],
            cred_helper=cred_helper,
            token_manager=token_mgr,
        )

        orch.sync_gateways()
        orch.generate_tokens()

        # Gateway registered
        assert len(orch.results) == 1
        assert orch.results[0]["status"] == "registered"
        assert orch.results[0]["resource_type"] == "gateway"
        registry.register_service.assert_called_once()

        # Credentials persisted
        cred_helper.persist_credentials.assert_called_once()
        assert orch._credentials_saved == 1

        # Token generation triggered
        token_mgr.generate_tokens_for_gateways.assert_called_once()
        assert orch._tokens_generated == 1

    def test_mcp_runtime_registered_as_server(self):
        """MCP runtime → registered as MCP Server via register_service."""
        orch, registry, _, _ = _build_orchestrator(runtimes=[MCP_RUNTIME])

        orch.sync_runtimes()

        assert len(orch.results) == 1
        assert orch.results[0]["status"] == "registered"
        assert orch.results[0]["registration_type"] == "mcp_server"
        assert orch.results[0]["resource_type"] == "runtime"
        registry.register_service.assert_called_once()
        registry.register_agent.assert_not_called()

    def test_http_runtime_registered_as_agent(self):
        """HTTP runtime → registered as A2A Agent via register_agent."""
        orch, registry, _, _ = _build_orchestrator(runtimes=[HTTP_RUNTIME])

        orch.sync_runtimes()

        assert len(orch.results) == 1
        assert orch.results[0]["status"] == "registered"
        assert orch.results[0]["registration_type"] == "agent"
        registry.register_agent.assert_called_once()
        registry.register_service.assert_not_called()

    def test_full_sync_gateways_and_runtimes(self):
        """Sync both gateways and runtimes in a single run."""
        cred_helper = MagicMock()
        cred_helper.get_credentials.return_value = None  # skip creds

        orch, registry, _, _ = _build_orchestrator(
            gateways=[{**GATEWAY_NONE}],
            runtimes=[MCP_RUNTIME, HTTP_RUNTIME],
            cred_helper=cred_helper,
        )

        orch.sync_gateways()
        orch.sync_runtimes()

        assert len(orch.results) == 3
        statuses = [r["status"] for r in orch.results]
        assert all(s == "registered" for s in statuses)
        # 1 gateway + 1 MCP runtime = 2 register_service calls
        assert registry.register_service.call_count == 2
        # 1 HTTP runtime = 1 register_agent call
        assert registry.register_agent.call_count == 1

    def test_credentials_loaded_from_env_skip_persistence(self):
        """Credentials already in env (have index) → no persist, still queue token gen."""
        cred_helper = MagicMock()
        cred_helper.get_credentials.return_value = {
            "client_id": "env-id",
            "client_secret": "env-secret",
            "index": "3",
            "server_name": "jwt-gateway",
        }

        token_mgr = MagicMock()
        token_mgr.generate_tokens_for_gateways.return_value = {
            GATEWAY_CUSTOM_JWT["gatewayArn"]: "token-path"
        }

        orch, registry, _, _ = _build_orchestrator(
            gateways=[GATEWAY_CUSTOM_JWT],
            cred_helper=cred_helper,
            token_manager=token_mgr,
        )

        orch.sync_gateways()
        orch.generate_tokens()

        # No persistence needed
        cred_helper.persist_credentials.assert_not_called()
        assert orch._credentials_saved == 0

        # Token gen still queued
        assert orch._arn_to_index[GATEWAY_CUSTOM_JWT["gatewayArn"]] == 3
        token_mgr.generate_tokens_for_gateways.assert_called_once()


# ---------------------------------------------------------------------------
# 8.3 — Dry-run mode
# Traces to: Req 6
# ---------------------------------------------------------------------------


class TestDryRunMode:
    """Dry-run: no registry calls, no credential persistence, no token generation."""

    def test_dry_run_skips_registry_calls(self):
        orch, registry, cred_helper, token_mgr = _build_orchestrator(
            gateways=[GATEWAY_CUSTOM_JWT, GATEWAY_NONE],
            runtimes=[MCP_RUNTIME, HTTP_RUNTIME],
            dry_run=True,
        )

        orch.sync_gateways()
        orch.sync_runtimes()
        orch.generate_tokens()

        # No registry calls
        registry.register_service.assert_not_called()
        registry.register_agent.assert_not_called()

        # No credential persistence
        cred_helper.persist_credentials.assert_not_called()

        # No token generation
        token_mgr.generate_tokens_for_gateways.assert_not_called()

        # All results are dry_run
        assert len(orch.results) == 4
        assert all(r["status"] == "dry_run" for r in orch.results)

    def test_dry_run_no_credentials_saved(self):
        orch, _, cred_helper, _ = _build_orchestrator(
            gateways=[GATEWAY_CUSTOM_JWT],
            dry_run=True,
        )

        orch.sync_gateways()

        assert orch._credentials_saved == 0
        cred_helper.get_credentials.assert_not_called()

    def test_dry_run_tokens_generated_is_zero(self):
        orch, _, _, _ = _build_orchestrator(
            gateways=[GATEWAY_CUSTOM_JWT],
            dry_run=True,
        )

        orch.sync_gateways()
        orch.generate_tokens()

        assert orch._tokens_generated == 0


# ---------------------------------------------------------------------------
# 8.4 — Rollback on errors
# Traces to: Req 14.6
# ---------------------------------------------------------------------------


class TestRollbackOnErrors:
    """Registration reverted if credential save fails."""

    def test_credential_persist_failure_marks_result_failed(self):
        """If .env write fails after successful registration, result → failed."""
        cred_helper = MagicMock()
        cred_helper.get_credentials.return_value = {
            "client_id": "id",
            "client_secret": "secret",
        }
        cred_helper.validate_credentials.return_value = True
        cred_helper.persist_credentials.side_effect = OSError("Permission denied")

        orch, registry, _, _ = _build_orchestrator(
            gateways=[GATEWAY_CUSTOM_JWT],
            cred_helper=cred_helper,
        )

        orch.sync_gateways()

        # Registration was called
        registry.register_service.assert_called_once()

        # But result is marked as failed due to credential save failure
        assert len(orch.results) == 1
        assert orch.results[0]["status"] == "failed"
        assert "credential save failed" in orch.results[0]["message"].lower()

    def test_rollback_does_not_affect_other_gateways(self):
        """One gateway's credential failure doesn't affect another gateway."""
        cred_helper = MagicMock()

        # First gateway: cred persist fails; second gateway: NONE auth (no creds)
        cred_helper.get_credentials.side_effect = [
            {"client_id": "id", "client_secret": "secret"},
            None,  # NONE gateway returns None
        ]
        cred_helper.validate_credentials.return_value = True
        cred_helper.persist_credentials.side_effect = OSError("disk full")

        orch, registry, _, _ = _build_orchestrator(
            gateways=[GATEWAY_CUSTOM_JWT, GATEWAY_NONE],
            cred_helper=cred_helper,
        )

        orch.sync_gateways()

        assert len(orch.results) == 2
        # First gateway: failed (rollback)
        assert orch.results[0]["status"] == "failed"
        # Second gateway: registered successfully
        assert orch.results[1]["status"] == "registered"

    def test_no_tokens_generated_after_credential_failure(self):
        """Token generation is not queued when credential persistence fails."""
        cred_helper = MagicMock()
        cred_helper.get_credentials.return_value = {
            "client_id": "id",
            "client_secret": "secret",
        }
        cred_helper.validate_credentials.return_value = True
        cred_helper.persist_credentials.side_effect = OSError("write error")

        token_mgr = MagicMock()
        token_mgr.generate_tokens_for_gateways.return_value = {}

        orch, _, _, _ = _build_orchestrator(
            gateways=[GATEWAY_CUSTOM_JWT],
            cred_helper=cred_helper,
            token_manager=token_mgr,
        )

        orch.sync_gateways()
        orch.generate_tokens()

        # No gateway configs queued for token gen
        assert len(orch._gateway_configs) == 0
        assert orch._tokens_generated == 0


# ---------------------------------------------------------------------------
# 8.5 — Mixed deployment: CUSTOM_JWT, IAM, NONE gateways in single sync
# Traces to: Req 11.5, 11.6, 11.7
# ---------------------------------------------------------------------------


class TestMixedDeployment:
    """Mixed authorizer types in a single sync run."""

    def test_mixed_gateways_all_registered(self):
        """All three authorizer types register successfully."""
        cred_helper = MagicMock()

        def _get_creds(arn, authorizer_type="CUSTOM_JWT", interactive=True):
            if authorizer_type == "CUSTOM_JWT":
                return {"client_id": "id", "client_secret": "secret"}
            if authorizer_type == "AWS_IAM":
                return {"type": "iam", "authorizer_type": "AWS_IAM"}
            if authorizer_type == "NONE":
                return {"type": "none", "authorizer_type": "NONE"}
            return None

        cred_helper.get_credentials.side_effect = _get_creds
        cred_helper.validate_credentials.return_value = True
        cred_helper.persist_credentials.return_value = 1

        token_mgr = MagicMock()
        token_mgr.generate_tokens_for_gateways.return_value = {
            GATEWAY_CUSTOM_JWT["gatewayArn"]: "token-path"
        }

        orch, registry, _, _ = _build_orchestrator(
            gateways=[GATEWAY_CUSTOM_JWT, GATEWAY_IAM, GATEWAY_NONE],
            cred_helper=cred_helper,
            token_manager=token_mgr,
        )

        orch.sync_gateways()
        orch.generate_tokens()

        # All 3 gateways registered
        assert len(orch.results) == 3
        assert all(r["status"] == "registered" for r in orch.results)
        assert registry.register_service.call_count == 3

    def test_only_custom_jwt_triggers_credential_persistence(self):
        """Only CUSTOM_JWT gateways persist credentials; IAM and NONE do not."""
        cred_helper = MagicMock()

        def _get_creds(arn, authorizer_type="CUSTOM_JWT", interactive=True):
            if authorizer_type == "CUSTOM_JWT":
                return {"client_id": "id", "client_secret": "secret"}
            if authorizer_type == "AWS_IAM":
                return {"type": "iam", "authorizer_type": "AWS_IAM"}
            return {"type": "none", "authorizer_type": "NONE"}

        cred_helper.get_credentials.side_effect = _get_creds
        cred_helper.validate_credentials.return_value = True
        cred_helper.persist_credentials.return_value = 1

        orch, _, _, _ = _build_orchestrator(
            gateways=[GATEWAY_CUSTOM_JWT, GATEWAY_IAM, GATEWAY_NONE],
            cred_helper=cred_helper,
        )

        orch.sync_gateways()

        # Only the CUSTOM_JWT gateway triggers persist
        cred_helper.persist_credentials.assert_called_once()
        assert orch._credentials_saved == 1

    def test_only_custom_jwt_triggers_token_generation(self):
        """Token generation only for CUSTOM_JWT gateways."""
        cred_helper = MagicMock()

        def _get_creds(arn, authorizer_type="CUSTOM_JWT", interactive=True):
            if authorizer_type == "CUSTOM_JWT":
                return {"client_id": "id", "client_secret": "secret"}
            if authorizer_type == "AWS_IAM":
                return {"type": "iam", "authorizer_type": "AWS_IAM"}
            return {"type": "none", "authorizer_type": "NONE"}

        cred_helper.get_credentials.side_effect = _get_creds
        cred_helper.validate_credentials.return_value = True
        cred_helper.persist_credentials.return_value = 5

        token_mgr = MagicMock()
        token_mgr.generate_tokens_for_gateways.return_value = {
            GATEWAY_CUSTOM_JWT["gatewayArn"]: "token-path"
        }

        orch, _, _, _ = _build_orchestrator(
            gateways=[GATEWAY_CUSTOM_JWT, GATEWAY_IAM, GATEWAY_NONE],
            cred_helper=cred_helper,
            token_manager=token_mgr,
        )

        orch.sync_gateways()
        orch.generate_tokens()

        # Only 1 gateway config queued (CUSTOM_JWT)
        assert len(orch._gateway_configs) == 1
        assert orch._gateway_configs[0]["gateway_arn"] == GATEWAY_CUSTOM_JWT["gatewayArn"]
        token_mgr.generate_tokens_for_gateways.assert_called_once()

    def test_mixed_with_runtimes(self):
        """Mixed gateways + mixed runtimes in a single sync."""
        cred_helper = MagicMock()
        cred_helper.get_credentials.return_value = None  # skip creds for simplicity

        orch, registry, _, _ = _build_orchestrator(
            gateways=[GATEWAY_IAM, GATEWAY_NONE],
            runtimes=[MCP_RUNTIME, HTTP_RUNTIME],
            cred_helper=cred_helper,
        )

        orch.sync_gateways()
        orch.sync_runtimes()

        assert len(orch.results) == 4
        types = {r["resource_type"] for r in orch.results}
        assert types == {"gateway", "runtime"}

        # 2 gateways + 1 MCP runtime = 3 register_service
        assert registry.register_service.call_count == 3
        # 1 HTTP runtime = 1 register_agent
        assert registry.register_agent.call_count == 1

    def test_iam_gateway_auth_scheme_is_bearer(self):
        """IAM gateways get auth_scheme=bearer in registration."""
        cred_helper = MagicMock()
        cred_helper.get_credentials.return_value = {
            "type": "iam",
            "authorizer_type": "AWS_IAM",
        }

        orch, registry, _, _ = _build_orchestrator(
            gateways=[GATEWAY_IAM],
            cred_helper=cred_helper,
        )

        orch.sync_gateways()

        assert len(orch.results) == 1
        assert orch.results[0]["status"] == "registered"
        # Verify the registration model passed to register_service
        call_args = registry.register_service.call_args
        reg = call_args[0][0]
        assert reg.auth_scheme == "bearer"

    def test_none_gateway_auth_scheme_is_none(self):
        """NONE gateways get auth_scheme=none in registration."""
        cred_helper = MagicMock()
        cred_helper.get_credentials.return_value = {
            "type": "none",
            "authorizer_type": "NONE",
        }

        orch, registry, _, _ = _build_orchestrator(
            gateways=[GATEWAY_NONE],
            cred_helper=cred_helper,
        )

        orch.sync_gateways()

        call_args = registry.register_service.call_args
        reg = call_args[0][0]
        assert reg.auth_scheme == "none"
